// =============================================================================
// ShimMapper.cpp
// =============================================================================
//
// Implementation of the launcher's mini-mapper. See header for design notes.
//
// This file uses VirtualAllocEx / WriteProcessMemory / CreateRemoteThread
// rather than the NT-direct syscalls the injector's main mapper resolves
// dynamically. The reason: the launcher is not stealth-critical. It runs
// before any anti-cheat exists; spending engineering effort on syscall
// indirection here buys us nothing. We keep it simple, readable, and
// provably correct.
//
// =============================================================================

#include "ShimMapper.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <vector>

#include <windows.h>

namespace ENI::Launcher {

namespace {

// Translate per-section IMAGE_SCN_* characteristics into a Win32 page
// protection. Same matrix used everywhere: never RWX simultaneously.
DWORD SectionProtection(DWORD characteristics) {
    const bool e = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool r = (characteristics & IMAGE_SCN_MEM_READ)    != 0;
    const bool w = (characteristics & IMAGE_SCN_MEM_WRITE)   != 0;

    if (e && r && w) return PAGE_EXECUTE_READWRITE; // Avoid in production - here only if PE truly demands it
    if (e && r)      return PAGE_EXECUTE_READ;
    if (e && w)      return PAGE_EXECUTE_READWRITE;
    if (e)           return PAGE_EXECUTE;
    if (r && w)      return PAGE_READWRITE;
    if (r)           return PAGE_READONLY;
    if (w)           return PAGE_READWRITE;
    return PAGE_NOACCESS;
}

// Find an export's RVA by name in a local-memory copy of a PE image.
// Returns 0 if not found. Used both for ENIShimEntry resolution in the
// shim and for resolving imports against modules already loaded in the
// target (we read those modules' export tables locally because they're
// the same kernel32/ntdll that the launcher is using).
DWORD FindExportRva(const std::uint8_t* image, const char* name) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.Size == 0) return 0;

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(image + dir.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(image + exp->AddressOfNames);
    const auto* ords  = reinterpret_cast<const WORD*>(image + exp->AddressOfNameOrdinals);
    const auto* funcs = reinterpret_cast<const DWORD*>(image + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* n = reinterpret_cast<const char*>(image + names[i]);
        if (n && std::strcmp(n, name) == 0) {
            return funcs[ords[i]];
        }
    }
    return 0;
}

// Same as above, but operates on a "raw file" PE - i.e., the bytes as they
// live on disk before mapping. We need this for the shim's ENIShimEntry
// lookup because we resolve the export from the local payload bytes
// (cheaper than reading them back from the target).
DWORD FindExportRvaRawFile(std::span<const std::uint8_t> bytes, const char* name) {
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.Size == 0) return 0;

    auto rvaToFileOffset = [&](DWORD rva) -> const std::uint8_t* {
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress &&
                rva < s.VirtualAddress + s.Misc.VirtualSize) {
                return bytes.data() + s.PointerToRawData + (rva - s.VirtualAddress);
            }
        }
        return nullptr;
    };

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        rvaToFileOffset(dir.VirtualAddress));
    if (!exp) return 0;
    const auto* names = reinterpret_cast<const DWORD*>(rvaToFileOffset(exp->AddressOfNames));
    const auto* ords  = reinterpret_cast<const WORD*>(rvaToFileOffset(exp->AddressOfNameOrdinals));
    const auto* funcs = reinterpret_cast<const DWORD*>(rvaToFileOffset(exp->AddressOfFunctions));
    if (!names || !ords || !funcs) return 0;

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* n = reinterpret_cast<const char*>(rvaToFileOffset(names[i]));
        if (n && std::strcmp(n, name) == 0) {
            return funcs[ords[i]];
        }
    }
    return 0;
}

// Resolve a function's absolute address within an in-memory module. We
// assume the module is already mapped *in our own process* (so kernel32,
// ntdll - shared with the target by the loader). The address resolved here
// is the same one the target sees because Windows shares these system
// modules across processes at the same base.
std::uintptr_t ResolveLocalExport(HMODULE mod, const char* name) {
    return reinterpret_cast<std::uintptr_t>(GetProcAddress(mod, name));
}

} // namespace

ShimMapResult MapShimAndInvoke(
    HANDLE targetProcess,
    std::span<const std::uint8_t> shimBytes,
    const Shim::ShimEnvelope& envelope,
    std::uint32_t bootTimeoutMs)
{
    ShimMapResult r{};

    // -- 1. Validate -----------------------------------------------------
    if (shimBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        r.Status = ShimMapStatus::InvalidPe;
        return r;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(shimBytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        r.Status = ShimMapStatus::InvalidPe;
        return r;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(shimBytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        r.Status = ShimMapStatus::InvalidPe;
        return r;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        r.Status = ShimMapStatus::NotX64;
        return r;
    }
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        r.Status = ShimMapStatus::NotDll;
        return r;
    }

    const DWORD entryRva = FindExportRvaRawFile(shimBytes, Shim::ShimEntryExportName);
    if (entryRva == 0) {
        r.Status = ShimMapStatus::MissingShimEntryExport;
        return r;
    }

    // -- 2. Allocate the image region in the target ---------------------
    const SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    LPVOID remoteBase = VirtualAllocEx(
        targetProcess, nullptr, imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBase) {
        r.Status = ShimMapStatus::AllocateImageFailed;
        return r;
    }
    r.RemoteImageBase = reinterpret_cast<std::uintptr_t>(remoteBase);

    // -- 3. Build a local image (headers + sections) and write at once.
    // Faster than per-section writes; the launcher target is not stealth-
    // critical so a single big write is fine.
    std::vector<std::uint8_t> localImage(imageSize, 0);
    std::memcpy(localImage.data(), shimBytes.data(),
                std::min<SIZE_T>(nt->OptionalHeader.SizeOfHeaders, shimBytes.size()));

    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        const auto& s = sections[i];
        if (s.SizeOfRawData == 0) continue;
        const std::size_t srcOff = s.PointerToRawData;
        const std::size_t dstOff = s.VirtualAddress;
        const std::size_t copyLen = std::min<std::size_t>(s.SizeOfRawData, s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData);
        if (srcOff + copyLen > shimBytes.size()) {
            r.Status = ShimMapStatus::SectionWriteFailed;
            return r;
        }
        if (dstOff + copyLen > localImage.size()) {
            r.Status = ShimMapStatus::SectionWriteFailed;
            return r;
        }
        std::memcpy(localImage.data() + dstOff, shimBytes.data() + srcOff, copyLen);
    }

    // -- 4. Apply base relocations on the local copy --------------------
    const std::int64_t delta = static_cast<std::int64_t>(r.RemoteImageBase) -
                               static_cast<std::int64_t>(nt->OptionalHeader.ImageBase);
    if (delta != 0) {
        const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            std::uint8_t* p = localImage.data() + relocDir.VirtualAddress;
            std::uint8_t* end = p + relocDir.Size;
            while (p < end) {
                auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(p);
                if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

                const DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                const auto* entries = reinterpret_cast<const WORD*>(p + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    const WORD type = entries[i] >> 12;
                    const WORD off  = entries[i] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                    if (type != IMAGE_REL_BASED_DIR64) {
                        r.Status = ShimMapStatus::UnsupportedRelocationType;
                        return r;
                    }
                    const std::size_t target = block->VirtualAddress + off;
                    if (target + sizeof(std::uint64_t) > localImage.size()) {
                        r.Status = ShimMapStatus::RelocationOutOfRange;
                        return r;
                    }
                    auto* slot = reinterpret_cast<std::uint64_t*>(localImage.data() + target);
                    *slot = *slot + delta;
                }

                p += block->SizeOfBlock;
            }
        }
    }

    // -- 5. Resolve imports ---------------------------------------------
    //
    // The shim only imports kernel32 and (via the static CRT) some msvcrt
    // pieces. Anything not present in our launcher process is not coming
    // from us - we LoadLibraryA it locally first so its address is known.
    // The launcher and target launcher share the same Windows system DLLs,
    // mapped at the same base, so a local resolve is correct for the remote.
    {
        const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size > 0) {
            auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                localImage.data() + importDir.VirtualAddress);
            for (; desc->Name; desc++) {
                const char* dllName = reinterpret_cast<const char*>(localImage.data() + desc->Name);
                HMODULE mod = GetModuleHandleA(dllName);
                if (!mod) {
                    mod = LoadLibraryA(dllName);
                }
                if (!mod) {
                    r.Status = ShimMapStatus::LoadLibraryRemoteFailed;
                    return r;
                }

                auto* origThunk = desc->OriginalFirstThunk
                    ? reinterpret_cast<IMAGE_THUNK_DATA64*>(localImage.data() + desc->OriginalFirstThunk)
                    : reinterpret_cast<IMAGE_THUNK_DATA64*>(localImage.data() + desc->FirstThunk);
                auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(localImage.data() + desc->FirstThunk);

                for (; origThunk->u1.AddressOfData; origThunk++, iat++) {
                    std::uintptr_t addr = 0;
                    if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        const WORD ord = static_cast<WORD>(origThunk->u1.Ordinal & 0xFFFF);
                        addr = reinterpret_cast<std::uintptr_t>(
                            GetProcAddress(mod, reinterpret_cast<LPCSTR>(static_cast<std::uintptr_t>(ord))));
                    } else {
                        const auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                            localImage.data() + origThunk->u1.AddressOfData);
                        addr = ResolveLocalExport(mod, byName->Name);
                    }
                    if (!addr) {
                        r.Status = ShimMapStatus::GetProcAddressFailed;
                        return r;
                    }
                    iat->u1.Function = addr;
                }
            }
        }
    }

    // -- 6. Write the prepared local image into the target --------------
    SIZE_T written = 0;
    if (!WriteProcessMemory(targetProcess, remoteBase, localImage.data(), imageSize, &written) ||
        written != imageSize) {
        r.Status = ShimMapStatus::SectionWriteFailed;
        return r;
    }

    // -- 7. Apply per-section protections in the target -----------------
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        const auto& s = sections[i];
        if (s.Misc.VirtualSize == 0) continue;
        DWORD oldProtect = 0;
        const DWORD newProtect = SectionProtection(s.Characteristics);
        if (!VirtualProtectEx(
                targetProcess,
                reinterpret_cast<std::uint8_t*>(remoteBase) + s.VirtualAddress,
                s.Misc.VirtualSize, newProtect, &oldProtect)) {
            r.Status = ShimMapStatus::ProtectionApplyFailed;
            return r;
        }
    }

    // -- 8. Allocate + write ShimEnvelope -------------------------------
    LPVOID remoteEnv = VirtualAllocEx(
        targetProcess, nullptr, sizeof(Shim::ShimEnvelope),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteEnv) {
        r.Status = ShimMapStatus::AllocateEnvelopeFailed;
        return r;
    }
    if (!WriteProcessMemory(targetProcess, remoteEnv, &envelope, sizeof(envelope), &written) ||
        written != sizeof(envelope)) {
        r.Status = ShimMapStatus::EnvelopeWriteFailed;
        return r;
    }
    r.RemoteEnvelope = reinterpret_cast<std::uintptr_t>(remoteEnv);

    // -- 9. Build + write the boot stub. Same recipe as ManualMapper's
    //       LaunchBootEntry, just with ENIShimEntry instead of ENIBootEntry.
    r.RemoteEntryPoint = r.RemoteImageBase + entryRva;

    std::uint8_t stub[] = {
        0x48, 0xB9, 0,0,0,0,0,0,0,0,             // mov rcx, envelope
        0x48, 0xB8, 0,0,0,0,0,0,0,0,             // mov rax, ENIShimEntry
        0x48, 0x83, 0xEC, 0x28,                  // sub rsp, 0x28
        0xFF, 0xD0,                              // call rax
        0x48, 0x83, 0xC4, 0x28,                  // add rsp, 0x28
        0xC3                                     // ret
    };
    std::memcpy(&stub[2],  &r.RemoteEnvelope,    sizeof(std::uintptr_t));
    std::memcpy(&stub[12], &r.RemoteEntryPoint,  sizeof(std::uintptr_t));

    LPVOID remoteStub = VirtualAllocEx(
        targetProcess, nullptr, sizeof(stub),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStub) {
        r.Status = ShimMapStatus::AllocateShellcodeFailed;
        return r;
    }
    if (!WriteProcessMemory(targetProcess, remoteStub, stub, sizeof(stub), &written) ||
        written != sizeof(stub)) {
        r.Status = ShimMapStatus::ShellcodeWriteFailed;
        return r;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(targetProcess, remoteStub, sizeof(stub),
                          PAGE_EXECUTE_READ, &oldProtect)) {
        r.Status = ShimMapStatus::ProtectionApplyFailed;
        return r;
    }
    r.BootStubAddress = reinterpret_cast<std::uintptr_t>(remoteStub);

    // -- 10. Run the stub. Wait for it. ---------------------------------
    HANDLE thread = CreateRemoteThread(
        targetProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub),
        nullptr, 0, nullptr);
    if (!thread) {
        r.Status = ShimMapStatus::BootThreadCreateFailed;
        return r;
    }

    const DWORD waitResult = WaitForSingleObject(
        thread, bootTimeoutMs ? bootTimeoutMs : INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);

    r.ShimReturnCode = exitCode;

    if (waitResult == WAIT_TIMEOUT) {
        r.Status = ShimMapStatus::BootTimeout;
        return r;
    }
    if (exitCode != 0) {
        r.Status = ShimMapStatus::ShimEntryReturnedError;
        return r;
    }

    r.Status = ShimMapStatus::Ok;
    return r;
}

} // namespace ENI::Launcher
