// =============================================================================
// ManualMapper.cpp
// =============================================================================
//
// Implementation notes that aren't obvious from the header:
//
// * We use NtAllocateVirtualMemory / NtProtectVirtualMemory / NtWriteVirtualMemory
//   directly (resolved at runtime from ntdll). The kernel32 wrappers (VirtualAllocEx
//   etc.) are the obvious user-mode hook targets; going through Nt* doesn't
//   *defeat* a kernel-callback-based EDR but it does sidestep the casual hooks
//   that 80% of detection products rely on.
//
// * Every NT function pointer is resolved once at construction. If ntdll itself
//   is hooked, well, we lose - but that's a different threat model (we'd need
//   to either parse ntdll on disk and copy fresh stubs, or do raw syscalls,
//   both of which can come later in DirectSyscall.cpp).
//
// * The "boot stub" shellcode is kept tiny - it does literally one thing:
//   call BootEntry with rcx = BootInfo address, then return. The thread's
//   exit code becomes the BootEntry return value. We don't put any logic
//   in the stub because debugging shellcode is its own circle of hell.
//
// * Section copy uses NtWriteVirtualMemory in chunks. Some sections (especially
//   .bss) have RawSize=0 with VirtualSize>0; we skip the write but still need
//   the protection applied. The allocator already zero-fills committed pages
//   so the empty sections start out clean.
//
// * Relocations on x64 only ever come in two flavors: IMAGE_REL_BASED_ABSOLUTE
//   (which is just padding to align reloc blocks to 4 bytes - skip it) and
//   IMAGE_REL_BASED_DIR64 (full 64-bit absolute fixup). Anything else is
//   either a fluke from a bad linker or a non-x64 image we shouldn't have
//   accepted at validation time.
//
// * For imports, we read the IAT off the *local* copy of the payload bytes
//   (since RVAs into the payload header are easy to walk there), but write
//   the resolved addresses to the *remote* mapped image. Mixing the two is
//   the most common bug in homemade mappers - keep it straight.
// =============================================================================

#include "ManualMapper.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

namespace ENI::Injector {

// -----------------------------------------------------------------------------
// NT function pointer resolution
// -----------------------------------------------------------------------------
//
// We grab these once. If any are missing, every Nt* call falls back to its
// kernel32 equivalent so the loader at least functions in degraded mode.
// (Without the syscall stubs we lose stealth, not correctness.)

namespace {

using PFN_NtAllocateVirtualMemory = NTSTATUS (NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using PFN_NtFreeVirtualMemory     = NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
using PFN_NtProtectVirtualMemory  = NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using PFN_NtReadVirtualMemory     = NTSTATUS (NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using PFN_NtWriteVirtualMemory    = NTSTATUS (NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

struct NtApi {
    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
    PFN_NtFreeVirtualMemory     NtFreeVirtualMemory     = nullptr;
    PFN_NtProtectVirtualMemory  NtProtectVirtualMemory  = nullptr;
    PFN_NtReadVirtualMemory     NtReadVirtualMemory     = nullptr;
    PFN_NtWriteVirtualMemory    NtWriteVirtualMemory    = nullptr;

    NtApi() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return;

        NtAllocateVirtualMemory = reinterpret_cast<PFN_NtAllocateVirtualMemory>(
            GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
        NtFreeVirtualMemory = reinterpret_cast<PFN_NtFreeVirtualMemory>(
            GetProcAddress(ntdll, "NtFreeVirtualMemory"));
        NtProtectVirtualMemory = reinterpret_cast<PFN_NtProtectVirtualMemory>(
            GetProcAddress(ntdll, "NtProtectVirtualMemory"));
        NtReadVirtualMemory = reinterpret_cast<PFN_NtReadVirtualMemory>(
            GetProcAddress(ntdll, "NtReadVirtualMemory"));
        NtWriteVirtualMemory = reinterpret_cast<PFN_NtWriteVirtualMemory>(
            GetProcAddress(ntdll, "NtWriteVirtualMemory"));
    }
};

const NtApi& Nt() {
    static NtApi instance;
    return instance;
}

// NTSTATUS success check - ntdll only considers values with the high bit
// clear to be successful. STATUS_SUCCESS == 0 but some operations return
// other "informational" non-error codes we want to accept.
constexpr bool NT_OK(NTSTATUS s) { return s >= 0; }

// The Win32 SDK defines STATUS_* constants only when <ntstatus.h> is
// included with WIN32_NO_STATUS first; pulling that in conflicts with
// <windows.h> in this TU. Define the one literal we use locally.
constexpr NTSTATUS NT_FALLBACK_FAIL = static_cast<NTSTATUS>(0xC0000001L); // STATUS_UNSUCCESSFUL

// Round up `value` to the nearest multiple of `align`. Both must be powers
// of two for the bitmask trick to work. Used everywhere PE alignment matters.
constexpr std::size_t AlignUp(std::size_t value, std::size_t align) {
    return (value + align - 1) & ~(align - 1);
}

// Lower-case ASCII compare for module-name lookups. The module list from
// Toolhelp arrives mixed-case ("KERNEL32.DLL", "kernel32.dll", etc.); we
// store everything lower-case in m_ModuleCache.
std::string ToLowerAscii(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Resolve the target process's primary image - base, size, and on-disk
// path - even when the process is suspended at its very first instruction.
//
// Why this isn't "just use EnumProcessModules": when the shim mapper runs,
// Roblox was just CreateProcess'd with CREATE_SUSPENDED. The kernel mapped
// the EXE image and ntdll into the address space, but the user-mode loader
// (LdrInitializeThunk in ntdll) hasn't run yet - so PEB->Ldr's module
// lists are empty. EnumProcessModules walks those lists, so it returns
// zero modules for a freshly suspended process. The kernel-populated bits
// we *can* trust at this stage are:
//
//   * PEB->ImageBaseAddress         (set by the kernel during CreateProcess)
//   * The PE headers at that base   (mapped by the kernel before LdrInit)
//
// We get PEB via NtQueryInformationProcess(ProcessBasicInformation), read
// ImageBaseAddress out of it, then read the IMAGE_NT_HEADERS64 at that base
// to recover SizeOfImage. Path comes from QueryFullProcessImageNameW which
// works on suspended processes (it queries the kernel's section object,
// not user-mode loader state).
//
// Returns true on success; on failure all out-parameters are left at their
// caller-initialized defaults so the caller can detect partial success.
struct PROCESS_BASIC_INFO_LITE {
    NTSTATUS    ExitStatus;
    PVOID       PebBaseAddress;
    ULONG_PTR   AffinityMask;
    LONG        BasePriority;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   InheritedFromUniqueProcessId;
};

bool ResolveTargetMainImage(HANDLE process,
                            std::uintptr_t& baseOut,
                            std::uintptr_t& sizeOut,
                            std::wstring& exePathOut) {
    using PFN_NtQueryInformationProcess = NTSTATUS (NTAPI*)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    auto NtQIP = reinterpret_cast<PFN_NtQueryInformationProcess>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!NtQIP) return false;

    PROCESS_BASIC_INFO_LITE pbi{};
    ULONG returned = 0;
    if (NtQIP(process, /*ProcessBasicInformation*/ 0,
              &pbi, sizeof(pbi), &returned) < 0 || !pbi.PebBaseAddress) {
        return false;
    }

    // PEB layout (x64): ImageBaseAddress lives at offset 0x10. We read just
    // that pointer rather than the whole PEB - the layout of the rest is
    // version-dependent and we don't need it.
    constexpr std::size_t kPebImageBaseOffset = 0x10;
    std::uintptr_t imageBase = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(process,
            reinterpret_cast<LPCVOID>(
                reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress) + kPebImageBaseOffset),
            &imageBase, sizeof(imageBase), &read) ||
        read != sizeof(imageBase) || imageBase == 0) {
        return false;
    }

    // Read the PE headers off the image to recover SizeOfImage. We only
    // need DOS + NT, which fit in the first 4 KB of any sane PE.
    std::uint8_t hdr[0x400] = {};
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(imageBase),
                           hdr, sizeof(hdr), &read) || read < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hdr);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    baseOut = imageBase;
    sizeOut = static_cast<std::uintptr_t>(nt->OptionalHeader.SizeOfImage);

    // QueryFullProcessImageNameW works on suspended processes - it queries
    // the kernel's section object, not user-mode loader state.
    wchar_t pathBuf[MAX_PATH * 2] = {};
    DWORD pathSize = static_cast<DWORD>(std::size(pathBuf));
    if (QueryFullProcessImageNameW(process, 0, pathBuf, &pathSize)) {
        exePathOut.assign(pathBuf, pathSize);
    } else {
        exePathOut.clear();
    }
    return true;
}

// Pack a VS_FIXEDFILEINFO version quartet into the BootInfo wire format:
// major<<48 | minor<<32 | build<<16 | revision. Returns 0 if the file has
// no version resource (rare for first-party PE images, but possible).
std::uint64_t QueryPackedFileVersion(const wchar_t* path) {
    if (!path || !*path) return 0;

    DWORD dummy = 0;
    const DWORD size = GetFileVersionInfoSizeW(path, &dummy);
    if (size == 0) return 0;

    std::vector<std::uint8_t> blob(size);
    if (!GetFileVersionInfoW(path, 0, size, blob.data())) return 0;

    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffiSize = 0;
    if (!VerQueryValueW(blob.data(), L"\\",
                        reinterpret_cast<LPVOID*>(&ffi), &ffiSize) ||
        !ffi || ffiSize < sizeof(VS_FIXEDFILEINFO)) {
        return 0;
    }

    const std::uint64_t major    = HIWORD(ffi->dwFileVersionMS);
    const std::uint64_t minor    = LOWORD(ffi->dwFileVersionMS);
    const std::uint64_t build    = HIWORD(ffi->dwFileVersionLS);
    const std::uint64_t revision = LOWORD(ffi->dwFileVersionLS);
    return (major << 48) | (minor << 32) | (build << 16) | revision;
}

// Convert a section's PE characteristics flags to a Win32 page-protection
// constant. We deliberately collapse some combinations - for example,
// any section marked executable becomes either RX or RWX-but-only-during-
// reloc; we never persist RWX after mapping completes.
DWORD CharacteristicsToProtect(DWORD characteristics) {
    const bool x = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool r = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool w = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (x && w) return PAGE_EXECUTE_READWRITE;  // rare; most linkers don't emit this
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

} // anonymous namespace


// -----------------------------------------------------------------------------
// Status -> string for log lines
// -----------------------------------------------------------------------------

const char* MapStatusToString(MapStatus s) {
    switch (s) {
        case MapStatus::Ok:                          return "Ok";
        case MapStatus::InvalidPeImage:              return "InvalidPeImage";
        case MapStatus::NotX64:                      return "NotX64";
        case MapStatus::NotDll:                      return "NotDll";
        case MapStatus::NoEntryPoint:                return "NoEntryPoint";
        case MapStatus::MissingBootEntryExport:      return "MissingBootEntryExport";
        case MapStatus::AllocateImageFailed:         return "AllocateImageFailed";
        case MapStatus::AllocateBootInfoFailed:      return "AllocateBootInfoFailed";
        case MapStatus::AllocateShellcodeFailed:     return "AllocateShellcodeFailed";
        case MapStatus::SectionCopyFailed:           return "SectionCopyFailed";
        case MapStatus::RelocationOutOfRange:        return "RelocationOutOfRange";
        case MapStatus::UnsupportedRelocationType:   return "UnsupportedRelocationType";
        case MapStatus::LoadLibraryRemoteFailed:     return "LoadLibraryRemoteFailed";
        case MapStatus::GetProcAddressFailed:        return "GetProcAddressFailed";
        case MapStatus::TlsCallbackFailed:           return "TlsCallbackFailed";
        case MapStatus::ProtectionApplyFailed:       return "ProtectionApplyFailed";
        case MapStatus::BootThreadCreateFailed:      return "BootThreadCreateFailed";
        case MapStatus::BootEntryReturnedError:      return "BootEntryReturnedError";
        case MapStatus::ProcessHandleInvalid:        return "ProcessHandleInvalid";
        case MapStatus::ProcessNotX64:               return "ProcessNotX64";
        case MapStatus::OutOfMemoryLocal:            return "OutOfMemoryLocal";
        case MapStatus::InternalLogicError:          return "InternalLogicError";
    }
    return "Unknown";
}

// -----------------------------------------------------------------------------
// Construction / RAII
// -----------------------------------------------------------------------------

ManualMapper::ManualMapper(HANDLE targetProcess, const MapOptions& options)
    : m_Process(targetProcess), m_Options(options) {}

ManualMapper::~ManualMapper() = default;

// -----------------------------------------------------------------------------
// Top-level Map()
// -----------------------------------------------------------------------------
//
// Each phase fills MapResult on its way through. If a phase returns false,
// we bail, run RollbackPartialMapping() to MEM_RELEASE whatever we managed
// to allocate, and return the result with whatever Status the failed phase
// set.
//
// Why rollback matters: under sustained dev iteration (build-fail-rebuild-
// inject), leaked allocations accumulate in the target process until it
// dies, and they show up in the next run's VirtualQuery walks - making it
// hard to tell which allocation is "ours from this attempt" vs "ours from
// a stale attempt". Cleaning up on failure keeps the post-mortem clean.
//
// On success we deliberately do NOT free anything except the boot stub
// (which is freed inside PostBootCleanup) - the image and BootInfo have
// to stay live for the payload to use them.

void ManualMapper::RollbackPartialMapping(MapResult& r) {
    auto freeRemote = [&](std::uintptr_t& addr) {
        if (!addr) return;
        PVOID base = reinterpret_cast<PVOID>(addr);
        if (Nt().NtFreeVirtualMemory) {
            SIZE_T zero = 0;
            Nt().NtFreeVirtualMemory(m_Process, &base, &zero, MEM_RELEASE);
        } else {
            VirtualFreeEx(m_Process, base, 0, MEM_RELEASE);
        }
        addr = 0;
    };

    freeRemote(r.BootStubAddress);
    freeRemote(r.RemoteBootInfo);
    freeRemote(r.RemoteImageBase);
}

MapResult ManualMapper::Map(std::span<const std::uint8_t> payload) {
    MapResult r{};

    if (!m_Process || m_Process == INVALID_HANDLE_VALUE) {
        r.Status = MapStatus::ProcessHandleInvalid;
        return r;
    }

    auto timed = [&](MapResult::TimingPhase phase, auto&& fn) -> bool {
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = fn();
        const auto t1 = std::chrono::steady_clock::now();
        r.TimingsUs[phase] = static_cast<std::uint32_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        return ok;
    };

    auto bail = [&]() -> MapResult& {
        RollbackPartialMapping(r);
        return r;
    };

    if (!timed(MapResult::TimingValidate,    [&]{ return ValidateImage(payload, r); })) return bail();
    if (!timed(MapResult::TimingAllocate,    [&]{ return AllocateImage(r); }))         return bail();
    if (!timed(MapResult::TimingCopySections,[&]{ return CopySections(payload, r); })) return bail();
    if (!timed(MapResult::TimingRelocations, [&]{ return ApplyRelocations(payload, r); })) return bail();
    if (!timed(MapResult::TimingImports,     [&]{ return ResolveImports(payload, r); })) return bail();
    if (!timed(MapResult::TimingTls,         [&]{ return InvokeTlsCallbacks(payload, r); })) return bail();
    if (!timed(MapResult::TimingProtections, [&]{ return ApplyProtections(payload, r); })) return bail();

    if (!ResolveBootEntry(payload, r))    return bail();
    if (!BuildAndWriteBootInfo(r))        return bail();

    if (!timed(MapResult::TimingBootEntry, [&]{ return LaunchBootEntry(r); })) return bail();
    if (!PostBootCleanup(r))              return bail();

    r.Status = MapStatus::Ok;
    return r;
}

// -----------------------------------------------------------------------------
// Phase 1: Validate the PE
// -----------------------------------------------------------------------------

bool ManualMapper::ValidateImage(std::span<const std::uint8_t> payload, MapResult& r) {
    if (payload.size() < sizeof(IMAGE_DOS_HEADER)) {
        r.Status = MapStatus::InvalidPeImage;
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        r.Status = MapStatus::InvalidPeImage;
        return false;
    }
    if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > payload.size()) {
        r.Status = MapStatus::InvalidPeImage;
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        r.Status = MapStatus::InvalidPeImage;
        return false;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        r.Status = MapStatus::NotX64;
        return false;
    }
    if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        r.Status = MapStatus::NotDll;
        return false;
    }
    if (nt->OptionalHeader.AddressOfEntryPoint == 0) {
        // We don't actually call AddressOfEntryPoint - we call BootEntry by
        // export name - but a DLL with no entry point is so unusual it's
        // probably broken. Refuse rather than silently mis-handle.
        r.Status = MapStatus::NoEntryPoint;
        return false;
    }

    // We also need the target process to be x64. If the user managed to
    // hand us an x86 Roblox somehow, abort here rather than later.
    BOOL isWow64 = FALSE;
    IsWow64Process(m_Process, &isWow64);
    if (isWow64) {
        r.Status = MapStatus::ProcessNotX64;
        return false;
    }

    r.RemoteImageSize = nt->OptionalHeader.SizeOfImage;
    return true;
}

// -----------------------------------------------------------------------------
// Phase 2: Allocate the image region
// -----------------------------------------------------------------------------

bool ManualMapper::AllocateImage(MapResult& r) {
    PVOID base = nullptr;
    SIZE_T size = r.RemoteImageSize;

    // We allocate RW first, not RWX. Each section gets its real protection
    // later in ApplyProtections(). This keeps the window of "RWX exists in
    // this process" to literally zero from the AV's point of view.
    NTSTATUS status = NT_FALLBACK_FAIL;
    if (Nt().NtAllocateVirtualMemory) {
        status = Nt().NtAllocateVirtualMemory(
            m_Process, &base, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        // Fallback - we lose stealth but the loader still works.
        base = VirtualAllocEx(m_Process, nullptr, size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = base ? 0 : -1;
    }

    if (!NT_OK(status) || !base) {
        r.Status = MapStatus::AllocateImageFailed;
        return false;
    }

    r.RemoteImageBase = reinterpret_cast<std::uintptr_t>(base);
    return true;
}

// -----------------------------------------------------------------------------
// Phase 3: Copy headers + each section to its RVA
// -----------------------------------------------------------------------------

bool ManualMapper::CopySections(std::span<const std::uint8_t> payload, MapResult& r) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);

    // Copy the headers themselves to RVA 0. The PE headers contain the
    // section table that the OS loader (and our payload, if it ever wants
    // to introspect itself) walks - the payload will not work without them
    // until ApplyProtections, when we may erase them per options.
    if (!RemoteWrite(r.RemoteImageBase, payload.data(), nt->OptionalHeader.SizeOfHeaders)) {
        r.Status = MapStatus::SectionCopyFailed;
        return false;
    }

    // Walk the section table.
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        const auto& s = sections[i];

        // .bss-style sections: zero VirtualSize is unusual; zero RawSize
        // with non-zero VirtualSize is normal. We skip the write (the
        // allocator already returned zero-filled pages) but still iterate
        // so ApplyProtections can set the right page protection later.
        if (s.SizeOfRawData == 0) continue;

        // Sanity: the section's raw data must fit inside the payload bytes.
        // Malformed PEs can list section RawSize > actual file - reject.
        if (static_cast<std::size_t>(s.PointerToRawData) + s.SizeOfRawData > payload.size()) {
            r.Status = MapStatus::SectionCopyFailed;
            return false;
        }

        const std::uintptr_t dst = r.RemoteImageBase + s.VirtualAddress;
        const auto* src = payload.data() + s.PointerToRawData;
        const std::size_t bytes = std::min<std::size_t>(s.SizeOfRawData, s.Misc.VirtualSize);

        if (!RemoteWrite(dst, src, bytes)) {
            r.Status = MapStatus::SectionCopyFailed;
            return false;
        }
    }

    return true;
}

// -----------------------------------------------------------------------------
// Phase 4: Base relocations
// -----------------------------------------------------------------------------
//
// Each block has a header (PageRVA + BlockSize), then BlockSize-8 bytes of
// 16-bit entries: top 4 bits = relocation type, low 12 bits = offset within
// the page. For x64 we expect ABSOLUTE (skip - just padding) and DIR64
// (read the 64-bit value at PageRVA+offset, add delta, write back).
//
// We do the read-modify-write through RemoteRead / RemoteWrite. Yes, that's
// two round trips per fixup. For typical DLLs (a few thousand fixups) this
// is fast enough; if it ever becomes a bottleneck, we can pull a whole
// 4KB page locally, fix everything in it, and write it back - but profile
// before optimizing.

bool ManualMapper::ApplyRelocations(std::span<const std::uint8_t> payload, MapResult& r) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);

    const std::int64_t delta = static_cast<std::int64_t>(r.RemoteImageBase) -
                               static_cast<std::int64_t>(nt->OptionalHeader.ImageBase);
    if (delta == 0) {
        // Loaded at preferred base - no fixups needed. Lucky.
        return true;
    }

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0 || dir.VirtualAddress == 0) {
        // No reloc directory but we're not at preferred base. The PE was
        // built with /FIXED:NO is implied for DLLs - if you see this,
        // someone built the payload with /FIXED:YES and that's a build bug.
        r.Status = MapStatus::RelocationOutOfRange;
        return false;
    }

    // The reloc directory lives at an RVA - resolve it inside the payload's
    // local copy. We could instead read it back from the remote image but
    // since we already have the bytes locally, save the round trips.
    auto rvaToLocalPtr = [&](DWORD rva) -> const std::uint8_t* {
        // Walk sections to find the one containing this RVA.
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize) {
                return payload.data() + s.PointerToRawData + (rva - s.VirtualAddress);
            }
        }
        return nullptr;
    };

    const auto* relocBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
        rvaToLocalPtr(dir.VirtualAddress));
    const auto* relocEnd = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
        reinterpret_cast<const std::uint8_t*>(relocBlock) + dir.Size);

    while (relocBlock < relocEnd && relocBlock->SizeOfBlock > 0) {
        const std::size_t entryCount =
            (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const auto* entries = reinterpret_cast<const WORD*>(relocBlock + 1);

        for (std::size_t i = 0; i < entryCount; i++) {
            const WORD entry = entries[i];
            const WORD type = entry >> 12;
            const WORD offset = entry & 0x0FFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue; // Padding entry, not a real relocation
            }
            if (type != IMAGE_REL_BASED_DIR64) {
                r.Status = MapStatus::UnsupportedRelocationType;
                return false;
            }

            const std::uintptr_t target = r.RemoteImageBase + relocBlock->VirtualAddress + offset;
            std::uint64_t value = 0;
            if (!RemoteRead(target, &value, sizeof(value))) {
                r.Status = MapStatus::RelocationOutOfRange;
                return false;
            }
            value = static_cast<std::uint64_t>(static_cast<std::int64_t>(value) + delta);
            if (!RemoteWrite(target, &value, sizeof(value))) {
                r.Status = MapStatus::RelocationOutOfRange;
                return false;
            }
        }

        relocBlock = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<const std::uint8_t*>(relocBlock) + relocBlock->SizeOfBlock);
    }

    return true;
}

// -----------------------------------------------------------------------------
// Phase 5: Imports
// -----------------------------------------------------------------------------
//
// For each entry in the import descriptor table:
//   1. Resolve the DLL name -> base in target.
//   2. For each named/ordinal import, look up its export.
//   3. Write the resolved address into the IAT slot in remote memory.
//
// We do not bind imports - i.e., we don't do any optimization where the
// IAT is pre-filled at link time. Just walk and resolve every slot.

bool ManualMapper::ResolveImports(std::span<const std::uint8_t> payload, MapResult& r) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0 || dir.VirtualAddress == 0) {
        // No imports? Very unusual for a real DLL but not fatal.
        return true;
    }

    auto rvaToLocalPtr = [&](DWORD rva) -> const std::uint8_t* {
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize) {
                return payload.data() + s.PointerToRawData + (rva - s.VirtualAddress);
            }
        }
        return nullptr;
    };

    if (!RefreshModuleCache()) {
        r.Status = MapStatus::LoadLibraryRemoteFailed;
        return false;
    }

    const auto* importDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
        rvaToLocalPtr(dir.VirtualAddress));

    while (importDesc->Name != 0) {
        const char* dllName = reinterpret_cast<const char*>(rvaToLocalPtr(importDesc->Name));
        if (!dllName) {
            r.Status = MapStatus::LoadLibraryRemoteFailed;
            return false;
        }

        std::uintptr_t moduleBase = EnsureModuleLoaded(dllName);
        if (!moduleBase) {
            r.Status = MapStatus::LoadLibraryRemoteFailed;
            return false;
        }

        // OriginalFirstThunk (lookup) is read-only - tells us names/ordinals.
        // FirstThunk (IAT) is what we patch with resolved addresses.
        const DWORD lookupRva = importDesc->OriginalFirstThunk
            ? importDesc->OriginalFirstThunk
            : importDesc->FirstThunk;

        const auto* lookup = reinterpret_cast<const IMAGE_THUNK_DATA64*>(rvaToLocalPtr(lookupRva));
        std::uintptr_t iatRemote = r.RemoteImageBase + importDesc->FirstThunk;

        for (; lookup->u1.AddressOfData != 0; lookup++, iatRemote += sizeof(std::uintptr_t)) {
            std::uintptr_t funcAddr = 0;

            if (lookup->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // Import by ordinal. We need GetProcAddress on the ordinal,
                // which requires us to walk the export table of the remote
                // module ourselves (since GetProcAddress is local). For now,
                // punt - ordinal imports are rare in modern code.
                r.Status = MapStatus::GetProcAddressFailed;
                return false;
            } else {
                const auto* byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                    rvaToLocalPtr(static_cast<DWORD>(lookup->u1.AddressOfData)));
                if (!byName) {
                    r.Status = MapStatus::GetProcAddressFailed;
                    return false;
                }
                funcAddr = ResolveRemoteExport(moduleBase, byName->Name);
            }

            if (!funcAddr) {
                r.Status = MapStatus::GetProcAddressFailed;
                return false;
            }

            if (!RemoteWrite(iatRemote, &funcAddr, sizeof(funcAddr))) {
                r.Status = MapStatus::GetProcAddressFailed;
                return false;
            }
        }

        importDesc++;
    }

    return true;
}

// -----------------------------------------------------------------------------
// Phase 6: TLS callbacks
// -----------------------------------------------------------------------------
//
// TLS callbacks are tricky because they expect to run in the target process
// before DllMain. We invoke them via the same shellcode mechanism as
// BootEntry - one per callback - with reason=DLL_PROCESS_ATTACH.

bool ManualMapper::InvokeTlsCallbacks(std::span<const std::uint8_t> payload, MapResult& r) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir.Size == 0 || dir.VirtualAddress == 0) {
        return true; // no TLS, nothing to do
    }

    // The TLS directory lives at an RVA in the mapped image. Read the
    // IMAGE_TLS_DIRECTORY64 from remote memory (it was just copied there
    // by Phase 3, post-relocation).
    IMAGE_TLS_DIRECTORY64 tls{};
    if (!RemoteRead(r.RemoteImageBase + dir.VirtualAddress, &tls, sizeof(tls))) {
        r.Status = MapStatus::TlsCallbackFailed;
        return false;
    }

    if (tls.AddressOfCallBacks == 0) return true;

    // The callback array is a null-terminated list of function pointers.
    // Each entry is an absolute address (since relocations were applied).
    //
    // The proper TLS callback ABI is:
    //   VOID NTAPI Callback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
    //
    // CreateRemoteThread only delivers one argument (rcx). To match the
    // real ABI we allocate a small per-iteration trampoline that loads
    // rcx/rdx/r8 with (hModule, DLL_PROCESS_ATTACH, NULL) before calling
    // the callback. The trampoline returns 0 so GetExitCodeThread tells
    // us "callback completed without complaint".
    //
    // Trampoline layout (x64, 41 bytes):
    //   48 B9 <8>          mov rcx, hModule          ; DllHandle
    //   BA 01 00 00 00     mov edx, 1                ; DLL_PROCESS_ATTACH
    //   45 33 C0           xor r8d, r8d              ; Reserved = NULL
    //   48 B8 <8>          mov rax, callback
    //   48 83 EC 28        sub rsp, 0x28             ; shadow + align
    //   FF D0              call rax
    //   48 83 C4 28        add rsp, 0x28
    //   33 C0              xor eax, eax              ; return 0
    //   C3                 ret
    //
    // We allocate one stub region up front and re-use it per callback by
    // patching the callback address - cheap, since callbacks are rare
    // (most payload DLLs have zero or one).
    PVOID stubBase = nullptr;
    SIZE_T stubSize = 64;
    NTSTATUS allocStatus = NT_FALLBACK_FAIL;
    if (Nt().NtAllocateVirtualMemory) {
        allocStatus = Nt().NtAllocateVirtualMemory(
            m_Process, &stubBase, 0, &stubSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        stubBase = VirtualAllocEx(m_Process, nullptr, stubSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        allocStatus = stubBase ? 0 : -1;
    }
    if (!NT_OK(allocStatus) || !stubBase) {
        r.Status = MapStatus::TlsCallbackFailed;
        return false;
    }

    std::uintptr_t cursor = tls.AddressOfCallBacks;
    for (;;) {
        std::uintptr_t cb = 0;
        if (!RemoteRead(cursor, &cb, sizeof(cb))) {
            r.Status = MapStatus::TlsCallbackFailed;
            // The stub allocation outlives this loop - leak it for now;
            // failure mid-TLS already poisoned the process and we'll be
            // killed by the shim anyway.
            return false;
        }
        if (cb == 0) break;

        std::uint8_t stub[] = {
            0x48, 0xB9, 0,0,0,0,0,0,0,0,         // mov rcx, hModule
            0xBA, 0x01, 0x00, 0x00, 0x00,        // mov edx, 1 (DLL_PROCESS_ATTACH)
            0x45, 0x33, 0xC0,                    // xor r8d, r8d
            0x48, 0xB8, 0,0,0,0,0,0,0,0,         // mov rax, callback
            0x48, 0x83, 0xEC, 0x28,              // sub rsp, 0x28
            0xFF, 0xD0,                          // call rax
            0x48, 0x83, 0xC4, 0x28,              // add rsp, 0x28
            0x33, 0xC0,                          // xor eax, eax
            0xC3                                 // ret
        };
        std::memcpy(&stub[2],  &r.RemoteImageBase, sizeof(std::uintptr_t));
        std::memcpy(&stub[20], &cb,                sizeof(std::uintptr_t));

        // Re-protect to RW (in case we ran the loop already and dropped
        // to RX), write, then flip to RX.
        DWORD oldProtect = 0;
        if (!RemoteProtect(reinterpret_cast<std::uintptr_t>(stubBase), sizeof(stub),
                           PAGE_READWRITE, &oldProtect)) {
            r.Status = MapStatus::TlsCallbackFailed;
            return false;
        }
        if (!RemoteWrite(reinterpret_cast<std::uintptr_t>(stubBase), stub, sizeof(stub))) {
            r.Status = MapStatus::TlsCallbackFailed;
            return false;
        }
        if (!RemoteProtect(reinterpret_cast<std::uintptr_t>(stubBase), sizeof(stub),
                           PAGE_EXECUTE_READ, &oldProtect)) {
            r.Status = MapStatus::TlsCallbackFailed;
            return false;
        }

        HANDLE thread = CreateRemoteThread(
            m_Process, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(stubBase),
            nullptr, 0, nullptr);

        if (!thread) {
            r.Status = MapStatus::TlsCallbackFailed;
            return false;
        }

        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);

        cursor += sizeof(std::uintptr_t);
    }

    // Reclaim the trampoline now that we're done.
    if (Nt().NtFreeVirtualMemory) {
        SIZE_T zero = 0;
        Nt().NtFreeVirtualMemory(m_Process, &stubBase, &zero, MEM_RELEASE);
    } else {
        VirtualFreeEx(m_Process, stubBase, 0, MEM_RELEASE);
    }

    return true;
}

// -----------------------------------------------------------------------------
// Phase 7: Apply per-section protections
// -----------------------------------------------------------------------------
//
// This is where we drop from RW to the real protection bits. After this
// phase, no part of the mapped image is RWX.

bool ManualMapper::ApplyProtections(std::span<const std::uint8_t> payload, MapResult& r) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);

    // Headers themselves: read-only.
    DWORD oldProtect = 0;
    if (!RemoteProtect(r.RemoteImageBase, nt->OptionalHeader.SizeOfHeaders,
                       PAGE_READONLY, &oldProtect)) {
        r.Status = MapStatus::ProtectionApplyFailed;
        return false;
    }

    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        const auto& s = sections[i];
        if (s.Misc.VirtualSize == 0) continue;

        const DWORD prot = CharacteristicsToProtect(s.Characteristics);
        if (!RemoteProtect(r.RemoteImageBase + s.VirtualAddress,
                           s.Misc.VirtualSize, prot, &oldProtect)) {
            r.Status = MapStatus::ProtectionApplyFailed;
            return false;
        }
    }

    return true;
}

// -----------------------------------------------------------------------------
// Phase 8a: Locate the BootEntry export
// -----------------------------------------------------------------------------

bool ManualMapper::ResolveBootEntry(std::span<const std::uint8_t> payload, MapResult& r) {
    // Walk the export directory in the LOCAL copy of the payload to find
    // ENIBootEntry. We could read it from remote but local is faster and
    // we still have the bytes.
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload.data());
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload.data() + dos->e_lfanew);
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.Size == 0) {
        r.Status = MapStatus::MissingBootEntryExport;
        return false;
    }

    auto rvaToLocalPtr = [&](DWORD rva) -> const std::uint8_t* {
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.Misc.VirtualSize) {
                return payload.data() + s.PointerToRawData + (rva - s.VirtualAddress);
            }
        }
        return nullptr;
    };

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        rvaToLocalPtr(dir.VirtualAddress));
    const auto* names = reinterpret_cast<const DWORD*>(rvaToLocalPtr(exp->AddressOfNames));
    const auto* ords  = reinterpret_cast<const WORD*>(rvaToLocalPtr(exp->AddressOfNameOrdinals));
    const auto* funcs = reinterpret_cast<const DWORD*>(rvaToLocalPtr(exp->AddressOfFunctions));

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = reinterpret_cast<const char*>(rvaToLocalPtr(names[i]));
        if (name && std::strcmp(name, Boot::BootEntryExportName) == 0) {
            r.RemoteEntryPoint = r.RemoteImageBase + funcs[ords[i]];
            return true;
        }
    }

    r.Status = MapStatus::MissingBootEntryExport;
    return false;
}

// -----------------------------------------------------------------------------
// Phase 8b: Build BootInfo and write it to remote memory
// -----------------------------------------------------------------------------

bool ManualMapper::BuildAndWriteBootInfo(MapResult& r) {
    PVOID base = nullptr;
    SIZE_T size = sizeof(Boot::BootInfo);

    NTSTATUS status = NT_FALLBACK_FAIL;
    if (Nt().NtAllocateVirtualMemory) {
        status = Nt().NtAllocateVirtualMemory(
            m_Process, &base, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        base = VirtualAllocEx(m_Process, nullptr, size,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = base ? 0 : -1;
    }

    if (!NT_OK(status) || !base) {
        r.Status = MapStatus::AllocateBootInfoFailed;
        return false;
    }

    Boot::BootInfo bi{};
    bi.Magic = Boot::Magic;
    bi.Version = Boot::ProtocolVersion;
    bi.StructSize = sizeof(Boot::BootInfo);
    bi.Flags = m_Options.Flags;

    bi.Process.Pid = GetProcessId(m_Process);

    // Resolve the target's main image. The handle was supplied to the
    // mapper with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ at minimum,
    // which is what EnumProcessModules + GetModuleInformation need. The
    // payload uses these to anchor sigscans against the Roblox image -
    // without them the sigscan engine has to walk the loader's module
    // list itself, which races Hyperion's enumeration. See TODO #17.
    //
    // If the resolution fails (suspended-process edge cases, mostly), we
    // leave the fields zero - the payload knows zero means "fall back to
    // self-discovery" rather than "trust this and crash".
    std::uintptr_t imgBase = 0;
    std::uintptr_t imgSize = 0;
    std::wstring   exePath;
    if (ResolveTargetMainImage(m_Process, imgBase, imgSize, exePath)) {
        bi.Process.BaseAddress = imgBase;
        bi.Process.ImageSize   = imgSize;
        bi.Process.FileVersion = QueryPackedFileVersion(exePath.c_str());
    } else {
        bi.Process.BaseAddress = 0;
        bi.Process.ImageSize   = 0;
        bi.Process.FileVersion = 0;
    }

    bi.Addresses = m_Options.Addresses;

    auto copyPath = [](wchar_t* dst, const std::wstring& src) {
        const std::size_t n = std::min<std::size_t>(src.size(), Boot::MaxPathChars - 1);
        std::wmemcpy(dst, src.data(), n);
        dst[n] = L'\0';
    };
    copyPath(bi.ConfigDir,  m_Options.ConfigDir);
    copyPath(bi.ScriptsDir, m_Options.ScriptsDir);
    copyPath(bi.LogsDir,    m_Options.LogsDir);

    bi.SelfAddress = reinterpret_cast<std::uintptr_t>(base);
    bi.SelfSize = sizeof(Boot::BootInfo);

    if (!RemoteWrite(reinterpret_cast<std::uintptr_t>(base), &bi, sizeof(bi))) {
        r.Status = MapStatus::AllocateBootInfoFailed;
        return false;
    }

    r.RemoteBootInfo = reinterpret_cast<std::uintptr_t>(base);
    return true;
}

// -----------------------------------------------------------------------------
// Phase 9: Launch BootEntry
// -----------------------------------------------------------------------------
//
// We allocate a tiny shellcode region, write a stub that calls
// BootEntry(BootInfo*) and returns the result, and start a remote thread
// at the stub. Thread exit code = BootEntry return value. Wait up to
// BootTimeoutMs.
//
// Stub layout (x64):
//   48 B9 <8 byte BootInfo addr>     mov rcx, BootInfo
//   48 B8 <8 byte BootEntry addr>    mov rax, BootEntry
//   48 83 EC 28                      sub rsp, 0x28      ; shadow space + align
//   FF D0                            call rax
//   48 83 C4 28                      add rsp, 0x28
//   C3                               ret

bool ManualMapper::LaunchBootEntry(MapResult& r) {
    PVOID stubBase = nullptr;
    SIZE_T stubSize = 64;

    NTSTATUS status = NT_FALLBACK_FAIL;
    if (Nt().NtAllocateVirtualMemory) {
        status = Nt().NtAllocateVirtualMemory(
            m_Process, &stubBase, 0, &stubSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    } else {
        stubBase = VirtualAllocEx(m_Process, nullptr, stubSize,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = stubBase ? 0 : -1;
    }

    if (!NT_OK(status) || !stubBase) {
        r.Status = MapStatus::AllocateShellcodeFailed;
        return false;
    }

    std::uint8_t stub[] = {
        0x48, 0xB9, 0,0,0,0,0,0,0,0,             // mov rcx, BootInfo
        0x48, 0xB8, 0,0,0,0,0,0,0,0,             // mov rax, BootEntry
        0x48, 0x83, 0xEC, 0x28,                  // sub rsp, 0x28
        0xFF, 0xD0,                              // call rax
        0x48, 0x83, 0xC4, 0x28,                  // add rsp, 0x28
        0xC3                                     // ret
    };
    std::memcpy(&stub[2],  &r.RemoteBootInfo,    sizeof(std::uintptr_t));
    std::memcpy(&stub[12], &r.RemoteEntryPoint,  sizeof(std::uintptr_t));

    if (!RemoteWrite(reinterpret_cast<std::uintptr_t>(stubBase), stub, sizeof(stub))) {
        r.Status = MapStatus::AllocateShellcodeFailed;
        return false;
    }

    DWORD oldProtect = 0;
    if (!RemoteProtect(reinterpret_cast<std::uintptr_t>(stubBase), sizeof(stub),
                       PAGE_EXECUTE_READ, &oldProtect)) {
        r.Status = MapStatus::AllocateShellcodeFailed;
        return false;
    }

    r.BootStubAddress = reinterpret_cast<std::uintptr_t>(stubBase);

    HANDLE thread = CreateRemoteThread(
        m_Process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(stubBase),
        nullptr, 0, nullptr);
    if (!thread) {
        r.Status = MapStatus::BootThreadCreateFailed;
        return false;
    }

    const DWORD waitResult = WaitForSingleObject(
        thread, m_Options.BootTimeoutMs ? m_Options.BootTimeoutMs : INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);

    r.PayloadReturnCode = exitCode;

    if (waitResult == WAIT_TIMEOUT) {
        r.Status = MapStatus::BootEntryReturnedError;
        return false;
    }
    if (exitCode != 0) {
        r.Status = MapStatus::BootEntryReturnedError;
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------------
// Phase 10: Post-boot cleanup
// -----------------------------------------------------------------------------
//
// Erase headers if requested, free the shellcode region (the payload's
// boot is done; the stub is no longer needed), and optionally unlink from
// PEB->Ldr (currently a no-op since we never linked it - placeholder for
// when we add LDR-spoofing for tools that fake module presence).

bool ManualMapper::PostBootCleanup(MapResult& r) {
    if (m_Options.EraseHeaders) {
        // Overwrite the first page (typical SizeOfHeaders) with zeros.
        // We have to flip the protection back to RW briefly to do this.
        DWORD oldProtect = 0;
        const std::size_t headerSize = 0x1000; // good enough for typical PE
        if (RemoteProtect(r.RemoteImageBase, headerSize, PAGE_READWRITE, &oldProtect)) {
            std::vector<std::uint8_t> zeros(headerSize, 0);
            RemoteWrite(r.RemoteImageBase, zeros.data(), zeros.size());
            RemoteProtect(r.RemoteImageBase, headerSize, PAGE_READONLY, &oldProtect);
        }
        // Failure to erase isn't fatal; log and move on.
    }

    if (m_Options.UnlinkFromPeb) {
        // Placeholder. We never linked the manually-mapped image into
        // PEB->Ldr (manual mapping by definition skips that step), so
        // there's nothing to unlink. Real LDR-spoofing would create a
        // fake LDR_DATA_TABLE_ENTRY for stealth-from-LDR-walkers tooling
        // that checks "is my module visible?" - we'll address that in a
        // later pass.
    }

    // Free the boot stub - it's done its job.
    if (r.BootStubAddress && Nt().NtFreeVirtualMemory) {
        PVOID base = reinterpret_cast<PVOID>(r.BootStubAddress);
        SIZE_T size = 0;
        Nt().NtFreeVirtualMemory(m_Process, &base, &size, MEM_RELEASE);
    }

    return true;
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

bool ManualMapper::RemoteWrite(std::uintptr_t target, const void* source, std::size_t size) {
    SIZE_T written = 0;
    if (Nt().NtWriteVirtualMemory) {
        const NTSTATUS s = Nt().NtWriteVirtualMemory(
            m_Process, reinterpret_cast<PVOID>(target),
            const_cast<PVOID>(source), size, &written);
        return NT_OK(s) && written == size;
    }
    return WriteProcessMemory(m_Process, reinterpret_cast<LPVOID>(target),
                              source, size, &written) && written == size;
}

bool ManualMapper::RemoteRead(std::uintptr_t source, void* dest, std::size_t size) {
    SIZE_T read = 0;
    if (Nt().NtReadVirtualMemory) {
        const NTSTATUS s = Nt().NtReadVirtualMemory(
            m_Process, reinterpret_cast<PVOID>(source),
            dest, size, &read);
        return NT_OK(s) && read == size;
    }
    return ReadProcessMemory(m_Process, reinterpret_cast<LPCVOID>(source),
                             dest, size, &read) && read == size;
}

bool ManualMapper::RemoteProtect(std::uintptr_t target, std::size_t size,
                                 DWORD newProtect, DWORD* oldProtect) {
    if (Nt().NtProtectVirtualMemory) {
        PVOID addr = reinterpret_cast<PVOID>(target);
        SIZE_T sz = size;
        ULONG oldP = 0;
        const NTSTATUS s = Nt().NtProtectVirtualMemory(
            m_Process, &addr, &sz, newProtect, &oldP);
        if (oldProtect) *oldProtect = oldP;
        return NT_OK(s);
    }
    return VirtualProtectEx(m_Process, reinterpret_cast<LPVOID>(target),
                            size, newProtect, oldProtect) != 0;
}

std::uintptr_t ManualMapper::ResolveRemoteExport(std::uintptr_t moduleBase, const char* exportName) {
    // Forward-chain bound. In the wild we observe at most 2 hops
    // (api-ms-win-*-l1 -> kernelbase -> ntdll). Eight hops is more than
    // enough headroom and short-circuits any pathological chain.
    constexpr int kMaxForwardHops = 8;
    std::string forwardOwned;  // owns string memory across hops

    for (int hop = 0; hop < kMaxForwardHops; ++hop) {
    // Read the PE headers from the remote module to find the export
    // directory. Slower than GetProcAddress on a local handle but works
    // for any module mapped in the target.
    IMAGE_DOS_HEADER dos{};
    if (!RemoteRead(moduleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!RemoteRead(moduleBase + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.Size == 0) return 0;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!RemoteRead(moduleBase + dir.VirtualAddress, &exp, sizeof(exp))) return 0;

    // Pull the three relevant arrays in one batch each.
    std::vector<DWORD> nameRvas(exp.NumberOfNames);
    std::vector<WORD>  nameOrds(exp.NumberOfNames);
    std::vector<DWORD> funcRvas(exp.NumberOfFunctions);

    if (!RemoteRead(moduleBase + exp.AddressOfNames,        nameRvas.data(), nameRvas.size() * sizeof(DWORD))) return 0;
    if (!RemoteRead(moduleBase + exp.AddressOfNameOrdinals, nameOrds.data(), nameOrds.size() * sizeof(WORD)))  return 0;
    if (!RemoteRead(moduleBase + exp.AddressOfFunctions,    funcRvas.data(), funcRvas.size() * sizeof(DWORD))) return 0;

    // Linear search by name. Could binary-search since names are sorted,
    // but exports lists are short (a few hundred at most) and we only do
    // this once per imported function.
    char nameBuffer[256];
    for (DWORD i = 0; i < exp.NumberOfNames; i++) {
        if (!RemoteRead(moduleBase + nameRvas[i], nameBuffer, sizeof(nameBuffer))) continue;
        nameBuffer[sizeof(nameBuffer) - 1] = '\0';
        if (std::strcmp(nameBuffer, exportName) != 0) continue;

        const DWORD rva = funcRvas[nameOrds[i]];

        // Forwarded export: the RVA points inside the export directory
        // itself, and the bytes there are a NUL-terminated ASCII string
        // of the form "OTHER.FuncName" - the import has been redirected
        // to a different module (commonly an api-ms-win-* shim forwarding
        // to ntdll/kernelbase). We have to chase the forward to get a
        // usable address.
        //
        // Edge cases handled below:
        //   * Forward by name: "kernelbase.HeapAlloc" -> resolve "HeapAlloc"
        //     in kernelbase.
        //   * Forward by ordinal: "kernelbase.#123" -> ordinal lookup, not
        //     supported here (rare in the surface we use). Bail with 0
        //     and let the caller treat it as GetProcAddressFailed.
        //   * Forwarded forwarders: a chase that lands on another forward.
        //     Bound the recursion depth so a circular-or-pathological
        //     chain can't hang the loader.
        if (rva < dir.VirtualAddress || rva >= dir.VirtualAddress + dir.Size) {
            return moduleBase + rva;
        }

        char fwd[256] = {};
        if (!RemoteRead(moduleBase + rva, fwd, sizeof(fwd) - 1)) return 0;
        fwd[sizeof(fwd) - 1] = '\0';

        // Split at the LAST dot. Modern api-ms-win-* names are themselves
        // dot-laden ("api-ms-win-core-heap-l1-2-0.HeapAlloc"), so a left
        // split would peel off "api-ms-win-core-heap-l1-2-0" which is the
        // module name and "HeapAlloc" - that happens to be correct here,
        // but only because those names use the last dot for the boundary.
        // Use rfind to be safe across both classic and api-set forms.
        const char* dot = std::strrchr(fwd, '.');
        if (!dot || dot == fwd || *(dot + 1) == '\0') return 0;

        std::string modName(fwd, dot - fwd);
        const char* funcPart = dot + 1;

        // Ordinal forwards look like "Foo.#123" - skip for now.
        if (funcPart[0] == '#') return 0;

        // Append .dll if the forward didn't include an extension. Both
        // forms exist in the wild (kernel32 forwards to "NTDLL.RtlXxx",
        // api-ms-win-* forwards to "ucrtbase.strlen" without .dll).
        if (modName.find('.') == std::string::npos) {
            modName += ".dll";
        }

        std::uintptr_t targetBase = EnsureModuleLoaded(modName.c_str());
        if (!targetBase) return 0;

        // Iterate rather than recurse - bounds the call stack and lets us
        // re-use the depth counter across the whole chain. forwardOwned
        // keeps the funcPart pointer alive for the next hop (the local
        // `fwd` buffer goes out of scope as soon as we re-enter).
        forwardOwned.assign(funcPart);
        moduleBase = targetBase;
        exportName = forwardOwned.c_str();
        goto next_hop;
    }

    // Name not found in this module's exports.
    return 0;

    next_hop:; // continue outer loop
    }

    // Forward chain too deep - give up.
    return 0;
}

std::uintptr_t ManualMapper::EnsureModuleLoaded(const char* moduleName) {
    const std::string lookup = ToLowerAscii(moduleName);

    for (const auto& m : m_ModuleCache) {
        if (m.Name == lookup) return m.Base;
    }

    // Not loaded - inject LoadLibraryA via remote thread. This is detectable
    // (CreateRemoteThread to LoadLibraryA is the textbook IOC) but we only
    // hit it when an imported DLL isn't already mapped, which for system
    // DLLs in a Roblox process is essentially never.
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return 0;
    auto loadLibraryA = GetProcAddress(k32, "LoadLibraryA");
    if (!loadLibraryA) return 0;

    SIZE_T nameLen = std::strlen(moduleName) + 1;
    LPVOID remoteName = VirtualAllocEx(m_Process, nullptr, nameLen,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteName) return 0;

    SIZE_T written = 0;
    if (!WriteProcessMemory(m_Process, remoteName, moduleName, nameLen, &written)) {
        VirtualFreeEx(m_Process, remoteName, 0, MEM_RELEASE);
        return 0;
    }

    HANDLE thread = CreateRemoteThread(
        m_Process, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryA),
        remoteName, 0, nullptr);
    if (!thread) {
        VirtualFreeEx(m_Process, remoteName, 0, MEM_RELEASE);
        return 0;
    }

    WaitForSingleObject(thread, 10000);
    CloseHandle(thread);
    VirtualFreeEx(m_Process, remoteName, 0, MEM_RELEASE);

    // Refresh and look up again.
    if (!RefreshModuleCache()) return 0;
    for (const auto& m : m_ModuleCache) {
        if (m.Name == lookup) return m.Base;
    }
    return 0;
}

bool ManualMapper::RefreshModuleCache() {
    m_ModuleCache.clear();

    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(m_Process));
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me)) {
        // Convert wide name to ASCII lower-case for our cache.
        char ascii[MAX_MODULE_NAME32 + 4] = {};
        WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, ascii, sizeof(ascii), nullptr, nullptr);

        m_ModuleCache.push_back(LoadedModule{
            ToLowerAscii(ascii),
            reinterpret_cast<std::uintptr_t>(me.modBaseAddr),
            me.modBaseSize,
        });
    }
    CloseHandle(snap);
    return true;
}

} // namespace ENI::Injector
