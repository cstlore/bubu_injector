// =============================================================================
// NtApi.cpp - the clean-stub cache + ntdll walker
// =============================================================================
//
// Two pieces here:
//
//   1. FindNtdllBase: walks PEB->Ldr to find ntdll. We can't use
//      GetModuleHandleW reliably from inside our manual-mapped payload
//      because the loader is still partially set up when we run, and
//      our own image was never linked into the LDR list. PEB itself is
//      always populated by the kernel before any user thread runs.
//
//   2. CacheAll: for each stub in the table, GetProcAddress equivalent
//      (we walk ntdll's export directory ourselves so we don't depend
//      on kernel32!GetProcAddress, which Hyperion is known to hook).
//      Then we copy the first 32 bytes and extract the syscall number.
//
// =============================================================================

#include "Hyperion/NtApi.h"
#include "Hyperion/Log.h"

#include <cstddef>
#include <cstring>
#include <cwchar>
#include <windows.h>
#include <winternl.h>

namespace ENI::Hyperion::NtApi {

namespace {

// We declare the NT loader-data structures inline rather than pulling
// in a third-party "ntdll headers" package. PEB_LDR_DATA layout has
// been stable since Windows XP.
struct LDR_DATA_TABLE_ENTRY_min {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

bool BaseNameEquals(const UNICODE_STRING& s, const wchar_t* expected) {
    if (!s.Buffer) return false;
    const std::size_t expectedLen = std::wcslen(expected);
    if (s.Length / sizeof(wchar_t) != expectedLen) return false;
    for (std::size_t i = 0; i < expectedLen; i++) {
        wchar_t a = s.Buffer[i];
        wchar_t b = expected[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b - L'A' + L'a');
        if (a != b) return false;
    }
    return true;
}

// PEB pointer is in GS:[0x60] on x64.
PEB* GetPEB() {
    return reinterpret_cast<PEB*>(__readgsqword(0x60));
}

// Walk ntdll's export directory by hand and return the address of
// `name`, or nullptr. This is used during the boot path before MinHook
// is even initialized, so we cannot rely on GetProcAddress (which
// kernel32 forwards through ntdll!LdrGetProcedureAddress and may have
// been hooked).
void* ResolveExportByName(std::uintptr_t moduleBase, const char* name) {
    if (!moduleBase || !name) return nullptr;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.Size) return nullptr;

    auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(moduleBase + dir.VirtualAddress);
    auto* names = reinterpret_cast<DWORD*>(moduleBase + exp->AddressOfNames);
    auto* ords  = reinterpret_cast<WORD*>(moduleBase + exp->AddressOfNameOrdinals);
    auto* funcs = reinterpret_cast<DWORD*>(moduleBase + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* n = reinterpret_cast<const char*>(moduleBase + names[i]);
        if (std::strcmp(n, name) == 0) {
            const DWORD rva = funcs[ords[i]];
            // Forwarded exports (rare in ntdll) point inside the export
            // directory itself. We don't follow them - if it's forwarded,
            // it's not a normal syscall stub anyway.
            if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size) {
                return nullptr;
            }
            return reinterpret_cast<void*>(moduleBase + rva);
        }
    }
    return nullptr;
}

// The fixed table of stubs, indexed by StubId. Names mirror the enum
// ordering exactly; if you reorder StubId, this table must follow.
Stub g_Table[static_cast<std::size_t>(StubId::Count)] = {
    {"NtSetInformationProcess",     nullptr, {}, 0, false},
    {"NtQueryInformationProcess",   nullptr, {}, 0, false},
    {"NtQueryVirtualMemory",        nullptr, {}, 0, false},
    {"NtSetInformationThread",      nullptr, {}, 0, false},
    {"NtQueryInformationThread",    nullptr, {}, 0, false},
    {"NtClose",                     nullptr, {}, 0, false},
    {"NtProtectVirtualMemory",      nullptr, {}, 0, false},
    {"NtAllocateVirtualMemory",     nullptr, {}, 0, false},
    {"NtFreeVirtualMemory",         nullptr, {}, 0, false},
    {"NtMapViewOfSection",          nullptr, {}, 0, false},
    {"NtUnmapViewOfSection",        nullptr, {}, 0, false},
    {"NtCreateThreadEx",            nullptr, {}, 0, false},
};

// Pull the syscall number out of the stub bytes. Pattern:
//   4C 8B D1            mov r10, rcx        (3 bytes)
//   B8 ?? ?? ?? ??      mov eax, imm32      (5 bytes, syscall # in last 4)
// Returns 0 if the pattern doesn't match (e.g. on a heavily-hooked stub
// where Hyperion has already overwritten the prologue, or on an export
// that's not actually a syscall wrapper - some Nt* exports are pure
// user-mode helpers and don't map to a syscall number).
std::uint32_t ExtractSyscallNo(const std::uint8_t* bytes) {
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
        bytes[3] == 0xB8) {
        std::uint32_t n;
        std::memcpy(&n, bytes + 4, sizeof(n));
        return n;
    }
    return 0;
}

bool g_Cached = false;

} // namespace

std::uintptr_t FindNtdllBase() {
    PEB* peb = GetPEB();
    if (!peb || !peb->Ldr) return 0;

    // PEB_LDR_DATA->InMemoryOrderModuleList: doubly-linked list of
    // LDR_DATA_TABLE_ENTRY chained by InMemoryOrderLinks. The list head
    // itself is in PEB_LDR_DATA, and the entries are at
    // CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks).
    // The first three entries on Windows are the EXE itself, ntdll, and
    // kernel32 - in load order. Ntdll might be entry #1 or #2 depending
    // on Windows build, so we walk and match by name.
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        // CONTAINING_RECORD by hand: subtract offsetof(LDR..., InMemoryOrderLinks).
        auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_min*>(
            reinterpret_cast<std::uint8_t*>(cur) -
            offsetof(LDR_DATA_TABLE_ENTRY_min, InMemoryOrderLinks));

        if (BaseNameEquals(entry->BaseDllName, L"ntdll.dll")) {
            return reinterpret_cast<std::uintptr_t>(entry->DllBase);
        }
    }
    return 0;
}

std::uint32_t CacheAll(std::uintptr_t ntdllBase) {
    if (g_Cached) return 0;
    if (!ntdllBase) return 0;

    std::uint32_t cached = 0;
    for (std::size_t i = 0; i < static_cast<std::size_t>(StubId::Count); i++) {
        Stub& s = g_Table[i];
        s.Address = ResolveExportByName(ntdllBase, s.Name);
        if (!s.Address) {
            Log::Line("[ntapi] %s NOT FOUND in ntdll", s.Name);
            continue;
        }
        std::memcpy(s.Bytes, s.Address, sizeof(s.Bytes));
        s.SyscallNo = ExtractSyscallNo(s.Bytes);
        s.Cached = true;
        cached++;
        Log::Line("[ntapi] %-32s @ %p syscall=0x%X",
                  s.Name, s.Address, s.SyscallNo);
    }

    g_Cached = true;
    return cached;
}

const Stub* Get(StubId id) {
    const auto idx = static_cast<std::size_t>(id);
    if (idx >= static_cast<std::size_t>(StubId::Count)) return nullptr;
    const Stub& s = g_Table[idx];
    return s.Cached ? &s : nullptr;
}

} // namespace ENI::Hyperion::NtApi
