#pragma once

// =============================================================================
// Hyperion::NtApi - clean NT-syscall stub cache + ntdll discovery
// =============================================================================
//
// The payload's first job, once it's running inside Roblox, is to grab a
// pristine copy of every NT export it expects to need to hook later. We
// do this BEFORE Hyperion's DllMain has a chance to overwrite ntdll's
// stubs with its own indirection.
//
// What "stub" means here: each Nt* export in ntdll on x64 looks like
//
//     mov r10, rcx          4C 8B D1
//     mov eax, <syscallno>  B8 ?? ?? ?? ??
//     test byte ptr [...    F6 04 25 08 03 FE 7F 01    ; only on Win10+
//     jne <kifast...>       75 03                       ; only on Win10+
//     syscall               0F 05
//     ret                   C3
//
// We snapshot the first 32 bytes verbatim so even if Hyperion overwrites
// the live bytes, we still have the original on hand. We also extract
// the syscall number (the imm32 after the B8) for diagnostics.
//
// The cache is fixed-size, fixed-list, no allocation.
// =============================================================================

#include <cstdint>

namespace ENI::Hyperion::NtApi {

// All the NT exports we care about across the payload. Each one gets a
// cached stub; failure to cache any individual one is non-fatal (we log
// and continue), but if NtAllocateVirtualMemory or NtProtectVirtualMemory
// fail to cache, anything downstream will be on shaky ground.
//
// Ordered by likelihood of hooking in v1.
enum class StubId : std::uint32_t {
    NtSetInformationProcess = 0,
    NtQueryInformationProcess,
    NtQueryVirtualMemory,
    NtSetInformationThread,
    NtQueryInformationThread,
    NtClose,
    NtProtectVirtualMemory,
    NtAllocateVirtualMemory,
    NtFreeVirtualMemory,
    NtMapViewOfSection,
    NtUnmapViewOfSection,
    NtCreateThreadEx,

    Count
};

struct Stub {
    const char*   Name;        // e.g. "NtSetInformationProcess"
    void*         Address;     // resolved ntdll export, 0 if not found
    std::uint8_t  Bytes[32];   // first 32 bytes copied verbatim
    std::uint32_t SyscallNo;   // extracted from "mov eax, imm32"; 0 if not parsed
    bool          Cached;
};

// Locate ntdll.dll's image base. Walks PEB→Ldr→InMemoryOrderModuleList.
// Returns 0 on failure.
std::uintptr_t FindNtdllBase();

// Snapshot every stub in the table. Must be called BEFORE installing any
// hooks. Idempotent - subsequent calls are no-ops. Returns the number of
// stubs successfully cached.
std::uint32_t CacheAll(std::uintptr_t ntdllBase);

// Look up a cached stub. Returns nullptr if not cached.
const Stub* Get(StubId id);

// Direct address of a cached stub. Convenience.
inline void* Address(StubId id) {
    const Stub* s = Get(id);
    return s ? s->Address : nullptr;
}

} // namespace ENI::Hyperion::NtApi
