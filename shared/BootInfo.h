#pragma once

// =============================================================================
// BootInfo.h - Loader/Payload Boot Contract
// =============================================================================
//
// This header defines the EXACT binary layout the injector passes to the
// payload DLL when it invokes the payload's exported BootEntry function via
// shellcode. Both sides MUST agree on this layout - any mismatch and we read
// garbage on the payload side and crash, hard.
//
// Versioning rules:
//   - Bumping ENI_BOOT_PROTOCOL_VERSION is REQUIRED on every binary-breaking
//     change (field added, removed, reordered, or resized).
//   - The payload checks the version on entry. Mismatch -> bail out fast,
//     don't try to be clever and parse a foreign struct.
//   - Adding a new field at the END of the struct is still a binary break,
//     because the payload sizeof check would reject smaller structs anyway.
//
// Layout rules:
//   - Pack to 8 bytes. We are x64-only.
//   - All pointers are uintptr_t, not native types - the loader and payload
//     agree on the bit-width here without having to drag in <windows.h>.
//   - No constructors, no virtuals, no STL types. POD only. The struct has
//     to be writable from one process and readable from another with zero
//     marshaling.
//
// =============================================================================

#include <cstddef>
#include <cstddef>
#include <cstdint>

namespace ENI::Boot {

// Bumped ANY time the layout below changes. Loader stamps this in,
// payload checks for exact match.
constexpr std::uint32_t ProtocolVersion = 1;

// Magic number to catch obvious corruption / wrong-pointer-to-BootEntry.
// "ENIB" in little-endian = 0x42494E45. Any payload that sees a BootInfo
// without this magic should refuse to run rather than risk dereferencing
// junk pointers.
constexpr std::uint32_t Magic = 0x42494E45;

// Maximum length of paths embedded inline. We pass paths inline rather
// than as pointers so the payload doesn't need to keep the loader process
// alive to read them - the loader can exit immediately after BootEntry
// returns.
constexpr std::size_t MaxPathChars = 520; // MAX_PATH (260) doubled for UNC

// Direct-syscall stub function pointers. The payload can use these to
// avoid going through the user-mode wrappers that Hyperion likes to hook.
// If a stub is null, the payload should fall back to the documented API
// or abort, depending on how critical the call is.
//
// Signatures match the NT-layer prototypes exactly. We don't include
// <winternl.h> here - everything is uintptr_t on the wire.
struct SyscallTable {
    // NTSTATUS NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)
    std::uintptr_t NtAllocateVirtualMemory;

    // NTSTATUS NtFreeVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG)
    std::uintptr_t NtFreeVirtualMemory;

    // NTSTATUS NtProtectVirtualMemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)
    std::uintptr_t NtProtectVirtualMemory;

    // NTSTATUS NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
    std::uintptr_t NtReadVirtualMemory;

    // NTSTATUS NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
    std::uintptr_t NtWriteVirtualMemory;

    // NTSTATUS NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T)
    std::uintptr_t NtQueryVirtualMemory;
};

// Pre-resolved Roblox function addresses. The loader scans for these once
// during version verification and hands them to the payload so the payload
// doesn't repeat the work. Any field can be 0 if scanning failed - the
// payload handles graceful degradation per-feature.
//
// All addresses are absolute virtual addresses inside the Roblox process,
// already resolved from any RIP-relative encoding.
struct ResolvedAddresses {
    std::uintptr_t LuaState;        // The lua_State* (already / 8 decoded)
    std::uintptr_t LuauLoad;        // luau_load function entry
    std::uintptr_t LuaPCall;        // lua_pcall function entry
    std::uintptr_t DataModel;       // DataModel* (already dereferenced)
    std::uintptr_t TaskScheduler;   // For scheduling work on a Roblox thread
    std::uintptr_t Print;           // Roblox's internal print for hooking
    std::uintptr_t IdentityGetter;  // getidentity / fenv-context fetcher
    std::uintptr_t IdentitySetter;  // setidentity counterpart
    std::uintptr_t RawMetatableGetter;
    std::uintptr_t RawMetatableSetter;
    std::uintptr_t CallingScriptGetter;
    std::uintptr_t FireClick;
    std::uintptr_t TeleportService;

    // Reserved for future signatures. Pad out so adding new addresses
    // doesn't bump ProtocolVersion every single time. When all reserved
    // slots fill, then we bump.
    std::uintptr_t Reserved[8];
};

// Roblox process identity. Mostly informational for the payload's logs,
// but PID + base are needed if the payload ever wants to spawn helper
// threads with spoofed start addresses (it needs to know its own context).
struct ProcessInfo {
    std::uint32_t Pid;              // Roblox PID
    std::uint32_t Padding;          // Explicit padding to keep alignment
    std::uintptr_t BaseAddress;     // RobloxPlayerBeta.exe image base
    std::uintptr_t ImageSize;       // Size of the image
    std::uint64_t FileVersion;      // Packed: major<<48 | minor<<32 | build<<16 | revision
};

// The full payload contract. Loader allocates this in remote memory,
// fills it, then passes its address as the single argument to BootEntry.
struct BootInfo {
    // Header - sanity-check fields the payload reads first.
    std::uint32_t Magic;            // == ENI::Boot::Magic
    std::uint32_t Version;          // == ENI::Boot::ProtocolVersion
    std::uint32_t StructSize;       // == sizeof(BootInfo)
    std::uint32_t Flags;            // see BootFlags below

    ProcessInfo Process;
    SyscallTable Syscalls;
    ResolvedAddresses Addresses;

    // Filesystem paths the payload uses for config, scripts, logs.
    // We pass these in because the payload's std::filesystem::current_path()
    // would inherit Roblox's working dir, which is wrong (and unstable
    // across launch methods - browser vs. shortcut vs. direct).
    //
    // Wide chars - Cyrillic / CJK usernames in %APPDATA% are common.
    wchar_t ConfigDir[MaxPathChars];
    wchar_t ScriptsDir[MaxPathChars];
    wchar_t LogsDir[MaxPathChars];

    // Set by the loader to the address of itself in the remote process,
    // so the payload can MEM_RELEASE this region after copying out what
    // it needs. Not doing this leaks ~4KB until process exit, which is
    // fine for correctness but bad for hygiene under memory scanners.
    std::uintptr_t SelfAddress;
    std::uintptr_t SelfSize;

    // Reserved for future fields without bumping version. Always zero
    // when the loader writes; payload ignores.
    std::uint64_t Reserved[16];
};

// Boot flags - bitfield in BootInfo::Flags.
namespace BootFlags {
    constexpr std::uint32_t None              = 0;

    // Loader was able to inject before Hyperion stage-2. The payload
    // can use direct VirtualAlloc / VirtualProtect freely. If unset,
    // the payload should prefer the syscall stubs and assume CIG/ACG
    // are active.
    constexpr std::uint32_t PreHyperion       = 1u << 0;

    // Loader manually erased the PE headers after mapping. Payload should
    // NOT try to re-read its own headers (e.g., for module enumeration).
    constexpr std::uint32_t HeadersErased     = 1u << 1;

    // Loader unlinked the module from PEB->Ldr. Payload's HMODULE-based
    // calls (LoadLibrary returning the same module, GetModuleHandle for self)
    // will fail.
    constexpr std::uint32_t ModuleUnlinked    = 1u << 2;

    // Debug build of the loader. Payload may opt to be more verbose.
    constexpr std::uint32_t DebugLoader       = 1u << 3;
}

// Static assertions to catch alignment / size mistakes at compile time.
// If any of these fire, the loader and payload would disagree on layout.
static_assert(sizeof(SyscallTable) == 6 * sizeof(std::uintptr_t),
              "SyscallTable layout drift");
static_assert(sizeof(ProcessInfo) % 8 == 0,
              "ProcessInfo alignment drift");
static_assert(sizeof(BootInfo) % 8 == 0,
              "BootInfo alignment drift");
static_assert(offsetof(BootInfo, Magic) == 0,
              "Magic must be the first field for sanity-checking");

// The payload exports a single function with this signature. The loader's
// shellcode calls it after the manual map completes.
//
// Return value: 0 on success, non-zero error code on failure. The loader
// can read this via GetExitCodeThread on the boot thread it created.
//
// extern "C" __declspec(dllexport) std::uint32_t ENIBootEntry(const BootInfo*);
constexpr const char* BootEntryExportName = "ENIBootEntry";

} // namespace ENI::Boot
