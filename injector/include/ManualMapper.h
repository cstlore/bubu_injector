#pragma once

// =============================================================================
// ManualMapper.h - PE manual mapping into a remote process
// =============================================================================
//
// This is the core of the loader. Given a payload DLL as raw bytes in our
// own memory, we:
//
//   1. Parse the PE headers (DOS, NT, optional, sections).
//   2. Allocate a contiguous region in the target process big enough for
//      the SizeOfImage. We try to use NtAllocateVirtualMemory directly
//      so the allocation isn't trivially traceable to our own thread.
//   3. Copy each section to its RVA, with padding zeroed.
//   4. Walk the base relocation directory and patch every RVA that
//      depends on the image base, using the delta between the chosen
//      remote address and the PE's PreferredImageBase.
//   5. Resolve the import address table - for each imported DLL, ensure
//      it's loaded in the target (LoadLibraryA via remote thread if not),
//      then for each function, resolve its address (GetProcAddress) and
//      patch the IAT slot.
//   6. Walk TLS callbacks (if the payload has any) and invoke them with
//      DLL_PROCESS_ATTACH semantics.
//   7. Apply per-section memory protections (RW for data, RX for code,
//      R for rdata) - never RWX simultaneously, that's the #1 thing AVs
//      flag.
//   8. Build a BootInfo struct in remote memory and write it.
//   9. Build shellcode that calls the payload's BootEntry export with
//      the BootInfo address, and execute it via CreateRemoteThread (or
//      thread hijack for stealth - selectable).
//  10. Optionally erase the PE headers in target memory and unlink from
//      the PEB module list.
//
// The mapper does NOT touch the disk. The payload bytes are passed in as
// a span; the caller is responsible for getting them there (decrypting an
// embedded resource, downloading from CDN, reading a file, whatever).
//
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

#include "../../shared/BootInfo.h"

namespace ENI::Injector {

// Result codes - granular so the UI / log can tell the user what failed
// without making them read a HRESULT table. Order roughly matches the
// pipeline stages above so the value tells you how far we got.
enum class MapStatus : std::uint32_t {
    Ok = 0,

    // Validation
    InvalidPeImage,             // No DOS / NT signature
    NotX64,                     // Machine != IMAGE_FILE_MACHINE_AMD64
    NotDll,                     // FileHeader Characteristics lacks DLL flag
    NoEntryPoint,               // OptionalHeader.AddressOfEntryPoint == 0
    MissingBootEntryExport,     // Payload doesn't export ENIBootEntry

    // Allocation
    AllocateImageFailed,        // NtAllocateVirtualMemory for SizeOfImage
    AllocateBootInfoFailed,     // NtAllocateVirtualMemory for BootInfo struct
    AllocateShellcodeFailed,    // NtAllocateVirtualMemory for the boot stub

    // Copy
    SectionCopyFailed,          // NtWriteVirtualMemory mid-section

    // Relocations
    RelocationOutOfRange,       // RVA in reloc block points outside image
    UnsupportedRelocationType,  // Anything other than ABSOLUTE / DIR64 on x64

    // Imports
    LoadLibraryRemoteFailed,    // CreateRemoteThread(LoadLibraryA) returned 0
    GetProcAddressFailed,       // Function not found in target module

    // TLS / Boot
    TlsCallbackFailed,          // A TLS callback returned non-zero or crashed
    ProtectionApplyFailed,      // VirtualProtectEx for one of the sections
    BootThreadCreateFailed,     // CreateRemoteThread for the boot stub
    BootEntryReturnedError,     // Payload's BootEntry returned non-zero

    // Process / handle
    ProcessHandleInvalid,
    ProcessNotX64,

    // Misc
    OutOfMemoryLocal,           // Couldn't allocate scratch on our side
    InternalLogicError,         // Bug in the mapper - shouldn't happen, file a ticket
};

const char* MapStatusToString(MapStatus s);

// Options that change the mapping behavior. Defaults are "production
// safe" - stealth on, RWX off, headers erased. Loosen for debugging.
struct MapOptions {
    // If true, after mapping is complete, overwrite the PE headers in
    // target memory with random bytes. Costs nothing, makes dumping the
    // module harder. ON by default.
    bool EraseHeaders = true;

    // If true, unlink the (fake) module entry from PEB->Ldr's three
    // lists after boot completes. Required for any real anti-detection;
    // off only for debugging via tools that walk LDR. ON by default.
    bool UnlinkFromPeb = true;

    // If true, randomize the choice of remote base address (within the
    // allowable range) instead of letting NtAllocateVirtualMemory pick
    // sequentially. Marginal stealth benefit, slight risk of failing to
    // find a free region. OFF by default.
    bool RandomizeBase = false;

    // If true, use CreateRemoteThread to invoke BootEntry. If false,
    // hijack an existing thread via SetThreadContext - much harder to
    // detect but more fragile. CreateRemoteThread by default while we
    // get the rest of the pipeline solid; flip to false in production.
    bool UseRemoteThread = true;

    // Wait this many milliseconds for BootEntry to return before assuming
    // it's stuck and forcibly cleaning up. Zero = wait forever. Default
    // 30s - if BootEntry takes longer than that we have bigger problems.
    std::uint32_t BootTimeoutMs = 30000;

    // Path to write the boot info paths. If any of these are empty we
    // pick reasonable defaults under %APPDATA%\ENI.
    std::wstring ConfigDir;
    std::wstring ScriptsDir;
    std::wstring LogsDir;

    // Pre-resolved Roblox addresses to embed in BootInfo. Loader fills
    // these from its version-detection pass before calling Map().
    Boot::ResolvedAddresses Addresses{};

    // Loader-injected boot flags (PreHyperion, etc.).
    std::uint32_t Flags = 0;
};

// What the mapper returns after a successful Map(). Useful for the loader
// to remember the allocation if it ever wants to MEM_RELEASE on detach.
// Also exposes diagnostic addresses for log lines.
struct MapResult {
    MapStatus Status = MapStatus::InternalLogicError;

    std::uintptr_t RemoteImageBase = 0;     // Where the payload now lives
    std::uintptr_t RemoteImageSize = 0;     // SizeOfImage from the payload
    std::uintptr_t RemoteBootInfo = 0;      // BootInfo struct in target
    std::uintptr_t RemoteEntryPoint = 0;    // Resolved address of BootEntry
    std::uintptr_t BootStubAddress = 0;     // Shellcode that called BootEntry

    // Set if the payload's BootEntry returned a non-zero status. Same
    // codes the payload defines internally.
    std::uint32_t PayloadReturnCode = 0;

    // For the curious: how long each phase took, in microseconds. Helps
    // when chasing "why does injection take 2 seconds" performance bugs.
    std::uint32_t TimingsUs[8] = {};
    enum TimingPhase {
        TimingValidate = 0,
        TimingAllocate,
        TimingCopySections,
        TimingRelocations,
        TimingImports,
        TimingTls,
        TimingProtections,
        TimingBootEntry,
    };
};

// The mapper itself. Stateless across calls - safe to construct fresh
// per-injection. Holds the target process handle and options for the
// duration of one Map() invocation.
class ManualMapper {
public:
    // Constructs a mapper bound to a specific target process. The handle
    // must have at minimum:
    //   PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
    //   PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD
    //
    // The mapper does NOT take ownership of the handle - caller closes it.
    ManualMapper(HANDLE targetProcess, const MapOptions& options);
    ~ManualMapper();

    ManualMapper(const ManualMapper&) = delete;
    ManualMapper& operator=(const ManualMapper&) = delete;

    // Map the given payload bytes into the target. The span must point
    // to a complete in-memory copy of the DLL (i.e., the file content,
    // not a memory-mapped view). The mapper will read it many times
    // during the process and may NOT modify it.
    MapResult Map(std::span<const std::uint8_t> payload);

private:
    // Pipeline stages - each one returns true on success, fills the
    // result on failure. Broken out so we can step through in tests.
    bool ValidateImage(std::span<const std::uint8_t> payload, MapResult& r);
    bool AllocateImage(MapResult& r);
    bool CopySections(std::span<const std::uint8_t> payload, MapResult& r);
    bool ApplyRelocations(std::span<const std::uint8_t> payload, MapResult& r);
    bool ResolveImports(std::span<const std::uint8_t> payload, MapResult& r);
    bool InvokeTlsCallbacks(std::span<const std::uint8_t> payload, MapResult& r);
    bool ApplyProtections(std::span<const std::uint8_t> payload, MapResult& r);
    bool ResolveBootEntry(std::span<const std::uint8_t> payload, MapResult& r);
    bool BuildAndWriteBootInfo(MapResult& r);
    bool LaunchBootEntry(MapResult& r);
    bool PostBootCleanup(MapResult& r);

    // Helpers wrapping NtWriteVirtualMemory etc., centralizing error
    // logging and partial-write handling.
    bool RemoteWrite(std::uintptr_t target, const void* source, std::size_t size);
    bool RemoteRead(std::uintptr_t source, void* dest, std::size_t size);
    bool RemoteProtect(std::uintptr_t target, std::size_t size, DWORD newProtect, DWORD* oldProtect);

    // Look up an export in a module that's already loaded in the target.
    // Used both for resolving the payload's BootEntry (via our own image
    // base) and for resolving imports that reference common DLLs.
    std::uintptr_t ResolveRemoteExport(std::uintptr_t moduleBase, const char* exportName);

    // Ensure a module is loaded in the target. If not present, calls
    // LoadLibraryA via CreateRemoteThread. Returns the remote module
    // base or 0 on failure.
    std::uintptr_t EnsureModuleLoaded(const char* moduleName);

    // Free any remote allocations recorded in `r` (image, BootInfo, boot
    // stub) and zero the corresponding fields. Called from Map() when a
    // pipeline phase fails so the target process doesn't accumulate
    // orphaned VirtualAlloc'd regions across failed inject attempts.
    void RollbackPartialMapping(MapResult& r);

private:
    HANDLE m_Process;
    MapOptions m_Options;

    // Cache: module name -> remote base. Populated lazily by
    // EnsureModuleLoaded so we don't re-snapshot for every imported DLL.
    struct LoadedModule {
        std::string Name;       // ASCII, lower-case for case-insensitive lookup
        std::uintptr_t Base;
        std::size_t Size;
    };
    std::vector<LoadedModule> m_ModuleCache;

    // Refresh m_ModuleCache from the target process. Called on first
    // import resolution and after any LoadLibraryA injection.
    bool RefreshModuleCache();
};

} // namespace ENI::Injector
