#pragma once

// =============================================================================
// ShimMapper.h - tiny manual-mapper specialized for ENILauncherShim
// =============================================================================
//
// The injector's ManualMapper is hard-wired to call ENIBootEntry(BootInfo*).
// The shim has a *different* contract - ENIShimEntry(ShimEnvelope*) - so
// instead of generalizing ManualMapper (which would force its public API to
// abstract over export name + payload struct), we keep a minimal, dedicated
// mapper here in the launcher.
//
// What this mapper does:
//   1. Validates the shim DLL bytes (PE / x64 / DLL).
//   2. Allocates SizeOfImage in the target launcher process via VirtualAllocEx.
//   3. Copies headers + sections.
//   4. Walks .reloc, applies DIR64 relocations using (allocBase - PreferredBase).
//   5. Resolves IAT (kernel32 / ntdll only - the shim doesn't import anything
//      else, by design).
//   6. Applies per-section page protections.
//   7. Writes a ShimEnvelope into a separate RW page in the target.
//   8. Writes a boot stub that calls ENIShimEntry(envelope).
//   9. CreateRemoteThread on the boot stub. Wait for completion.
//
// Compared to ManualMapper this is simpler in three ways:
//   - We control the shim's own imports - we know they're tiny and stable.
//   - We don't run TLS callbacks (the shim has none; we'd assert during build
//     if anyone added any).
//   - We don't erase headers / unlink from PEB - the shim is short-lived in
//     the launcher and the launcher itself is short-lived too. Stealth at
//     this level isn't worth the complexity.
//
// =============================================================================

#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <windows.h>

#include "../../shared/ShimContract.h"

namespace ENI::Launcher {

// Granular result codes - mirror ManualMapper's style so we can log
// uniformly.
enum class ShimMapStatus : std::uint32_t {
    Ok = 0,

    InvalidPe,                  // No DOS / NT signature
    NotX64,                     // Not IMAGE_FILE_MACHINE_AMD64
    NotDll,                     // FileHeader Characteristics lacks DLL flag
    MissingShimEntryExport,     // No ENIShimEntry export

    AllocateImageFailed,        // VirtualAllocEx for SizeOfImage
    AllocateEnvelopeFailed,     // VirtualAllocEx for ShimEnvelope
    AllocateShellcodeFailed,    // VirtualAllocEx for boot stub

    SectionWriteFailed,         // WriteProcessMemory mid-section
    EnvelopeWriteFailed,
    ShellcodeWriteFailed,
    HeaderWriteFailed,

    RelocationOutOfRange,
    UnsupportedRelocationType,

    LoadLibraryRemoteFailed,
    GetProcAddressFailed,
    ImportResolutionFailed,

    ProtectionApplyFailed,
    BootThreadCreateFailed,
    ShimEntryReturnedError,     // ENIShimEntry returned non-zero
    BootTimeout,
};

inline const char* ShimMapStatusToString(ShimMapStatus s) {
    switch (s) {
        case ShimMapStatus::Ok:                       return "Ok";
        case ShimMapStatus::InvalidPe:                return "InvalidPe";
        case ShimMapStatus::NotX64:                   return "NotX64";
        case ShimMapStatus::NotDll:                   return "NotDll";
        case ShimMapStatus::MissingShimEntryExport:   return "MissingShimEntryExport";
        case ShimMapStatus::AllocateImageFailed:      return "AllocateImageFailed";
        case ShimMapStatus::AllocateEnvelopeFailed:   return "AllocateEnvelopeFailed";
        case ShimMapStatus::AllocateShellcodeFailed:  return "AllocateShellcodeFailed";
        case ShimMapStatus::SectionWriteFailed:       return "SectionWriteFailed";
        case ShimMapStatus::EnvelopeWriteFailed:      return "EnvelopeWriteFailed";
        case ShimMapStatus::ShellcodeWriteFailed:     return "ShellcodeWriteFailed";
        case ShimMapStatus::HeaderWriteFailed:        return "HeaderWriteFailed";
        case ShimMapStatus::RelocationOutOfRange:     return "RelocationOutOfRange";
        case ShimMapStatus::UnsupportedRelocationType:return "UnsupportedRelocationType";
        case ShimMapStatus::LoadLibraryRemoteFailed:  return "LoadLibraryRemoteFailed";
        case ShimMapStatus::GetProcAddressFailed:     return "GetProcAddressFailed";
        case ShimMapStatus::ImportResolutionFailed:   return "ImportResolutionFailed";
        case ShimMapStatus::ProtectionApplyFailed:    return "ProtectionApplyFailed";
        case ShimMapStatus::BootThreadCreateFailed:   return "BootThreadCreateFailed";
        case ShimMapStatus::ShimEntryReturnedError:   return "ShimEntryReturnedError";
        case ShimMapStatus::BootTimeout:              return "BootTimeout";
    }
    return "Unknown";
}

struct ShimMapResult {
    ShimMapStatus Status = ShimMapStatus::InvalidPe;

    std::uintptr_t RemoteImageBase = 0;
    std::uintptr_t RemoteEnvelope = 0;
    std::uintptr_t RemoteEntryPoint = 0;
    std::uintptr_t BootStubAddress = 0;

    // ENIShimEntry's return value (a ShimStatus enum value).
    std::uint32_t ShimReturnCode = 0;
};

// Map the shim DLL into `targetProcess`, then synchronously call
// ENIShimEntry with a copy of `envelope` placed in target memory.
//
// `targetProcess` must be a handle with at least:
//   PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
//   PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD
//
// Caller does not own the returned remote allocations - the shim runs in-
// process inside the launcher and lives as long as the launcher does.
ShimMapResult MapShimAndInvoke(
    HANDLE targetProcess,
    std::span<const std::uint8_t> shimBytes,
    const Shim::ShimEnvelope& envelope,
    std::uint32_t bootTimeoutMs = 30000);

} // namespace ENI::Launcher
