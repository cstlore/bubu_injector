#pragma once

// =============================================================================
// ShimContract.h - Launcher → Shim → Payload contract
// =============================================================================
//
// The shim DLL lives briefly inside the legitimate RobloxPlayerLauncher.exe.
// Its job:
//   1. Hook CreateProcessW.
//   2. When the launcher spawns RobloxPlayerBeta.exe, intercept that call,
//      add CREATE_SUSPENDED to the flags, call the real CreateProcessW.
//   3. Manual-map the payload DLL into the suspended Roblox process using
//      the same mapper as ENILoader.
//   4. Resume the Roblox main thread.
//   5. Self-unload from the launcher.
//
// The launcher (ENILauncher.exe) hands the shim three things:
//   * The path of the payload DLL to inject into Roblox
//   * The boot options (paths, flags, pre-resolved addresses) to pass through
//     to the payload via BootInfo
//   * Control flags (verbose, keep-alive-after-inject, etc.)
//
// Like BootInfo, this struct is passed via shellcode invocation of the shim's
// exported entry function. Same versioning and magic-number rules apply.
//
// =============================================================================

#include <cstddef>
#include <cstddef>
#include <cstdint>

#include "BootInfo.h"

namespace ENI::Shim {

// Bumped on any binary-breaking change. Independent from BootInfo's version
// because the launcher↔shim and shim↔payload are separate contracts that
// can evolve at different rates.
constexpr std::uint32_t ProtocolVersion = 1;

// "ENIS" little-endian = 0x53494E45.
constexpr std::uint32_t Magic = 0x53494E45;

constexpr std::size_t MaxPathChars = ENI::Boot::MaxPathChars;

// Flags that change shim behavior. Most users want all defaults (zero).
namespace ShimFlags {
    constexpr std::uint32_t None             = 0;

    // Keep the shim DLL loaded in the launcher after injecting Roblox.
    // Useful when the launcher might spawn multiple Roblox processes
    // (which happens with multi-instance setups). Default OFF - normally
    // we self-unload after one successful inject to leave no trace.
    constexpr std::uint32_t StayResident     = 1u << 0;

    // Verbose - write diagnostic info to a log file (path in LogFile).
    // Off in production; on while debugging.
    constexpr std::uint32_t Verbose          = 1u << 1;

    // Don't actually inject the payload - just hook CreateProcessW and
    // let Roblox launch normally. For testing the hook chain in isolation.
    constexpr std::uint32_t DryRun           = 1u << 2;

    // The launcher already pre-resolved Roblox signatures and filled
    // BootOptions.Addresses. Shim should pass these through to the payload
    // verbatim instead of zeroing them. Default ON when the launcher does
    // its job; OFF if the launcher can't reach a Roblox image to scan.
    constexpr std::uint32_t HasPreResolved   = 1u << 3;
}

// What the launcher passes to the shim. Allocated in the shim's address
// space (the launcher process), filled by the launcher, then handed to
// the shim's entry function.
struct ShimEnvelope {
    // Header
    std::uint32_t Magic;            // == ENI::Shim::Magic
    std::uint32_t Version;          // == ENI::Shim::ProtocolVersion
    std::uint32_t StructSize;       // == sizeof(ShimEnvelope)
    std::uint32_t Flags;            // ShimFlags

    // Path on disk to the payload DLL we'll manual-map into Roblox.
    // The shim reads this file at hook time. Must remain readable until
    // Roblox is launched - i.e., until the user actually starts a game.
    // Wide chars for Unicode paths.
    wchar_t PayloadPath[MaxPathChars];

    // If Verbose is set, the shim appends to this log file. Created if
    // missing. Empty string disables.
    wchar_t LogFile[MaxPathChars];

    // The full boot-options blob to feed into ManualMapper for the Roblox
    // injection. This is the same struct ENILoader fills in main.cpp -
    // we hoist it into the contract so the launcher can prepare it once,
    // pass it across, and the shim doesn't need to reimplement defaults.
    //
    // We carry it as raw fields (not the MapOptions C++ struct) because
    // MapOptions has std::wstring which isn't POD and won't survive the
    // cross-process hand-off cleanly.
    std::uint32_t BootFlags;        // Boot::BootFlags bitmask
    std::uint32_t BootTimeoutMs;
    std::uint8_t  EraseHeaders;     // bool, sized for binary stability
    std::uint8_t  UnlinkFromPeb;
    std::uint8_t  UseRemoteThread;
    std::uint8_t  Reserved0;        // explicit padding

    wchar_t ConfigDir[MaxPathChars];
    wchar_t ScriptsDir[MaxPathChars];
    wchar_t LogsDir[MaxPathChars];

    // Pre-resolved Roblox addresses. Zeroed unless HasPreResolved is set
    // in Flags - in that case the launcher did the version detection pass
    // before spawning the launcher and filled this in.
    Boot::ResolvedAddresses Addresses;

    // Reserved for future fields.
    std::uint64_t Reserved[16];
};

static_assert(sizeof(ShimEnvelope) % 8 == 0, "ShimEnvelope alignment drift");
static_assert(offsetof(ShimEnvelope, Magic) == 0,
              "Magic must come first for sanity checks");

// The shim DLL exports this single function. The launcher's manual-mapper
// invokes it the same way ENILoader invokes ENIBootEntry on the payload.
//
// extern "C" __declspec(dllexport) std::uint32_t ENIShimEntry(const ShimEnvelope*);
//
// Return: 0 = installed hooks successfully, non-zero = error (codes match
// ShimStatus enum in shim's public header).
constexpr const char* ShimEntryExportName = "ENIShimEntry";

} // namespace ENI::Shim
