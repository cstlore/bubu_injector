#pragma once

// =============================================================================
// Hyperion::Sentry - boot-time arming sequence
// =============================================================================
//
// Single entry point: Arm(). Called once from ENIBootEntry after logging
// is up. Composes the rest of the subsystems:
//
//   1. NtApi::FindNtdllBase + NtApi::CacheAll
//   2. HookEngine::Initialize
//   3. PayloadRegion::Add for our own image + BootInfo blob
//   4. Install detours on cached NT exports
//   5. Anti-debug: PEB->BeingDebugged = 0, NtGlobalFlag clean, DRs zeroed
//   6. LdrRegisterDllNotification with our load watcher
//
// Every step is best-effort: a failure logs and the rest still tries.
// Arm() returns the number of steps that fully succeeded, mostly for
// diagnostic visibility - the only fatal failure is "no ntdll", which
// returns 0 and signals the caller to bail.
// =============================================================================

#include <cstddef>
#include <cstddef>
#include <cstdint>

namespace ENI::Hyperion::Sentry {

struct ArmResult {
    bool          NtdllFound        = false;
    bool          MinHookReady      = false;
    bool          DllNotifyHooked   = false;
    std::uint32_t StubsCached       = 0;
    std::uint32_t HooksInstalled    = 0;
    std::uint32_t RegionsRegistered = 0;
};

ArmResult Arm(std::uintptr_t imageBase, std::size_t imageSize,
              std::uintptr_t bootInfoBase, std::size_t bootInfoSize);

void Disarm();

} // namespace ENI::Hyperion::Sentry
