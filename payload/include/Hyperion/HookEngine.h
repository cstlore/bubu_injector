#pragma once

// =============================================================================
// Hyperion::HookEngine - small wrapper around MinHook
// =============================================================================
//
// We use MinHook's bare API (MH_Initialize / MH_CreateHook / MH_EnableHook)
// rather than the legacy `src/Hooking/HookManager` singleton because:
//   * The legacy class depends on Core::Globals, which is part of the
//     out-of-process attach codebase we're NOT porting yet.
//   * The legacy singleton uses std::unordered_map keyed on string,
//     which means heap allocations on the boot path. We want zero
//     allocations during arming.
//   * We want trampolines stored alongside the rest of the hook record
//     so we can iterate them for diagnostics.
//
// Capacity is fixed (16 entries). v1 only installs 6-7 hooks; if a future
// pass needs more we bump kMaxHooks.
//
// All hooks are installed during the boot window. Once Roblox resumes,
// new hook installation is unsafe (MinHook's VirtualAlloc trampolines
// might get routed through Hyperion's own VirtualAlloc detour). If we
// ever need runtime hook installation, we'll use cached syscall stubs.
// =============================================================================

#include <cstddef>

namespace ENI::Hyperion::HookEngine {

constexpr std::size_t kMaxHooks = 16;

// Initialize MinHook. Must be called once before any Install. Returns
// true on success.
bool Initialize();

// Tear down all hooks and uninitialize MinHook. Idempotent.
void Shutdown();

// Install a hook. `target` is the function to detour, `detour` is our
// replacement, `outTrampoline` receives the pointer to call to invoke
// the original. `name` is logged on success/failure. Returns true on
// successful install + enable.
bool Install(void* target, void* detour, void** outTrampoline, const char* name);

// Number of currently-installed hooks.
std::size_t Count();

} // namespace ENI::Hyperion::HookEngine
