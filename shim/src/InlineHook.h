#pragma once

// =============================================================================
// InlineHook.h - tiny in-process inline hooker
// =============================================================================
//
// We hook a function in our own process by:
//   1. Reading the first 14 bytes of the target (the size of an absolute
//      "jmp [rip+0]; <8-byte addr>" sequence).
//   2. Allocating a small executable trampoline that:
//      a. Re-runs the original 14 bytes (after they've been clobbered).
//      b. Jumps back to target+14 to continue execution.
//   3. Overwriting the target's first 14 bytes with a jump to our detour.
//
// The detour, when called, looks identical to the original from the caller's
// perspective. To call the original from inside the detour, you call the
// trampoline.
//
// Caveats this implementation accepts:
//   * 14 bytes is conservative. If the prologue contains a jcc / call /
//     mov-rip-relative within the first 14 bytes, the trampoline will
//     execute relocated code that points at the wrong target. In practice
//     CreateProcessW's prologue on Win10/11 starts with the standard
//     "mov [rsp+8], rbx; ..." sequence which is safe to relocate. We will
//     verify at install time and fail-fast if we see a problematic byte.
//   * No instruction-length disassembly. We assume "first 14 bytes" is
//     a clean break. For our targets it is. A general-purpose hooker
//     (like MinHook) does instruction-aware splitting; we don't need that
//     since we hook a known set of API entries.
//   * Thread safety during installation: we don't suspend other threads
//     before patching. Our shim runs from DllMain (or the boot stub
//     equivalent) which fires before the launcher has spawned its worker
//     threads, so concurrent execution at the patch site is unlikely.
//     If this becomes a problem we'll add a SuspendThread sweep.
//
// Why not MinHook? The shim wants to be self-contained, ~30KB binary, no
// dependencies. MinHook is well-engineered but adds 80KB and another
// build target. Our hook surface is exactly two functions.
// =============================================================================

#include <cstdint>
#include <cstring>
#include <windows.h>

namespace ENI::Shim {

// One installed hook's bookkeeping. Stored by the caller; freed via Uninstall.
struct InlineHook {
    void* Target = nullptr;             // The function we patched (e.g. CreateProcessW)
    void* Detour = nullptr;             // Our replacement function
    void* Trampoline = nullptr;         // Allocated stub that calls the original
    std::uint8_t OriginalBytes[14] = {};
    bool Installed = false;
};

// Install an inline hook. On success, fills `out` and returns true.
// `Trampoline` after install is the function pointer you call to invoke
// the original (cast it to the same signature as the target).
inline bool InstallInlineHook(void* target, void* detour, InlineHook& out) {
    if (!target || !detour) return false;
    if (out.Installed) return false;

    // Save the first 14 bytes - we'll restore these on uninstall, and
    // the trampoline will re-execute them.
    std::memcpy(out.OriginalBytes, target, sizeof(out.OriginalBytes));

    // Sanity check: refuse to hook if the prologue contains anything that
    // looks like a relative-displacement instruction. This is a coarse
    // filter - it catches the common dangerous opcodes (call rel32 = E8,
    // jmp rel32 = E9, jcc rel32 = 0F 8x). Misses some obscure cases but
    // protects against the loud failures.
    for (int i = 0; i < 14; i++) {
        const std::uint8_t b = out.OriginalBytes[i];
        if (b == 0xE8 || b == 0xE9) {
            // Relative call/jmp - relocating it would break the target.
            // Bail - the caller can pick a different hook strategy.
            return false;
        }
        if (b == 0x0F && i + 1 < 14) {
            const std::uint8_t b2 = out.OriginalBytes[i + 1];
            if (b2 >= 0x80 && b2 <= 0x8F) {
                return false; // jcc rel32
            }
        }
    }

    // Allocate a 32-byte trampoline: 14 bytes original + 14 bytes return
    // jmp + 4 bytes padding. Mark RX after writing.
    void* trampoline = VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!trampoline) return false;

    // Compose the trampoline: copy of original prologue, then absolute
    // jump back to target+14.
    std::uint8_t* tp = reinterpret_cast<std::uint8_t*>(trampoline);
    std::memcpy(tp, out.OriginalBytes, 14);

    // jmp [rip+0]; <addr>
    tp[14] = 0xFF;
    tp[15] = 0x25;
    tp[16] = 0x00; tp[17] = 0x00; tp[18] = 0x00; tp[19] = 0x00;
    const std::uintptr_t returnAddr = reinterpret_cast<std::uintptr_t>(target) + 14;
    std::memcpy(tp + 20, &returnAddr, sizeof(returnAddr));

    DWORD oldProt = 0;
    if (!VirtualProtect(trampoline, 32, PAGE_EXECUTE_READ, &oldProt)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }

    // Patch the target. Same 14-byte absolute jmp pattern.
    std::uint8_t patch[14];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00; patch[3] = 0x00; patch[4] = 0x00; patch[5] = 0x00;
    const std::uintptr_t detourAddr = reinterpret_cast<std::uintptr_t>(detour);
    std::memcpy(patch + 6, &detourAddr, sizeof(detourAddr));

    DWORD oldTargetProt = 0;
    if (!VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &oldTargetProt)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }

    std::memcpy(target, patch, 14);

    // Restore the original protection. Some functions are mapped from
    // a pageable region we shouldn't leave RWX.
    VirtualProtect(target, 14, oldTargetProt, &oldTargetProt);
    FlushInstructionCache(GetCurrentProcess(), target, 14);

    out.Target = target;
    out.Detour = detour;
    out.Trampoline = trampoline;
    out.Installed = true;
    return true;
}

inline bool UninstallInlineHook(InlineHook& h) {
    if (!h.Installed) return false;

    DWORD oldProt = 0;
    if (!VirtualProtect(h.Target, 14, PAGE_EXECUTE_READWRITE, &oldProt)) return false;
    std::memcpy(h.Target, h.OriginalBytes, 14);
    VirtualProtect(h.Target, 14, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), h.Target, 14);

    if (h.Trampoline) {
        VirtualFree(h.Trampoline, 0, MEM_RELEASE);
    }
    h.Installed = false;
    return true;
}

} // namespace ENI::Shim
