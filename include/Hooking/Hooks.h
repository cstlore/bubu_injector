#pragma once

#include "../pch.h"

namespace Hooking {

// Additional hook definitions that may be needed
struct HookDefinitions {
    // Memory protection hooks
    using VirtualProtectFn = BOOL(*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    using VirtualAllocFn = LPVOID(*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);

    // Process manipulation
    using CreateRemoteThreadFn = HANDLE(*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using OpenProcessFn = HANDLE(*)(DWORD, BOOL, DWORD);

    // PEB manipulation for integrity bypass
    struct PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PVOID AtlThunkSListPtr;
        PVOID Reserved4;
        DWORD Reserved5;
        DWORD Reserved6;
        PVOID Reserved7;
        PVOID Reserved8;
        DWORD Reserved9;
        DWORD Reserved10;
        DWORD SessionId;
    };

    // Hardware breakpoint manipulation
    struct CONTEXT {
        DWORD64 Rax;
        DWORD64 Rcx;
        DWORD64 Rdx;
        DWORD64 Rbx;
        DWORD64 Rsp;
        DWORD64 Rbp;
        DWORD64 Rsi;
        DWORD64 Rdi;
        DWORD64 R8;
        DWORD64 R9;
        DWORD64 R10;
        DWORD64 R11;
        DWORD64 R12;
        DWORD64 R13;
        DWORD64 R14;
        DWORD64 R15;
        DWORD64 Rip;
        DWORD64 EFlags;
        DWORD64 Dr0;
        DWORD64 Dr1;
        DWORD64 Dr2;
        DWORD64 Dr3;
        DWORD64 Dr6;
        DWORD64 Dr7;
        FLOATING_SAVE_AREA FloatSave;
    };

    // Debug registers
    enum class DebugRegister {
        Dr0 = 0,
        Dr1 = 1,
        Dr2 = 2,
        Dr3 = 3,
        Dr6 = 6,
        Dr7 = 7
    };

    // Integrity bypass functions
    void HideFromDebugger();
    void ClearDebugRegisters();
    void PatchHardwareBreakpoints();
    void PatchIntegrityChecks();

    // Thread context manipulation
    bool SetThreadDebugRegister(HANDLE hThread, DebugRegister reg, uptr value);
    uptr GetThreadDebugRegister(HANDLE hThread, DebugRegister reg);
    void ClearThreadDebugRegisters(HANDLE hThread);
}

// Inline implementations for common hooks
namespace InlineHooks {
    // Trampoline storage for inline hooks
    template<typename T>
    struct Trampoline {
        T Function = nullptr;
        byte OriginalBytes[64]{};
        usize OriginalSize = 0;
        bool IsHooked = false;
    };

    // Install inline hook with trampoline
    template<typename T>
    bool InstallInlineHook(uptr target, uptr detour, Trampoline<T>& tramp) {
        // Read original bytes
        if (!ReadProcessMemory(Core::Globals().Handle,
            reinterpret_cast<LPCVOID>(target), tramp.OriginalBytes, 64, nullptr)) {
            return false;
        }

        // Find instruction length (simplified)
        tramp.OriginalSize = 14; // Typical jmp rel32
        tramp.Function = reinterpret_cast<T>(target);

        // Make target region executable
        Memory::MemoryManager::Get().Protect(target, tramp.OriginalSize,
            Memory::Protection::ReadWriteExecute);

        // Write jump to detour
        byte jmp[] = {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // address
        };
        *reinterpret_cast<uptr*>(&jmp[6]) = detour;

        WriteProcessMemory(Core::Globals().Handle,
            reinterpret_cast<LPVOID>(target), jmp, sizeof(jmp), nullptr);

        tramp.IsHooked = true;
        return true;
    }

    // Remove inline hook and restore original
    template<typename T>
    void RemoveInlineHook(Trampoline<T>& tramp) {
        if (!tramp.IsHooked) return;

        WriteProcessMemory(Core::Globals().Handle,
            reinterpret_cast<LPVOID>(reinterpret_cast<uptr>(tramp.Function)),
            tramp.OriginalBytes, tramp.OriginalSize, nullptr);

        tramp.IsHooked = false;
    }
}

} // namespace Hooking