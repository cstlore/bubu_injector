#pragma once

#include "../pch.h"

namespace Core {

// Global Roblox process information
struct RobloxInfo {
    DWORD PID = 0;
    HANDLE Handle = nullptr;
    uptr BaseAddress = 0;
    usize ImageSize = 0;
    bool Is64Bit = true;

    // Lua state pointer (multiplied by 8 due to bytecode encoding)
    uptr LuaState = 0;

    // DataModel and Workspace pointers
    uptr DataModel = 0;
    uptr Workspace = 0;
    uptr Players = 0;
    uptr Lighting = 0;

    // Service pointers
    uptr ScriptService = 0;
    uptr TeleportService = 0;
    uptr HttpService = 0;
};

// Global singleton accessor
RobloxInfo& Globals();

// Initialize globals with process handle
void InitializeGlobals(HANDLE hProcess, DWORD pid);

// Check if Roblox is running
bool IsRobloxRunning();

// Find and attach to RobloxPlayerBeta.exe
bool AttachToRoblox();

// Get process handle
HANDLE GetProcessHandle();

} // namespace Core