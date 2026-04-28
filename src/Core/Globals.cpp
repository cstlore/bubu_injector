#include "pch.h"
#include "Core/Globals.h"
#include "Memory/MemoryManager.h"

namespace Core {

// Static storage for global state
static RobloxInfo g_RobloxInfo{};
static bool g_Initialized = false;

RobloxInfo& Globals() {
    return g_RobloxInfo;
}

void InitializeGlobals(HANDLE hProcess, DWORD pid) {
    g_RobloxInfo = RobloxInfo{
        .PID = pid,
        .Handle = hProcess,
        .BaseAddress = Memory::MemoryManager::GetBaseAddress(hProcess),
        .ImageSize = Memory::MemoryManager::GetImageSize(hProcess),
        .Is64Bit = Memory::MemoryManager::IsProcess64Bit(hProcess)
    };
    g_Initialized = true;
}

bool IsRobloxRunning() {
    constexpr const char* processName = "RobloxPlayerBeta.exe";
    return FindWindowA(nullptr, processName) != nullptr;
}

bool AttachToRoblox() {
    constexpr const char* processName = "RobloxPlayerBeta.exe";

    // Find existing process
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);
    for (BOOL ok = Process32FirstW(hSnap, &pe); ok; ok = Process32NextW(hSnap, &pe)) {
        if (wcscmp(pe.szExeFile, L"RobloxPlayerBeta.exe") == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(hSnap);

    if (pid == 0) {
        LOG_ERROR("RobloxPlayerBeta.exe not found");
        return false;
    }

    // Open process with all access rights
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
        PROCESS_SUSPEND_RESUME,
        FALSE, pid
    );

    if (!hProcess) {
        LOG_ERROR("Failed to open Roblox process: %lu", GetLastError());
        return false;
    }

    InitializeGlobals(hProcess, pid);
    LOG_INFO("Attached to Roblox (PID: %lu, Base: 0x%llX)", pid, g_RobloxInfo.BaseAddress);
    return true;
}

HANDLE GetProcessHandle() {
    return g_RobloxInfo.Handle;
}

} // namespace Core