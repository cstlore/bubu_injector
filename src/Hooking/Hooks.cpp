#include "pch.h"
#include "Hooking/Hooks.h"
#include "Core/Globals.h"
#include "Memory/MemoryManager.h"

namespace Hooking {

void HookDefinitions::HideFromDebugger() {
    // PEB->BeingDebugged = 0
    PEB* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
    if (peb) {
        peb->BeingDebugged = 0;
        LOG_DEBUG("PEB->BeingDebugged patched");
    }

    // Also patch NtQueryInformationProcess with ProcessDebugPort
    // This is handled through system call hooking if needed
}

void HookDefinitions::ClearDebugRegisters() {
    HANDLE hThread = GetCurrentThread();

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0x400; // Disable all breakpoints

    SetThreadContext(hThread, &ctx);
    LOG_DEBUG("Debug registers cleared");
}

void HookDefinitions::PatchHardwareBreakpoints() {
    // Clear DR registers on current thread
    ClearDebugRegisters();

    // Patch the API that sets hardware breakpoints
    // Pattern scan for SetThreadContext and hook
}

void HookDefinitions::PatchIntegrityChecks() {
    // Find and patch common integrity check patterns
    auto& scanner = Memory::RemoteScanner{Core::Globals().Handle};

    // Patch IsDebuggerPresent
    auto result = scanner.Scan("E8 ?? ?? ?? ?? 84 C0 74 ?? B8 ?? ?? ?? ?? C3");
    if (result) {
        // NOP out theje rel32 call and make function return 0
        byte patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret
        MemoryManager::Get().Protect(result.address, 3, Memory::Protection::ReadWriteExecute);
        MemoryManager::WriteArray(result.address, patch, 3);
        LOG_DEBUG("Patched IsDebuggerPresent at 0x%llX", result.address);
    }

    // Patch CheckRemoteDebuggerPresent
    result = scanner.Scan("48 8B 4C 24 ?? 48 89 4C 24 ?? E8 ?? ?? ?? ?? 84 C0");
    if (result) {
        byte patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret
        MemoryManager::Get().Protect(result.address, 3, Memory::Protection::ReadWriteExecute);
        MemoryManager::WriteArray(result.address, patch, 3);
        LOG_DEBUG("Patched CheckRemoteDebuggerPresent at 0x%llX", result.address);
    }

    // Patch NtQueryInformationProcess (ProcessDebugPort check)
    result = scanner.Scan("48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30 48 8B F9 48 85 DB 74");
    if (result) {
        byte patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret
        MemoryManager::Get().Protect(result.address, 3, Memory::Protection::ReadWriteExecute);
        MemoryManager::WriteArray(result.address, patch, 3);
        LOG_DEBUG("Patched NtQueryInformationProcess at 0x%llX", result.address);
    }
}

bool HookDefinitions::SetThreadDebugRegister(HANDLE hThread, DebugRegister reg, uptr value) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    switch (reg) {
        case DebugRegister::Dr0: ctx.Dr0 = value; break;
        case DebugRegister::Dr1: ctx.Dr1 = value; break;
        case DebugRegister::Dr2: ctx.Dr2 = value; break;
        case DebugRegister::Dr3: ctx.Dr3 = value; break;
        case DebugRegister::Dr6: ctx.Dr6 = value; break;
        case DebugRegister::Dr7: ctx.Dr7 = value; break;
    }

    return SetThreadContext(hThread, &ctx) != 0;
}

uptr HookDefinitions::GetThreadDebugRegister(HANDLE hThread, DebugRegister reg) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    switch (reg) {
        case DebugRegister::Dr0: return ctx.Dr0;
        case DebugRegister::Dr1: return ctx.Dr1;
        case DebugRegister::Dr2: return ctx.Dr2;
        case DebugRegister::Dr3: return ctx.Dr3;
        case DebugRegister::Dr6: return ctx.Dr6;
        case DebugRegister::Dr7: return ctx.Dr7;
    }
    return 0;
}

void HookDefinitions::ClearThreadDebugRegisters(HANDLE hThread) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    ctx.Dr0 = 0;
    ctx.Dr1 = 0;
    ctx.Dr2 = 0;
    ctx.Dr3 = 0;
    ctx.Dr6 = 0;
    ctx.Dr7 = 0x400; // Disable all

    SetThreadContext(hThread, &ctx);
}

} // namespace Hooking