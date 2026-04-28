#include "pch.h"
#include "Hooking/HookManager.h"
#include "Core/Globals.h"
#include "Memory/MemoryManager.h"
#include "Memory/PatternScanner.h"

namespace Hooking {

HookManager& HookManager::Get() {
    static HookManager instance{};
    return instance;
}

bool HookManager::Initialize() {
    if (m_Initialized) return true;

    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        LOG_ERROR("MinHook initialization failed: %d", status);
        return false;
    }

    m_Initialized = true;
    LOG_INFO("Hook manager initialized");
    return true;
}

void HookManager::Shutdown() {
    if (!m_Initialized) return;

    DisableAllHooks();
    RemoveAllHooks();
    MH_Uninitialize();
    m_Initialized = false;
}

HookStatus HookManager::CreateHook(const char* name, void* target, void* detour, void** original) {
    if (!m_Initialized) {
        return HookStatus::Unknown;
    }

    MH_STATUS status = MH_CreateHook(target, detour, original);
    if (status != MH_OK) {
        LOG_ERROR("Failed to create hook '%s': %d", name, status);
        return static_cast<HookStatus>(status);
    }

    HookInfo info{};
    info.Target = target;
    info.Detour = detour;
    info.Original = original;
    info.Name = name;
    info.IsActive = false;

    m_Hooks[name] = info;
    LOG_DEBUG("Created hook '%s' at 0x%llX", name, reinterpret_cast<uptr>(target));

    return HookStatus::Success;
}

HookStatus HookManager::CreateHook(uptr target, uptr detour, uptr* original, const char* name) {
    char nameBuf[64] = {};
    if (name) {
        strncpy(nameBuf, name, sizeof(nameBuf) - 1);
    } else {
        snprintf(nameBuf, sizeof(nameBuf), "Hook_0x%llX", target);
    }
    return CreateHook(nameBuf, reinterpret_cast<void*>(target), reinterpret_cast<void*>(detour),
        reinterpret_cast<void**>(original));
}

HookStatus HookManager::EnableHook(const char* name) {
    if (!m_Initialized) return HookStatus::Unknown;

    auto it = m_Hooks.find(name);
    if (it == m_Hooks.end()) {
        return HookStatus::NotFound;
    }

    if (it->second.IsActive) {
        return HookStatus::Success;
    }

    MH_STATUS status = MH_EnableHook(it->second.Target);
    if (status != MH_OK) {
        LOG_ERROR("Failed to enable hook '%s': %d", name, status);
        return static_cast<HookStatus>(status);
    }

    it->second.IsActive = true;
    LOG_DEBUG("Enabled hook '%s'", name);

    return HookStatus::Success;
}

HookStatus HookManager::DisableHook(const char* name) {
    if (!m_Initialized) return HookStatus::Unknown;

    auto it = m_Hooks.find(name);
    if (it == m_Hooks.end()) {
        return HookStatus::NotFound;
    }

    if (!it->second.IsActive) {
        return HookStatus::Success;
    }

    MH_STATUS status = MH_DisableHook(it->second.Target);
    if (status != MH_OK) {
        LOG_ERROR("Failed to disable hook '%s': %d", name, status);
        return static_cast<HookStatus>(status);
    }

    it->second.IsActive = false;
    LOG_DEBUG("Disabled hook '%s'", name);

    return HookStatus::Success;
}

HookStatus HookManager::EnableAllHooks() {
    if (!m_Initialized) return HookStatus::Unknown;

    MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        LOG_ERROR("Failed to enable all hooks: %d", status);
        return static_cast<HookStatus>(status);
    }

    for (auto& [name, info] : m_Hooks) {
        info.IsActive = true;
    }

    return HookStatus::Success;
}

HookStatus HookManager::DisableAllHooks() {
    if (!m_Initialized) return HookStatus::Unknown;

    MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
    if (status != MH_OK) {
        LOG_ERROR("Failed to disable all hooks: %d", status);
        return static_cast<HookStatus>(status);
    }

    for (auto& [name, info] : m_Hooks) {
        info.IsActive = false;
    }

    return HookStatus::Success;
}

bool HookManager::IsHooked(const char* name) const {
    return m_Hooks.find(name) != m_Hooks.end();
}

bool HookManager::IsHookActive(const char* name) const {
    if (auto it = m_Hooks.find(name); it != m_Hooks.end()) {
        return it->second.IsActive;
    }
    return false;
}

void* HookManager::GetOriginal(const char* name) const {
    if (auto it = m_Hooks.find(name); it != m_Hooks.end()) {
        return *it->second.Original;
    }
    return nullptr;
}

uptr HookManager::GetOriginalAddress(const char* name) const {
    return reinterpret_cast<uptr>(GetOriginal(name));
}

void HookManager::RemoveHook(const char* name) {
    auto it = m_Hooks.find(name);
    if (it == m_Hooks.end()) return;

    if (it->second.IsActive) {
        MH_DisableHook(it->second.Target);
    }
    MH_RemoveHook(it->second.Target);
    m_Hooks.erase(it);

    LOG_DEBUG("Removed hook '%s'", name);
}

void HookManager::RemoveAllHooks() {
    for (auto& [name, info] : m_Hooks) {
        if (info.IsActive) {
            MH_DisableHook(info.Target);
        }
        MH_RemoveHook(info.Target);
    }
    m_Hooks.clear();
}

// Roblox hook implementations
namespace RobloxHooks {

    // Identity storage for current context
    static thread_local int g_CurrentIdentity = 7;
    static thread_local int g_OldIdentity = 7;

    int SetIdentity_hook(int identity) {
        g_OldIdentity = g_CurrentIdentity;
        g_CurrentIdentity = identity;
        LOG_DEBUG("Identity changed from %d to %d", g_OldIdentity, identity);
        return identity;
    }

    int GetIdentity_hook() {
        return g_CurrentIdentity;
    }

    void FireClick_hook(uptr button, uptr hit, uptr pos) {
        // Bypass click detection
        if (auto original = HookManager::Get().GetOriginalAddress("FireClick")) {
            auto fn = reinterpret_cast<FireClickFn>(original);
            fn(button, hit, pos);
        }
    }

    void FireInputBegan_hook(uptr inputObject) {
        if (auto original = HookManager::Get().GetOriginalAddress("FireInputBegan")) {
            auto fn = reinterpret_cast<FireInputFn>(original);
            fn(inputObject);
        }
    }

    void FireInputEnded_hook(uptr inputObject) {
        if (auto original = HookManager::Get().GetOriginalAddress("FireInputEnded")) {
            auto fn = reinterpret_cast<FireInputFn>(original);
            fn(inputObject);
        }
    }

    uptr GetRawMetaTable_hook(uptr obj) {
        // Return metatable without rbxscriptsign check
        if (obj) {
            uptr metatable = Memory::MemoryManager::Read<uptr>(obj - 0x10);
            if (metatable) {
                return metatable;
            }
        }
        return 0;
    }

    bool SetRawMetaTable_hook(uptr obj, uptr metatable) {
        // Set metatable without rbxscriptsign check
        if (obj && metatable) {
            Memory::MemoryManager::Write<uptr>(obj - 0x10, metatable);
            return true;
        }
        return false;
    }

    uptr GetCallingScript_hook() {
        // Return calling script context
        if (auto original = HookManager::Get().GetOriginalAddress("GetCallingScript")) {
            auto fn = reinterpret_cast<GetCallingScriptFn>(original);
            return fn();
        }
        return 0;
    }

    bool CanTeleport_hook() {
        // Allow teleport bypass
        return true;
    }

    void ForceTeleport_hook(uptr service, uptr args) {
        // Direct teleport implementation
    }

    void Print_hook(const char* msg) {
        // Capture print output
        Executor::ScriptEngine::Get().Print(msg);

        // Call original
        if (auto original = HookManager::Get().GetOriginalAddress("Print")) {
            auto fn = reinterpret_cast<PrintFn>(original);
            fn(msg);
        }
    }
}

bool InitializeRobloxHooks() {
    auto& hm = HookManager::Get();
    if (!hm.Initialize()) {
        return false;
    }

    auto hProcess = Core::Globals().Handle;
    if (!hProcess) {
        LOG_ERROR("Process not attached");
        return false;
    }

    Memory::RemoteScanner scanner(hProcess);

    // Find and hook setidentity
    auto result = scanner.Scan(Memory::Signatures::GetFEnv.pattern);
    if (result) {
        hm.CreateHook("SetIdentity", reinterpret_cast<void*>(result.address),
            reinterpret_cast<void*>(RobloxHooks::SetIdentity_hook), nullptr);
        hm.EnableHook("SetIdentity");
        LOG_INFO("Hooked SetIdentity at 0x%llX", result.address);
    }

    // Find and hook getidentity
    result = scanner.Scan(Memory::Signatures::GetFEnv.pattern);
    if (result) {
        hm.CreateHook("GetIdentity", reinterpret_cast<void*>(result.address + 0x50),
            reinterpret_cast<void*>(RobloxHooks::GetIdentity_hook), nullptr);
        hm.EnableHook("GetIdentity");
        LOG_INFO("Hooked GetIdentity at 0x%llX", result.address + 0x50);
    }

    // Find and hook fireclick
    result = scanner.Scan(Memory::Signatures::FireClick.pattern);
    if (result) {
        hm.CreateHook("FireClick", reinterpret_cast<void*>(result.address),
            reinterpret_cast<void*>(RobloxHooks::FireClick_hook), nullptr);
        hm.EnableHook("FireClick");
        LOG_INFO("Hooked FireClick at 0x%llX", result.address);
    }

    // Find and hook getrawmetatable
    result = scanner.Scan(Memory::Signatures::GetRawMetaTable.pattern);
    if (result) {
        hm.CreateHook("GetRawMetaTable", reinterpret_cast<void*>(result.address),
            reinterpret_cast<void*>(RobloxHooks::GetRawMetaTable_hook), nullptr);
        hm.EnableHook("GetRawMetaTable");
        LOG_INFO("Hooked GetRawMetaTable at 0x%llX", result.address);
    }

    // Find and hook setrawmetatable
    result = scanner.Scan("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B F9 48 85 DB");
    if (result) {
        hm.CreateHook("SetRawMetaTable", reinterpret_cast<void*>(result.address),
            reinterpret_cast<void*>(RobloxHooks::SetRawMetaTable_hook), nullptr);
        hm.EnableHook("SetRawMetaTable");
        LOG_INFO("Hooked SetRawMetaTable at 0x%llX", result.address);
    }

    // Find and hook getcallingscript
    result = scanner.Scan(Memory::Signatures::GetCallingScript.pattern);
    if (result) {
        hm.CreateHook("GetCallingScript", reinterpret_cast<void*>(result.address),
            reinterpret_cast<void*>(RobloxHooks::GetCallingScript_hook), nullptr);
        hm.EnableHook("GetCallingScript");
        LOG_INFO("Hooked GetCallingScript at 0x%llX", result.address);
    }

    // Find and hook print
    result = scanner.Scan("48 83 EC 28 48 8B 4C 24 30 48 8B 54 24 38");
    if (result) {
        hm.CreateHook("Print", reinterpret_cast<void*>(result.address),
            reinterpret_cast<void*>(RobloxHooks::Print_hook), nullptr);
        hm.EnableHook("Print");
        LOG_INFO("Hooked Print at 0x%llX", result.address);
    }

    return true;
}

} // namespace Hooking