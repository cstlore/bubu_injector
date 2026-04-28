#pragma once

#include "../pch.h"
#include <MinHook.h>

namespace Hooking {

// Hook handle type
using HookHandle = MH_HANDLE;

// Hook status
enum class HookStatus {
    Success = MH_OK,
    NotFound = MH_ERROR_NOT_FOUND,
    AlreadyHooked = MH_ERROR_ALREADY_HOOKED,
    NotHooked = MH_ERROR_NOT_HOOKED,
    InvalidFunction = MH_ERROR_UNSUPPORTED_FUNCTION,
    MemoryAlloc = MH_ERROR_MEMORY_ALLOC,
    MemoryProtect = MH_ERROR_MEMORY_PROTECT,
    Unknown = MH_UNKNOWN
};

// Hook information
struct HookInfo {
    void* Target;
    void* Detour;
    void** Original;
    std::string Name;
    bool IsActive;
};

// Hook manager singleton using MinHook
class HookManager {
public:
    static HookManager& Get();

    // Initialization
    bool Initialize();
    void Shutdown();

    // Hook creation
    HookStatus CreateHook(const char* name, void* target, void* detour, void** original);
    HookStatus CreateHook(uptr target, uptr detour, uptr* original, const char* name = nullptr);

    // Hook control
    HookStatus EnableHook(const char* name);
    HookStatus DisableHook(const char* name);
    HookStatus EnableAllHooks();
    HookStatus DisableAllHooks();

    // Query
    bool IsHooked(const char* name) const;
    bool IsHookActive(const char* name) const;
    void* GetOriginal(const char* name) const;
    uptr GetOriginalAddress(const char* name) const;

    // Cleanup
    void RemoveHook(const char* name);
    void RemoveAllHooks();

    // Accessors
    const std::unordered_map<std::string, HookInfo>& GetHooks() const { return m_Hooks; }

private:
    HookManager() = default;
    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    std::unordered_map<std::string, HookInfo> m_Hooks;
    bool m_Initialized = false;
};

// RAII hook guard
class AutoHook {
public:
    template<typename T>
    AutoHook(const char* name, T target, T detour, T* original)
        : m_Name(name) {
        auto& hm = HookManager::Get();
        hm.CreateHook(name, reinterpret_cast<void*>(target), reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(original));
        hm.EnableHook(name);
    }

    ~AutoHook() {
        HookManager::Get().DisableHook(m_Name.c_str());
    }

private:
    std::string m_Name;
};

// Macro for easy hook creation
#define CREATE_HOOK(name, target, detour, original) \
    HookManager::Get().CreateHook(name, reinterpret_cast<void*>(target), \
        reinterpret_cast<void*>(detour), reinterpret_cast<void**>(original))

#define ENABLE_HOOK(name) HookManager::Get().EnableHook(name)
#define DISABLE_HOOK(name) HookManager::Get().DisableHook(name)

// Specific hook types for Roblox
namespace RobloxHooks {
    // Identity manipulation
    using SetIdentityFn = int(*)(int identity);
    using GetIdentityFn = int(*)();

    extern "C" {
        int SetIdentity_hook(int identity);
        int GetIdentity_hook();
    }

    // FireClick bypass
    using FireClickFn = void(*)(uptr button, uptr hit, uptr pos);
    extern "C" void FireClick_hook(uptr button, uptr hit, uptr pos);

    // Input bypass
    using FireInputFn = void(*)(uptr inputObject);
    extern "C" void FireInputBegan_hook(uptr inputObject);
    extern "C" void FireInputEnded_hook(uptr inputObject);

    // Metatable bypass
    using GetRawMetaTableFn = uptr(*)(uptr obj);
    using SetRawMetaTableFn = bool(*)(uptr obj, uptr metatable);
    extern "C" uptr GetRawMetaTable_hook(uptr obj);
    extern "C" bool SetRawMetaTable_hook(uptr obj, uptr metatable);

    // Script context hooks
    using GetCallingScriptFn = uptr(*)();
    extern "C" uptr GetCallingScript_hook();

    // Teleport bypass
    using CanTeleportFn = bool(*)();
    using ForceTeleportFn = void(*)(uptr service, uptr args);
    extern "C" bool CanTeleport_hook();
    extern "C" void ForceTeleport_hook(uptr service, uptr args);

    // Print hook for output capture
    using PrintFn = void(*)(const char* msg);
    extern "C" void Print_hook(const char* msg);
}

// Hook initialization helper
bool InitializeRobloxHooks();

} // namespace Hooking