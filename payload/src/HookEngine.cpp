// =============================================================================
// HookEngine.cpp
// =============================================================================

#include "Hyperion/HookEngine.h"
#include "Hyperion/Log.h"

#include <MinHook.h>

namespace ENI::Hyperion::HookEngine {

namespace {

struct Entry {
    void*       Target = nullptr;
    void*       Detour = nullptr;
    void*       Trampoline = nullptr;
    const char* Name = nullptr;
    bool        Active = false;
};

Entry g_Entries[kMaxHooks];
std::size_t g_Count = 0;
bool g_Initialized = false;

const char* MhStatusName(MH_STATUS s) {
    switch (s) {
        case MH_OK:                       return "OK";
        case MH_ERROR_ALREADY_INITIALIZED:return "ALREADY_INITIALIZED";
        case MH_ERROR_NOT_INITIALIZED:    return "NOT_INITIALIZED";
        case MH_ERROR_ALREADY_CREATED:    return "ALREADY_CREATED";
        case MH_ERROR_NOT_CREATED:        return "NOT_CREATED";
        case MH_ERROR_ENABLED:            return "ENABLED";
        case MH_ERROR_DISABLED:           return "DISABLED";
        case MH_ERROR_NOT_EXECUTABLE:     return "NOT_EXECUTABLE";
        case MH_ERROR_UNSUPPORTED_FUNCTION: return "UNSUPPORTED_FUNCTION";
        case MH_ERROR_MEMORY_ALLOC:       return "MEMORY_ALLOC";
        case MH_ERROR_MEMORY_PROTECT:     return "MEMORY_PROTECT";
        case MH_ERROR_MODULE_NOT_FOUND:   return "MODULE_NOT_FOUND";
        case MH_ERROR_FUNCTION_NOT_FOUND: return "FUNCTION_NOT_FOUND";
        default:                          return "UNKNOWN";
    }
}

} // namespace

bool Initialize() {
    if (g_Initialized) return true;
    const MH_STATUS s = MH_Initialize();
    if (s != MH_OK) {
        Log::Line("[hook] MH_Initialize failed: %s", MhStatusName(s));
        return false;
    }
    g_Initialized = true;
    return true;
}

void Shutdown() {
    if (!g_Initialized) return;

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    for (auto& e : g_Entries) e = {};
    g_Count = 0;
    g_Initialized = false;
}

bool Install(void* target, void* detour, void** outTrampoline, const char* name) {
    if (!g_Initialized) return false;
    if (!target || !detour) return false;
    if (g_Count >= kMaxHooks) {
        Log::Line("[hook] table full, can't install %s", name ? name : "?");
        return false;
    }

    void* tramp = nullptr;
    MH_STATUS s = MH_CreateHook(target, detour, &tramp);
    if (s != MH_OK) {
        Log::Line("[hook] %s create failed: %s", name ? name : "?", MhStatusName(s));
        return false;
    }
    s = MH_EnableHook(target);
    if (s != MH_OK) {
        Log::Line("[hook] %s enable failed: %s", name ? name : "?", MhStatusName(s));
        MH_RemoveHook(target);
        return false;
    }

    Entry& e = g_Entries[g_Count++];
    e.Target = target;
    e.Detour = detour;
    e.Trampoline = tramp;
    e.Name = name;
    e.Active = true;

    if (outTrampoline) *outTrampoline = tramp;
    Log::Line("[hook] %s installed: target=%p detour=%p tramp=%p",
              name ? name : "?", target, detour, tramp);
    return true;
}

std::size_t Count() {
    return g_Count;
}

} // namespace ENI::Hyperion::HookEngine
