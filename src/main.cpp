#include "pch.h"
#include "Core/Globals.h"
#include "Core/Config.h"
#include "Memory/MemoryManager.h"
#include "Executor/LuaContext.h"
#include "Executor/ScriptEngine.h"
#include "Hooking/HookManager.h"
#include "Hooking/Hooks.h"
#include "UI/ImGuiRenderer.h"
#include "UI/Menu.h"
#include "UI/ESP.h"
#include "ScriptHub/ScriptHub.h"
#include "Utils/Utils.h"

// Global state
static bool g_Initialized = false;
static bool g_DetachRequested = false;

// Forward declarations
namespace UI {
    void RenderOverlay();
    class Watermark;
    class NotificationManager;
}

// Window procedure
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Handle ImGui input
    if (UI::ImGuiRenderer::Get().HandleMessage(hwnd, msg, wParam, lParam)) {
        return TRUE;
    }

    // Handle toggle
    if (msg == WM_KEYDOWN && wParam == VK_F1) {
        UI::Menu::Get().Toggle();
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// Initialize the executor
static bool InitializeExecutor() {
    LOG_INFO("Initializing executor...");

    // Attach to Roblox
    if (!Core::AttachToRoblox()) {
        LOG_ERROR("Failed to attach to Roblox");
        return false;
    }

    // Initialize memory manager with process handle
    Memory::MemoryManager::Get().SetProcess(Core::Globals().Handle);

    // Load configuration
    Core::ConfigManager::Get().Load();

    // Initialize hook manager
    if (!Hooking::HookManager::Get().Initialize()) {
        LOG_ERROR("Failed to initialize hook manager");
        return false;
    }

    // Initialize Roblox hooks
    if (!Hooking::InitializeRobloxHooks()) {
        LOG_WARN("Some Roblox hooks failed to initialize");
    }

    // Patch integrity checks
    Hooking::HookDefinitions::PatchIntegrityChecks();
    Hooking::HookDefinitions::HideFromDebugger();
    Hooking::HookDefinitions::ClearDebugRegisters();

    // Initialize Lua context
    if (!Executor::LuaContext::Get().Initialize()) {
        LOG_ERROR("Failed to initialize Lua context");
        return false;
    }

    // Initialize script engine
    if (!Executor::ScriptEngine::Get().Initialize()) {
        LOG_ERROR("Failed to initialize script engine");
        return false;
    }

    // Initialize script hub
    ScriptHub::ScriptHubManager::Get().Initialize();

    // Initialize ESP
    UI::ESP::Get().Initialize();

    LOG_INFO("Executor initialized successfully");
    return true;
}

// Shutdown the executor
static void ShutdownExecutor() {
    LOG_INFO("Shutting down executor...");

    // Save configuration
    Core::ConfigManager::Get().Save();

    // Shutdown components in reverse order
    UI::ESP::Get().Shutdown();
    ScriptHub::ScriptHubManager::Get().Shutdown();
    Executor::ScriptEngine::Get().Shutdown();
    Executor::LuaContext::Get().Shutdown();
    Hooking::HookManager::Get().Shutdown();

    LOG_INFO("Executor shutdown complete");
}

// Main render loop
static void RenderLoop() {
    auto& renderer = UI::ImGuiRenderer::Get();
    auto& menu = UI::Menu::Get();

    while (!g_DetachRequested) {
        // Wait for VSync or message
        MSG msg{};
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                g_DetachRequested = true;
                break;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        if (g_DetachRequested) break;

        // Render frame
        renderer.NewFrame();

        // Render ESP (world space)
        UI::ESP::Get().Update();
        UI::ESP::Get().Render();

        // Render menu
        menu.Render();

        // Render watermark
        static UI::Watermark watermark;
        watermark.Render();

        // Render notifications
        static UI::NotificationManager notifications;
        notifications.Render();

        renderer.Render();

        // Tick enabled scripts
        Executor::ScriptEngine::Get().TickEnabledScripts();

        // Small sleep to prevent CPU spinning
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            {
                // Disable thread notifications for performance
                DisableThreadLibraryCalls(hModule);

                // Initialize logging
                AllocConsole();
                FILE* fp;
                freopen_s(&fp, "CONOUT$", "w", stdout);
                freopen_s(&fp, "CONOUT$", "w", stderr);

                LOG_INFO("=== ENI Executor v%s ===", EXECUTOR_VERSION);
                LOG_INFO("Build: %s", EXECUTOR_BUILD_DATE);

                // Run initialization in a separate thread
                std::thread initThread([]() {
                    if (InitializeExecutor()) {
                        g_Initialized = true;

                        // Create render thread
                        std::thread renderThread(RenderLoop);
                        renderThread.detach();
                    } else {
                        LOG_ERROR("Initialization failed!");
                        Sleep(2000);
                        FreeConsole();
                        FreeLibraryAndExitThread(hModule, 0);
                    }
                });
                initThread.detach();
            }
            break;

        case DLL_PROCESS_DETACH:
            {
                g_DetachRequested = true;
                ShutdownExecutor();

                if (fp) fclose(fp);
                FreeConsole();
            }
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

// Exported functions for external control
extern "C" {
    __declspec(dllexport) bool Attach() {
        if (!g_Initialized) {
            return InitializeExecutor();
        }
        return true;
    }

    __declspec(dllexport) bool Detach() {
        g_DetachRequested = true;
        return true;
    }

    __declspec(dllexport) bool IsAttached() {
        return g_Initialized;
    }

    __declspec(dllexport) bool ExecuteScript(const char* script) {
        if (!g_Initialized) return false;
        auto result = Executor::ScriptEngine::Get().Execute(script, "External");
        return result.Success;
    }

    __declspec(dllexport) void SetIdentity(int level) {
        if (!g_Initialized) return;
        Executor::LuaContext::Roblox::SetIdentity(level);
    }

    __declspec(dllexport) int GetIdentity() {
        if (!g_Initialized) return 0;
        return static_cast<int>(Executor::LuaContext::Roblox::GetIdentity());
    }

    __declspec(dllexport) void ToggleMenu() {
        UI::Menu::Get().Toggle();
    }
}
