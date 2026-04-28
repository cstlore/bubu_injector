#pragma once

#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_opengl3.h>
#include <d3d11.h>
#include <dxgi.h>

namespace UI {

// DirectX 11 state
struct D3D11State {
    ID3D11Device* Device = nullptr;
    ID3D11DeviceContext* Context = nullptr;
    IDXGISwapChain* SwapChain = nullptr;
    ID3D11RenderTargetView* RenderTargetView = nullptr;
    ID3D11DepthStencilView* DepthStencilView = nullptr;
};

// Render overlay state
struct OverlayState {
    bool IsVisible = true;
    bool IsMinimized = false;
    ImVec2 Position;
    ImVec2 Size;
    bool IsDragging = false;
    bool IsResizing = false;
};

// Main ImGui renderer
class ImGuiRenderer {
public:
    static ImGuiRenderer& Get();

    // Initialization with window handle
    bool Initialize(HWND hWnd, ID3D11Device* device, ID3D11DeviceContext* context);
    void Shutdown();

    // Frame management
    void NewFrame();
    void Render();

    // Device state
    D3D11State& GetD3DState() { return m_D3DState; }
    const D3D11State& GetD3DState() const { return m_D3DState; }

    // Overlay state
    OverlayState& GetOverlayState() { return m_OverlayState; }
    bool IsMenuVisible() const { return m_OverlayState.IsVisible && !m_OverlayState.IsMinimized; }

    // Window info
    HWND GetWindowHandle() const { return m_hWnd; }
    void SetWindowHandle(HWND hWnd) { m_hWnd = hWnd; }

    // Frame timing
    float GetDeltaTime() const { return m_DeltaTime; }
    float GetFPS() const { return m_FPS; }
    int GetFrameCount() const { return m_FrameCount; }

    // Input handling (call from WndProc)
    LRESULT HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    ImGuiRenderer() = default;
    ImGuiRenderer(const ImGuiRenderer&) = delete;
    ImGuiRenderer& operator=(const ImGuiRenderer&) = delete;

    bool CreateRenderTarget();
    void DestroyRenderTarget();
    void UpdateFrameStats();

    HWND m_hWnd = nullptr;
    D3D11State m_D3DState;
    OverlayState m_OverlayState;

    // Frame timing
    float m_DeltaTime = 0.0f;
    float m_FPS = 0.0f;
    int m_FrameCount = 0;
    LARGE_INTEGER m_LastTime{};
    LARGE_INTEGER m_CurrentTime{};
    LARGE_INTEGER m_Frequency{};

    // Mouse state
    ImVec2 m_MousePos;
    bool m_MouseDown[3] = {false, false, false};
};

// Style customization helpers
namespace Style {
    // Apply custom theme
    void ApplyDarkTheme();
    void ApplyLightTheme();
    void ApplyCustomTheme(ImVec4 windowBg, ImVec4 accentColor);

    // Individual style setters
    void SetWindowPadding(float x, float y);
    void SetFramePadding(float x, float y);
    void SetItemSpacing(float x, float y);
    void SetAlpha(float alpha);
    void SetRounding(float rounding);

    // Color scheme helpers
    namespace Colors {
        ImU32 ToU32(ImVec4 color);
        void SetColor(ImGuiCol idx, ImVec4 color);

        // Preset palettes
        void Cyberpunk();
        void Synthwave();
        void Nord();
        void Dracula();
        void OneDark();
    }
}

// Input helpers
namespace Input {
    // Hotkey checking
    bool IsKeyPressed(int key);
    bool IsKeyReleased(int key);
    bool IsKeyDown(int key);
    bool IsMouseClicked(int button);
    bool IsMouseReleased(int button);
    bool IsMouseDown(int button);

    // Get key name
    const char* GetKeyName(int key);

    // Key combinations
    bool IsCtrlDown();
    bool IsShiftDown();
    bool IsAltDown();
    bool IsWinDown();
}

// Overlay/Watermark
class Watermark {
public:
    Watermark() = default;

    void Render();
    void SetPosition(ImVec2 pos) { m_Position = pos; }
    void SetSize(ImVec2 size) { m_Size = size; }
    void SetVisible(bool visible) { m_Visible = visible; }
    void Toggle() { m_Visible = !m_Visible; }

    // Custom content
    void SetContent(const std::string& content) { m_Content = content; }

private:
    ImVec2 m_Position{10, 10};
    ImVec2 m_Size{200, 60};
    bool m_Visible = true;
    std::string m_Content;
};

// Notification system
class NotificationManager {
public:
    struct Notification {
        std::string Message;
        float Duration;
        float Timer;
        ImVec4 Color;
        ImGuiToastType Type;
    };

    void Add(const std::string& message, float duration = 3.0f, ImVec4 color = {});
    void Render();
    void Clear();

private:
    std::vector<Notification> m_Notifications;
};

} // namespace UI