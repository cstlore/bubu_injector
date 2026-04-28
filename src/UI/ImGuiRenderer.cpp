#include "UI/ImGuiRenderer.h"
#include "Core/Config.h"

namespace UI {

ImGuiRenderer& ImGuiRenderer::Get() {
    static ImGuiRenderer instance{};
    return instance;
}

bool ImGuiRenderer::Initialize(HWND hWnd, ID3D11Device* device, ID3D11DeviceContext* context) {
    m_hWnd = hWnd;
    m_D3DState.Device = device;
    m_D3DState.Context = context;

    if (!CreateRenderTarget()) {
        LOG_ERROR("Failed to create render target");
        return false;
    }

    // Initialize ImGui
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; // Don't save layout
    io.MouseDrawCursor = false;
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;

    // Setup platform/renderer bindings
    ImGui_ImplWin32_Init(hWnd);
    ImGui_ImplDX11_Init(device, context);
    ImGui_ImplOpenGL3_Init("#version 130");

    // Apply default theme
    Style::ApplyDarkTheme();

    // Initialize timing
    QueryPerformanceFrequency(&m_Frequency);
    QueryPerformanceCounter(&m_LastTime);

    LOG_INFO("ImGui renderer initialized");
    return true;
}

void ImGuiRenderer::Shutdown() {
    DestroyRenderTarget();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
}

void ImGuiRenderer::NewFrame() {
    UpdateFrameStats();

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();
}

void ImGuiRenderer::Render() {
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

bool ImGuiRenderer::CreateRenderTarget() {
    ID3D11Texture2D* backBuffer = nullptr;
    if (FAILED(m_D3DState.SwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer)))) {
        return false;
    }

    if (FAILED(m_D3DState.Device->CreateRenderTargetView(backBuffer, nullptr, &m_D3DState.RenderTargetView))) {
        backBuffer->Release();
        return false;
    }

    backBuffer->Release();
    return true;
}

void ImGuiRenderer::DestroyRenderTarget() {
    if (m_D3DState.RenderTargetView) {
        m_D3DState.RenderTargetView->Release();
        m_D3DState.RenderTargetView = nullptr;
    }
}

void ImGuiRenderer::UpdateFrameStats() {
    QueryPerformanceCounter(&m_CurrentTime);

    float delta = static_cast<float>(m_CurrentTime.QuadPart - m_LastTime.QuadPart)
        / static_cast<float>(m_Frequency.QuadPart);

    m_DeltaTime = delta;
    m_FPS = 1.0f / delta;
    m_FrameCount++;

    m_LastTime = m_CurrentTime;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT ImGuiRenderer::HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (m_OverlayState.IsVisible) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
            return true;
        }
    }

    // Handle toggle key (F1)
    if (msg == WM_KEYDOWN && wParam == VK_F1) {
        m_OverlayState.IsVisible = !m_OverlayState.IsVisible;
        return true;
    }

    // Track mouse state
    switch (msg) {
        case WM_LBUTTONDOWN: m_MouseDown[0] = true; break;
        case WM_LBUTTONUP: m_MouseDown[0] = false; break;
        case WM_RBUTTONDOWN: m_MouseDown[1] = true; break;
        case WM_RBUTTONUP: m_MouseDown[1] = false; break;
        case WM_MBUTTONDOWN: m_MouseDown[2] = true; break;
        case WM_MBUTTONUP: m_MouseDown[2] = false; break;
    }

    return FALSE;
}

// Style implementations
namespace Style {
    void ApplyDarkTheme() {
        ImGui::StyleColorsDark();

        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 8.0f;
        style.FrameRounding = 6.0f;
        style.PopupRounding = 6.0f;
        style.GrabRounding = 4.0f;
        style.ChildRounding = 6.0f;
        style.ScrollbarRounding = 8.0f;
        style.TabRounding = 4.0f;

        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.08f, 0.10f, 0.95f);
        style.Colors[ImGuiCol_ChildBg] = ImVec4(0.12f, 0.12f, 0.14f, 0.95f);
        style.Colors[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.15f, 0.17f, 0.80f);
        style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.20f, 0.23f, 0.80f);
        style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.25f, 0.25f, 0.28f, 0.80f);
        style.Colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.10f, 0.12f, 0.95f);
        style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.15f, 0.15f, 0.17f, 0.95f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(0.40f, 0.70f, 1.00f, 1.00f);
        style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.40f, 0.70f, 1.00f, 1.00f);
        style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.50f, 0.80f, 1.00f, 1.00f);
        style.Colors[ImGuiCol_Button] = ImVec4(0.20f, 0.20f, 0.23f, 1.00f);
        style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.30f, 0.30f, 0.35f, 1.00f);
        style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.40f, 0.40f, 0.48f, 1.00f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.20f, 0.20f, 0.23f, 0.80f);
        style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.30f, 0.30f, 0.35f, 0.80f);
        style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.40f, 0.40f, 0.48f, 0.80f);
        style.Colors[ImGuiCol_Separator] = ImVec4(0.25f, 0.25f, 0.28f, 0.50f);
        style.Colors[ImGuiCol_Tab] = ImVec4(0.15f, 0.15f, 0.17f, 0.95f);
        style.Colors[ImGuiCol_TabHovered] = ImVec4(0.30f, 0.30f, 0.35f, 0.95f);
        style.Colors[ImGuiCol_TabActive] = ImVec4(0.25f, 0.25f, 0.28f, 0.95f);
    }

    void ApplyLightTheme() {
        ImGui::StyleColorsLight();

        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 6.0f;
        style.FrameRounding = 4.0f;
        style.GrabRounding = 4.0f;
    }

    void ApplyCustomTheme(ImVec4 windowBg, ImVec4 accentColor) {
        ImGui::StyleColorsDark();

        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = windowBg;
        style.Colors[ImGuiCol_CheckMark] = accentColor;
        style.Colors[ImGuiCol_SliderGrab] = accentColor;
        style.Colors[ImGuiCol_Button] = accentColor;
    }

    void SetWindowPadding(float x, float y) {
        ImGui::GetStyle().WindowPadding = ImVec2(x, y);
    }

    void SetFramePadding(float x, float y) {
        ImGui::GetStyle().FramePadding = ImVec2(x, y);
    }

    void SetItemSpacing(float x, float y) {
        ImGui::GetStyle().ItemSpacing = ImVec2(x, y);
    }

    void SetAlpha(float alpha) {
        ImGuiStyle& style = ImGui::GetStyle();
        for (int i = 0; i < ImGuiCol_COUNT; i++) {
            style.Colors[i].w *= alpha;
        }
    }

    void SetRounding(float rounding) {
        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = rounding;
        style.FrameRounding = rounding;
        style.PopupRounding = rounding;
        style.GrabRounding = rounding;
        style.ChildRounding = rounding;
        style.ScrollbarRounding = rounding;
    }

    ImU32 Colors::ToU32(ImVec4 color) {
        return ImGui::GetColorU32(color);
    }

    void Colors::SetColor(ImGuiCol idx, ImVec4 color) {
        ImGui::GetStyle().Colors[idx] = color;
    }

    void Colors::Cyberpunk() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.02f, 0.02f, 0.05f, 0.95f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.20f, 0.00f, 0.40f, 0.80f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 0.00f, 0.80f, 1.00f);
        style.Colors[ImGuiCol_SliderGrab] = ImVec4(1.00f, 0.00f, 0.80f, 1.00f);
        style.Colors[ImGuiCol_Button] = ImVec4(0.40f, 0.00f, 0.80f, 1.00f);
    }

    void Colors::Synthwave() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.05f, 0.00f, 0.10f, 0.95f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.15f, 0.00f, 0.30f, 0.80f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(1.00f, 0.50f, 0.00f, 1.00f);
        style.Colors[ImGuiCol_SliderGrab] = ImVec4(1.00f, 0.50f, 0.00f, 1.00f);
    }

    void Colors::Nord() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.21f, 0.24f, 0.29f, 0.95f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.27f, 0.31f, 0.38f, 0.80f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(0.69f, 0.86f, 0.92f, 1.00f);
    }

    void Colors::Dracula() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.15f, 0.15f, 0.18f, 0.95f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.20f, 0.20f, 0.24f, 0.80f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(0.68f, 0.50f, 0.69f, 1.00f);
    }

    void Colors::OneDark() {
        ImGuiStyle& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.18f, 0.20f, 0.25f, 0.95f);
        style.Colors[ImGuiCol_Header] = ImVec4(0.25f, 0.27f, 0.32f, 0.80f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(0.56f, 0.78f, 0.62f, 1.00f);
    }
}

// Input implementations
namespace Input {
    bool IsKeyPressed(int key) {
        return ImGui::IsKeyPressed(key);
    }

    bool IsKeyReleased(int key) {
        return ImGui::IsKeyReleased(key);
    }

    bool IsKeyDown(int key) {
        return ImGui::IsKeyDown(key);
    }

    bool IsMouseClicked(int button) {
        return ImGui::IsMouseClicked(button);
    }

    bool IsMouseReleased(int button) {
        return ImGui::IsMouseReleased(button);
    }

    bool IsMouseDown(int button) {
        return ImGui::IsMouseDown(button);
    }

    bool IsCtrlDown() {
        return ImGui::IsKeyDown(ImGuiKey_LeftCtrl) || ImGui::IsKeyDown(ImGuiKey_RightCtrl);
    }

    bool IsShiftDown() {
        return ImGui::IsKeyDown(ImGuiKey_LeftShift) || ImGui::IsKeyDown(ImGuiKey_RightShift);
    }

    bool IsAltDown() {
        return ImGui::IsKeyDown(ImGuiKey_LeftAlt) || ImGui::IsKeyDown(ImGuiKey_RightAlt);
    }

    bool IsWinDown() {
        return ImGui::IsKeyDown(ImGuiKey_LeftSuper) || ImGui::IsKeyDown(ImGuiKey_RightSuper);
    }
}

// Watermark
void Watermark::Render() {
    if (!m_Visible) return;

    ImGui::SetNextWindowPos(m_Position, ImGuiCond_Always);
    ImGui::SetNextWindowSize(m_Size, ImGuiCond_Always);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoBackground |
        ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("##Watermark", nullptr, flags);

    ImGui::TextColored(ImVec4(0.4f, 0.7f, 1.0f, 1.0f), "ENI Executor");
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), EXECUTOR_VERSION);

    if (!m_Content.empty()) {
        ImGui::Separator();
        ImGui::Text("%s", m_Content.c_str());
    }

    ImGui::End();
}

// Notification
void NotificationManager::Add(const std::string& message, float duration, ImVec4 color) {
    Notification notif;
    notif.Message = message;
    notif.Duration = duration;
    notif.Timer = 0.0f;
    notif.Color = color;
    m_Notifications.push_back(notif);
}

void NotificationManager::Render() {
    float y = 10.0f;
    ImVec2 notificationSize(300.0f, 0.0f);

    for (auto it = m_Notifications.begin(); it != m_Notifications.end(); ) {
        auto& notif = *it;
        notif.Timer += ImGui::GetIO().DeltaTime;

        if (notif.Timer >= notif.Duration) {
            it = m_Notifications.erase(it);
            continue;
        }

        float alpha = 1.0f - (notif.Timer / notif.Duration);
        alpha = std::min(alpha * 2.0f, 1.0f);

        ImGui::SetNextWindowPos(ImVec2(ImGui::GetIO().DisplaySize.x - notificationSize.x - 10.0f, y),
            ImGuiCond_Always);
        ImGui::SetNextWindowSize(notificationSize, ImGuiCond_Always);

        ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoInputs;

        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha);

        ImGui::Begin(("##Notification" + std::to_string(reinterpret_cast<uintptr_t>(&notif))).c_str(),
            nullptr, flags);

        ImGui::TextColored(notif.Color.w > 0 ? notif.Color : ImGui::GetStyleColorVec4(ImGuiCol_Text),
            "%s", notif.Message.c_str());

        ImGui::End();
        ImGui::PopStyleVar();

        y += 40.0f;
        ++it;
    }
}

void NotificationManager::Clear() {
    m_Notifications.clear();
}

} // namespace UI