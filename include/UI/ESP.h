#pragma once

#include "../pch.h"

namespace UI {

// Player data for ESP
struct PlayerESPData {
    uptr Address = 0;
    std::string Name;
    ImVec2 ScreenPosition;
    float Distance = 0;
    float Health = 0;
    float MaxHealth = 0;
    bool IsVisible = false;
    bool IsValid = false;

    ImVec4 BoxColor = ImVec4(0, 1, 0, 1);
    ImVec4 HealthColor = ImVec4(0, 1, 0, 1);
};

// Item data for ESP
struct ItemESPData {
    std::string Name;
    uptr Address = 0;
    ImVec3 Position;
    ImVec2 ScreenPosition;
    float Distance = 0;
    bool IsValid = false;
};

class ESP {
public:
    static ESP& Get();

    // Lifecycle
    void Initialize();
    void Shutdown();
    bool IsEnabled() const { return m_Enabled; }
    void SetEnabled(bool enabled) { m_Enabled = enabled; }

    // Frame update (called each render frame)
    void Update();

    // Rendering
    void Render();

    // Player ESP
    void SetPlayerESP(bool enabled, bool box, bool name, bool health, bool distance, bool tracers);
    void SetPlayerColors(ImVec4 normal, ImVec4 visible);
    void SetMaxDistance(float dist) { m_MaxDistance = dist; }

    // Item ESP
    void SetItemESP(bool enabled, bool chests, bool coins, bool drops);
    void SetItemColors(ImVec4 chest, ImVec4 coin, ImVec4 drop);

    // Utility
    ImVec2 WorldToScreen(ImVec3 pos, float fov = 70.0f);

private:
    ESP() = default;
    ESP(const ESP&) = delete;
    ESP& operator=(const ESP&) = delete;

    void RenderPlayerESP(const PlayerESPData& player);
    void RenderItemESP(const ItemESPData& item);
    void RenderBox(const PlayerESPData& player);
    void RenderTracers(const PlayerESPData& player);
    void RenderName(const PlayerESPData& player);
    void RenderHealth(const PlayerESPData& player);
    void RenderDistance(const PlayerESPData& player);

    bool m_Enabled = false;
    bool m_PlayerESP = true;
    bool m_BoxESP = true;
    bool m_NameESP = true;
    bool m_HealthESP = true;
    bool m_DistanceESP = true;
    bool m_Tracers = false;
    bool m_ItemESP = false;
    bool m_ChestESP = true;
    bool m_CoinESP = true;
    bool m_DropESP = true;

    float m_MaxDistance = 500.0f;

    ImVec4 m_PlayerColorNormal = ImVec4(0, 1, 0, 1);
    ImVec4 m_PlayerColorVisible = ImVec4(1, 1, 0, 1);
    ImVec4 m_ChestColor = ImVec4(1, 0.5f, 0, 1);
    ImVec4 m_CoinColor = ImVec4(1, 1, 0, 1);
    ImVec4 m_DropColor = ImVec4(0.5f, 0.5f, 1, 1);

    std::vector<PlayerESPData> m_Players;
    std::vector<ItemESPData> m_Items;

    // Rendering state
    ImDrawList* m_DrawList = nullptr;
    ImVec2 m_ScreenCenter;
};

// Inline rendering helper
namespace Render {
    // Draw a 2D box
    void Box(ImDrawList* drawList, ImVec2 topLeft, ImVec2 bottomRight, ImU32 color, float thickness = 1.0f);

    // Draw a corner box
    void CornerBox(ImDrawList* drawList, ImVec2 headPos, float height, float width, ImU32 color);

    // Draw a line
    void Line(ImDrawList* drawList, ImVec2 from, ImVec2 to, ImU32 color, float thickness = 1.0f);

    // Draw text with outline
    void Text(ImDrawList* drawList, const ImVec2& pos, const char* text, ImU32 color, bool center = false);

    // Draw health bar
    void HealthBar(ImDrawList* drawList, ImVec2 topLeft, float width, float height, float healthPercent, ImU32 bgColor, ImU32 healthColor);

    // Draw circle
    void Circle(ImDrawList* drawList, const ImVec2& center, float radius, ImU32 color, float thickness = 1.0f);

    // Draw skeleton
    void Skeleton(ImDrawList* drawList, const std::vector<ImVec2>& joints, ImU32 color);
}

// Preset ESP configurations
namespace ESPPresets {
    void Vanilla(ESP& esp);
    void Compact(ESP& esp);
    void Full(ESP& esp);
}

} // namespace UI