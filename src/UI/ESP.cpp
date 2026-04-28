#include "pch.h"
#include "UI/ESP.h"
#include "Core/Globals.h"
#include "Core/Config.h"
#include "Memory/MemoryManager.h"

namespace UI {

ESP& ESP::Get() {
    static ESP instance{};
    return instance;
}

void ESP::Initialize() {
    m_Enabled = true;
    LOG_INFO("ESP system initialized");
}

void ESP::Shutdown() {
    m_Enabled = false;
    m_Players.clear();
    m_Items.clear();
}

void ESP::Update() {
    if (!m_Enabled) return;

    // Get local player
    auto& globals = Core::Globals();
    if (!globals.Handle || !globals.Players) return;

    // Clear old data
    m_Players.clear();
    m_Items.clear();

    // Update screen center for tracers
    m_ScreenCenter = ImGui::GetIO().DisplaySize / 2;

    // Read player data from Roblox's internal structures
    // This is simplified - actual implementation would read from DataModel
    uptr playerList = Memory::MemoryManager::Read<uptr>(globals.Players);
    if (!playerList) return;

    int playerCount = Memory::MemoryManager::Read<i32>(playerList + 0x18); // GetChildren count
    for (int i = 0; i < playerCount && i < 100; i++) {
        uptr childPtr = Memory::MemoryManager::Read<uptr>(playerList + 0x20 + (i * 8)); // GetChildren array
        if (!childPtr) continue;

        // Get player name (simplified - would need proper string reading)
        PlayerESPData player;
        player.Address = childPtr;

        // Get character
        uptr character = Memory::MemoryManager::Read<uptr>(childPtr + 0x100); // Character offset
        if (!character) continue;

        // Get humanoid
        uptr humanoid = Memory::MemoryManager::Read<uptr>(character + 0x2A8); // Humanoid offset
        if (!humanoid) continue;

        player.MaxHealth = Memory::MemoryManager::Read<f32>(humanoid + 0xE0); // MaxHealth
        player.Health = Memory::MemoryManager::Read<f32>(humanoid + 0xE4); // Health

        // Calculate health color
        float healthPercent = player.MaxHealth > 0 ? player.Health / player.MaxHealth : 0;
        player.HealthColor = ImVec4(
            1.0f - healthPercent,  // Red increases as health decreases
            healthPercent,          // Green decreases as health decreases
            0, 1
        );

        // Get position (simplified)
        uptr rootPart = Memory::MemoryManager::Read<uptr>(character + 0x168); // HumanoidRootPart
        if (rootPart) {
            // Read position from CFrame
            float posX = Memory::MemoryManager::Read<f32>(rootPart + 0x10);
            float posY = Memory::MemoryManager::Read<f32>(rootPart + 0x14);
            float posZ = Memory::MemoryManager::Read<f32>(rootPart + 0x18);

            ImVec3 worldPos{posX, posY, posZ};
            player.ScreenPosition = WorldToScreen(worldPos);

            // Calculate distance from local player
            uptr localChar = Memory::MemoryManager::Read<uptr>(globals.Players + 0x100);
            if (localChar) {
                uptr localRoot = Memory::MemoryManager::Read<uptr>(localChar + 0x168);
                if (localRoot) {
                    float localX = Memory::MemoryManager::Read<f32>(localRoot + 0x10);
                    float localY = Memory::MemoryManager::Read<f32>(localRoot + 0x14);
                    float localZ = Memory::MemoryManager::Read<f32>(localRoot + 0x18);

                    float dx = posX - localX;
                    float dy = posY - localY;
                    float dz = posZ - localZ;
                    player.Distance = sqrtf(dx*dx + dy*dy + dz*dz);
                }
            }
        }

        player.IsValid = true;
        player.IsVisible = true; // Would need proper visibility check
        player.BoxColor = m_PlayerColorNormal;

        if (player.Distance <= m_MaxDistance) {
            m_Players.push_back(player);
        }
    }
}

void ESP::Render() {
    if (!m_Enabled) return;

    m_DrawList = ImGui::GetBackgroundDrawList();

    // Render players
    for (const auto& player : m_Players) {
        if (player.IsValid) {
            RenderPlayerESP(player);
        }
    }

    // Render items
    for (const auto& item : m_Items) {
        if (item.IsValid) {
            RenderItemESP(item);
        }
    }
}

void ESP::RenderPlayerESP(const PlayerESPData& player) {
    if (!player.IsVisible) return;

    ImU32 color = ImGui::GetColorU32(player.BoxColor);

    if (m_BoxESP) {
        RenderBox(player);
    }

    if (m_NameESP) {
        RenderName(player);
    }

    if (m_HealthESP) {
        RenderHealth(player);
    }

    if (m_DistanceESP) {
        RenderDistance(player);
    }

    if (m_Tracers) {
        RenderTracers(player);
    }
}

void ESP::RenderBox(const PlayerESPData& player) {
    ImVec2 headPos = player.ScreenPosition;
    float height = 80.0f; // Simplified - should be calculated from character size
    float width = height * 0.5f;

    ImU32 color = ImGui::GetColorU32(player.BoxColor);

    // Box outline
    Render::CornerBox(m_DrawList, headPos, height, width, color);

    // Alternative: simple box
    ImVec2 topLeft{headPos.x - width/2, headPos.y};
    ImVec2 bottomRight{headPos.x + width/2, headPos.y + height};

    Render::Box(m_DrawList, topLeft, bottomRight, color, 2.0f);
}

void ESP::RenderTracers(const PlayerESPData& player) {
    ImU32 color = ImGui::GetColorU32(ImVec4(
        player.BoxColor.x, player.BoxColor.y, player.BoxColor.z, 0.5f));

    Render::Line(m_DrawList, m_ScreenCenter, player.ScreenPosition, color, 1.0f);
}

void ESP::RenderName(const PlayerESPData& player) {
    ImU32 color = ImGui::GetColorU32(ImVec4(1, 1, 1, 1));
    Render::Text(m_DrawList, ImVec2(player.ScreenPosition.x, player.ScreenPosition.y - 20),
        player.Name.c_str(), color, true);
}

void ESP::RenderHealth(const PlayerESPData& player) {
    float height = 80.0f;
    float width = 4.0f;
    ImVec2 topLeft{player.ScreenPosition.x + 30, player.ScreenPosition.y};

    ImU32 bgColor = ImGui::GetColorU32(ImVec4(0.3f, 0.3f, 0.3f, 1));
    ImU32 healthColor = ImGui::GetColorU32(player.HealthColor);

    float healthPercent = player.MaxHealth > 0 ? player.Health / player.MaxHealth : 0;
    Render::HealthBar(m_DrawList, topLeft, width, height, healthPercent, bgColor, healthColor);
}

void ESP::RenderDistance(const PlayerESPData& player) {
    char distText[32];
    snprintf(distText, sizeof(distText), "%.0fm", player.Distance);

    ImU32 color = ImGui::GetColorU32(ImVec4(1, 1, 1, 0.7f));
    Render::Text(m_DrawList, ImVec2(player.ScreenPosition.x + 40, player.ScreenPosition.y + 40),
        distText, color, true);
}

void ESP::RenderItemESP(const ItemESPData& item) {
    ImU32 color;

    switch (item.Name.find("chest") != std::string::npos ? 0 :
            item.Name.find("coin") != std::string::npos ? 1 :
            item.Name.find("drop") != std::string::npos ? 2 : 3) {
        case 0: color = ImGui::GetColorU32(m_ChestColor); break;
        case 1: color = ImGui::GetColorU32(m_CoinColor); break;
        case 2: color = ImGui::GetColorU32(m_DropColor); break;
        default: color = ImGui::GetColorU32(ImVec4(1, 1, 1, 1));
    }

    // Draw as a small square
    ImVec2 pos = item.ScreenPosition;
    Render::Box(m_DrawList, ImVec2(pos.x - 5, pos.y - 5), ImVec2(pos.x + 5, pos.y + 5), color);

    // Draw name above
    Render::Text(m_DrawList, ImVec2(pos.x, pos.y - 15), item.Name.c_str(), color, true);
}

void ESP::SetPlayerESP(bool enabled, bool box, bool name, bool health, bool distance, bool tracers) {
    m_PlayerESP = enabled;
    m_BoxESP = box;
    m_NameESP = name;
    m_HealthESP = health;
    m_DistanceESP = distance;
    m_Tracers = tracers;
}

void ESP::SetPlayerColors(ImVec4 normal, ImVec4 visible) {
    m_PlayerColorNormal = normal;
    m_PlayerColorVisible = visible;
}

void ESP::SetItemESP(bool enabled, bool chests, bool coins, bool drops) {
    m_ItemESP = enabled;
    m_ChestESP = chests;
    m_CoinESP = coins;
    m_DropESP = drops;
}

void ESP::SetItemColors(ImVec4 chest, ImVec4 coin, ImVec4 drop) {
    m_ChestColor = chest;
    m_CoinColor = coin;
    m_DropColor = drop;
}

ImVec2 ESP::WorldToScreen(ImVec3 pos, float fov) {
    // Simplified world-to-screen conversion
    // Full implementation would use camera CFrame and projection matrix

    ImVec2 screenCenter = m_ScreenCenter;
    float tanFov = tanf(fov * 0.5f * 3.14159f / 180.0f);

    // Return as percentage of screen
    // In real implementation, this would use Roblox's camera data
    return ImVec2(screenCenter.x + pos.x * 50, screenCenter.y - pos.y * 50);
}

// Render namespace implementations
namespace Render {
    void Box(ImDrawList* drawList, ImVec2 topLeft, ImVec2 bottomRight, ImU32 color, float thickness) {
        drawList->AddRect(topLeft, bottomRight, color, 0.0f, 0, thickness);
    }

    void CornerBox(ImDrawList* drawList, ImVec2 headPos, float height, float width, ImU32 color) {
        float cornerLength = width * 0.3f;

        // Top-left corner
        drawList->AddLine(headPos, ImVec2(headPos.x - cornerLength, headPos.y), color, 2.0f);
        drawList->AddLine(headPos, ImVec2(headPos.x, headPos.y + cornerLength), color, 2.0f);

        // Top-right corner
        drawList->AddLine(ImVec2(headPos.x + width/2, headPos.y), ImVec2(headPos.x + width/2 + cornerLength, headPos.y), color, 2.0f);
        drawList->AddLine(ImVec2(headPos.x + width/2, headPos.y), ImVec2(headPos.x + width/2, headPos.y + cornerLength), color, 2.0f);

        // Bottom-left corner
        drawList->AddLine(ImVec2(headPos.x, headPos.y + height), ImVec2(headPos.x - cornerLength, headPos.y + height), color, 2.0f);
        drawList->AddLine(ImVec2(headPos.x, headPos.y + height), ImVec2(headPos.x, headPos.y + height - cornerLength), color, 2.0f);

        // Bottom-right corner
        drawList->AddLine(ImVec2(headPos.x + width/2, headPos.y + height), ImVec2(headPos.x + width/2 + cornerLength, headPos.y + height), color, 2.0f);
        drawList->AddLine(ImVec2(headPos.x + width/2, headPos.y + height), ImVec2(headPos.x + width/2, headPos.y + height - cornerLength), color, 2.0f);
    }

    void Line(ImDrawList* drawList, ImVec2 from, ImVec2 to, ImU32 color, float thickness) {
        drawList->AddLine(from, to, color, thickness);
    }

    void Text(ImDrawList* drawList, const ImVec2& pos, const char* text, ImU32 color, bool center) {
        ImVec2 textPos = pos;
        if (center) {
            ImVec2 textSize = ImGui::CalcTextSize(text);
            textPos.x -= textSize.x * 0.5f;
        }

        // Draw shadow
        drawList->AddText(ImVec2(textPos.x + 1, textPos.y + 1), IM_COL32(0, 0, 0, 150), text);
        // Draw text
        drawList->AddText(textPos, color, text);
    }

    void HealthBar(ImDrawList* drawList, ImVec2 topLeft, float width, float height, float healthPercent, ImU32 bgColor, ImU32 healthColor) {
        // Background
        drawList->AddRectFilled(topLeft, ImVec2(topLeft.x + width, topLeft.y + height), bgColor);

        // Health fill
        float healthHeight = height * healthPercent;
        drawList->AddRectFilled(
            ImVec2(topLeft.x, topLeft.y + height - healthHeight),
            ImVec2(topLeft.x + width, topLeft.y + height),
            healthColor
        );

        // Border
        drawList->AddRect(topLeft, ImVec2(topLeft.x + width, topLeft.y + height), IM_COL32(0, 0, 0, 200), 0.0f, 0, 1.0f);
    }

    void Circle(ImDrawList* drawList, const ImVec2& center, float radius, ImU32 color, float thickness) {
        drawList->AddCircle(center, radius, color, 12, thickness);
    }

    void Skeleton(ImDrawList* drawList, const std::vector<ImVec2>& joints, ImU32 color) {
        if (joints.size() < 2) return;

        for (size_t i = 1; i < joints.size(); i++) {
            drawList->AddLine(joints[i-1], joints[i], color, 2.0f);
        }
    }
}

// Presets
namespace ESPPresets {
    void Vanilla(ESP& esp) {
        esp.SetPlayerESP(true, true, true, false, false, false);
    }

    void Compact(ESP& esp) {
        esp.SetPlayerESP(true, false, true, true, true, false);
    }

    void Full(ESP& esp) {
        esp.SetPlayerESP(true, true, true, true, true, true);
        esp.SetItemESP(true, true, true, true);
    }
}

} // namespace UI