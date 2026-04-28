#pragma once

#include "../pch.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace Core {

// Execution settings
struct ExecutionSettings {
    bool AutoAttach = true;
    bool ShowConsole = true;
    int IdentityLevel = 7;
    bool EnableContextBypass = true;
    bool EnableFireClicks = true;
    bool EnableTPBypass = true;
};

// UI settings
struct UISettings {
    ImVec4 MenuColor = ImVec4(0.15f, 0.15f, 0.15f, 0.95f);
    ImVec4 AccentColor = ImVec4(0.4f, 0.7f, 1.0f, 1.0f);
    bool ShowFPS = true;
    bool ShowMenuBar = true;
    bool DarkMode = true;
    int TabIndex = 0;
};

// ESP settings
struct ESPSettings {
    bool PlayerESP = false;
    bool BoxESP = true;
    bool NameESP = true;
    bool HealthESP = true;
    bool DistanceESP = true;
    bool Tracers = false;
    bool ItemESP = false;
    bool ChestESP = false;
    bool CoinESP = false;
    ImVec4 ESPColor = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
    ImVec4 BoxColor = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
    float ESPDistance = 500.0f;
};

// Script entry for history/management
struct ScriptEntry {
    std::string Name;
    std::string Content;
    std::string Category;
    bool Enabled = false;
    std::chrono::system_clock::time_point LastUsed;
};

// Main config container
struct Config {
    ExecutionSettings Execution;
    UISettings UI;
    ESPSettings ESP;
    std::vector<ScriptEntry> ScriptHistory;
    std::vector<ScriptEntry> SavedScripts;
    std::unordered_map<std::string, std::string> Hotkeys;
    std::string LastSelectedScript;
    int MaxScriptHistory = 50;
};

// Configuration manager singleton
class ConfigManager {
public:
    static ConfigManager& Get();

    // Load/save config from disk
    bool Load();
    bool Save();

    // Runtime accessors
    Config& GetConfig();
    const Config& GetConfig() const;

    // Individual section accessors
    ExecutionSettings& Execution();
    UISettings& UI();
    ESPSettings& ESP();

    // Script management
    void AddToHistory(const std::string& name, const std::string& content);
    void SaveScript(const std::string& name, const std::string& content, const std::string& category = "Custom");
    void RemoveScript(size_t index);
    std::vector<ScriptEntry>& GetSavedScripts();
    std::vector<ScriptEntry>& GetScriptHistory();

    // Path helpers
    static std::filesystem::path GetConfigPath();
    static std::filesystem::path GetScriptsPath();

private:
    ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;

    Config m_Config{};
};

} // namespace Core