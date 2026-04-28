#include "pch.h"
#include "Core/Config.h"
#include "Memory/MemoryManager.h"

namespace Core {

ConfigManager& ConfigManager::Get() {
    static ConfigManager instance{};
    return instance;
}

Config& ConfigManager::GetConfig() { return m_Config; }
const Config& ConfigManager::GetConfig() const { return m_Config; }

ExecutionSettings& ConfigManager::Execution() { return m_Config.Execution; }
UISettings& ConfigManager::UI() { return m_Config.UI; }
ESPSettings& ConfigManager::ESP() { return m_Config.ESP; }

std::filesystem::path ConfigManager::GetConfigPath() {
    return std::filesystem::current_path() / "config.json";
}

std::filesystem::path ConfigManager::GetScriptsPath() {
    return std::filesystem::current_path() / "scripts";
}

std::vector<ScriptEntry>& ConfigManager::GetSavedScripts() { return m_Config.SavedScripts; }
std::vector<ScriptEntry>& ConfigManager::GetScriptHistory() { return m_Config.ScriptHistory; }

bool ConfigManager::Load() {
    try {
        auto path = GetConfigPath();
        if (!std::filesystem::exists(path)) {
            LOG_INFO("Config file not found, using defaults");
            return false;
        }

        std::ifstream file(path);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open config file");
            return false;
        }

        json j;
        file >> j;
        file.close();

        // Parse execution settings
        if (j.contains("execution")) {
            auto& exec = j["execution"];
            m_Config.Execution.AutoAttach = exec.value("autoAttach", true);
            m_Config.Execution.ShowConsole = exec.value("showConsole", true);
            m_Config.Execution.IdentityLevel = exec.value("identityLevel", 7);
            m_Config.Execution.EnableContextBypass = exec.value("contextBypass", true);
            m_Config.Execution.EnableFireClicks = exec.value("fireClicks", true);
            m_Config.Execution.EnableTPBypass = exec.value("tpBypass", true);
        }

        // Parse UI settings
        if (j.contains("ui")) {
            auto& ui = j["ui"];
            m_Config.UI.ShowFPS = ui.value("showFPS", true);
            m_Config.UI.ShowMenuBar = ui.value("showMenuBar", true);
            m_Config.UI.DarkMode = ui.value("darkMode", true);
            m_Config.UI.TabIndex = ui.value("tabIndex", 0);
        }

        // Parse ESP settings
        if (j.contains("esp")) {
            auto& esp = j["esp"];
            m_Config.ESP.PlayerESP = esp.value("playerESP", false);
            m_Config.ESP.BoxESP = esp.value("boxESP", true);
            m_Config.ESP.NameESP = esp.value("nameESP", true);
            m_Config.ESP.HealthESP = esp.value("healthESP", true);
            m_Config.ESP.DistanceESP = esp.value("distanceESP", true);
            m_Config.ESP.Tracers = esp.value("tracers", false);
            m_Config.ESP.ItemESP = esp.value("itemESP", false);
            m_Config.ESP.ChestESP = esp.value("chestESP", false);
            m_Config.ESP.CoinESP = esp.value("coinESP", false);
            m_Config.ESP.ESPDistance = esp.value("espDistance", 500.0f);
        }

        // Parse script history
        if (j.contains("scriptHistory")) {
            for (auto& entry : j["scriptHistory"]) {
                ScriptEntry se;
                se.Name = entry.value("name", "");
                se.Content = entry.value("content", "");
                se.Category = entry.value("category", "Custom");
                se.Enabled = entry.value("enabled", false);
                m_Config.ScriptHistory.push_back(se);
            }
        }

        // Parse saved scripts
        if (j.contains("savedScripts")) {
            for (auto& entry : j["savedScripts"]) {
                ScriptEntry se;
                se.Name = entry.value("name", "");
                se.Content = entry.value("content", "");
                se.Category = entry.value("category", "Custom");
                se.Enabled = entry.value("enabled", false);
                m_Config.SavedScripts.push_back(se);
            }
        }

        // Parse hotkeys
        if (j.contains("hotkeys")) {
            for (auto& [key, value] : j["hotkeys"].items()) {
                m_Config.Hotkeys[key] = value.get<std::string>();
            }
        }

        m_Config.LastSelectedScript = j.value("lastSelectedScript", "");
        m_Config.MaxScriptHistory = j.value("maxScriptHistory", 50);

        LOG_INFO("Config loaded successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Config load failed: %s", e.what());
        return false;
    }
}

bool ConfigManager::Save() {
    try {
        json j;

        // Serialize execution settings
        j["execution"] = {
            {"autoAttach", m_Config.Execution.AutoAttach},
            {"showConsole", m_Config.Execution.ShowConsole},
            {"identityLevel", m_Config.Execution.IdentityLevel},
            {"contextBypass", m_Config.Execution.EnableContextBypass},
            {"fireClicks", m_Config.Execution.EnableFireClicks},
            {"tpBypass", m_Config.Execution.EnableTPBypass}
        };

        // Serialize UI settings
        j["ui"] = {
            {"showFPS", m_Config.UI.ShowFPS},
            {"showMenuBar", m_Config.UI.ShowMenuBar},
            {"darkMode", m_Config.UI.DarkMode},
            {"tabIndex", m_Config.UI.TabIndex}
        };

        // Serialize ESP settings
        j["esp"] = {
            {"playerESP", m_Config.ESP.PlayerESP},
            {"boxESP", m_Config.ESP.BoxESP},
            {"nameESP", m_Config.ESP.NameESP},
            {"healthESP", m_Config.ESP.HealthESP},
            {"distanceESP", m_Config.ESP.DistanceESP},
            {"tracers", m_Config.ESP.Tracers},
            {"itemESP", m_Config.ESP.ItemESP},
            {"chestESP", m_Config.ESP.ChestESP},
            {"coinESP", m_Config.ESP.CoinESP},
            {"espDistance", m_Config.ESP.ESPDistance}
        };

        // Serialize script history (limit to max)
        j["scriptHistory"] = json::array();
        size_t count = 0;
        for (auto& entry : m_Config.ScriptHistory) {
            if (++count > m_Config.MaxScriptHistory) break;
            j["scriptHistory"].push_back({
                {"name", entry.Name},
                {"content", entry.Content},
                {"category", entry.Category},
                {"enabled", entry.Enabled}
            });
        }

        // Serialize saved scripts
        j["savedScripts"] = json::array();
        for (auto& entry : m_Config.SavedScripts) {
            j["savedScripts"].push_back({
                {"name", entry.Name},
                {"content", entry.Content},
                {"category", entry.Category},
                {"enabled", entry.Enabled}
            });
        }

        // Serialize hotkeys
        j["hotkeys"] = m_Config.Hotkeys;
        j["lastSelectedScript"] = m_Config.LastSelectedScript;
        j["maxScriptHistory"] = m_Config.MaxScriptHistory;

        // Write to file
        auto path = GetConfigPath();
        std::ofstream file(path);
        if (!file.is_open()) {
            LOG_ERROR("Failed to create config file");
            return false;
        }

        file << j.dump(4);
        file.close();

        LOG_INFO("Config saved successfully");
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Config save failed: %s", e.what());
        return false;
    }
}

void ConfigManager::AddToHistory(const std::string& name, const std::string& content) {
    ScriptEntry entry;
    entry.Name = name;
    entry.Content = content;
    entry.Category = "History";
    entry.LastUsed = std::chrono::system_clock::now();

    // Remove duplicates
    auto it = std::remove_if(m_Config.ScriptHistory.begin(), m_Config.ScriptHistory.end(),
        [&name](const ScriptEntry& e) { return e.Name == name; });
    m_Config.ScriptHistory.erase(it, m_Config.ScriptHistory.end());

    // Add to front
    m_Config.ScriptHistory.insert(m_Config.ScriptHistory.begin(), entry);

    // Trim to max size
    while (m_Config.ScriptHistory.size() > m_Config.MaxScriptHistory) {
        m_Config.ScriptHistory.pop_back();
    }
}

void ConfigManager::SaveScript(const std::string& name, const std::string& content, const std::string& category) {
    ScriptEntry entry;
    entry.Name = name;
    entry.Content = content;
    entry.Category = category;
    entry.LastUsed = std::chrono::system_clock::now();

    // Check if exists
    auto it = std::find_if(m_Config.SavedScripts.begin(), m_Config.SavedScripts.end(),
        [&name](const ScriptEntry& e) { return e.Name == name; });

    if (it != m_Config.SavedScripts.end()) {
        *it = entry;
    } else {
        m_Config.SavedScripts.push_back(entry);
    }
}

void ConfigManager::RemoveScript(size_t index) {
    if (index < m_Config.SavedScripts.size()) {
        m_Config.SavedScripts.erase(m_Config.SavedScripts.begin() + index);
    }
}

} // namespace Core