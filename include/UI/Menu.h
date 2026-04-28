#pragma once

#include "../pch.h"
#include "ScriptEditor.h"
#include "ESP.h"

namespace UI {

// Tab identifiers
enum class MenuTab {
    Execute,
    ScriptHub,
    Settings,
    About
};

// Main menu renderer
class Menu {
public:
    static Menu& Get();

    void Render();
    void RenderExecuteTab();
    void RenderScriptHubTab();
    void RenderSettingsTab();
    void RenderAboutTab();

    // Tab control
    void SetActiveTab(MenuTab tab);
    MenuTab GetActiveTab() const { return m_ActiveTab; }
    void NextTab();
    void PrevTab();

    // Window state
    bool IsOpen() const { return m_IsOpen; }
    void Open() { m_IsOpen = true; }
    void Close() { m_IsOpen = false; }
    void Toggle() { m_IsOpen = !m_IsOpen; }

    // Console
    Executor::ScriptEngine::ConsoleWidget& GetConsole() { return m_Console; }

private:
    Menu();
    Menu(const Menu&) = delete;
    Menu& operator=(const Menu&) = delete;

    MenuTab m_ActiveTab = MenuTab::Execute;
    bool m_IsOpen = true;

    // Child components
    Executor::ScriptEngine::ScriptEditor m_Editor;
    Executor::ScriptEngine::ConsoleWidget m_Console;

    // UI state
    ImVec2 m_WindowPos;
    ImVec2 m_WindowSize;
    bool m_Initialized = false;
};

// Script hub entry
struct ScriptHubEntry {
    std::string Name;
    std::string Description;
    std::string Category;
    std::string Script;
    bool Enabled = false;
    bool Favorite = false;
};

// Script hub manager
class ScriptHub {
public:
    ScriptHub();

    void Render();
    void LoadDefaultScripts();

    const std::vector<ScriptHubEntry>& GetEntries() const { return m_Entries; }
    void AddEntry(const ScriptHubEntry& entry);
    void RemoveEntry(const std::string& name);
    void ToggleScript(const std::string& name);
    bool IsScriptEnabled(const std::string& name) const;

    // Categories
    std::vector<std::string> GetCategories() const;
    void SetCategoryFilter(const std::string& category);
    std::string GetCategoryFilter() const { return m_CategoryFilter; }

private:
    std::vector<ScriptHubEntry> m_Entries;
    std::string m_CategoryFilter;
    std::string m_SearchQuery;
};

// Settings panel
class SettingsPanel {
public:
    SettingsPanel();

    void Render();

    // Individual setting pages
    void RenderGeneralSettings();
    void RenderExecutionSettings();
    void RenderUISettings();
    void RenderHotkeySettings();
    void RenderESPSettings();

private:
    int m_SelectedPage = 0;
};

} // namespace UI