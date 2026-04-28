#pragma once

#include "../pch.h"

namespace ScriptHub {

// Pre-built script entries
struct ScriptEntry {
    std::string Name;
    std::string Description;
    std::string Category;
    std::string Content;
    bool Enabled = false;
};

// Script hub manager
class ScriptHubManager {
public:
    static ScriptHubManager& Get();

    void Initialize();
    void Shutdown();

    // Script management
    const std::vector<ScriptEntry>& GetScripts() const { return m_Scripts; }
    void AddScript(const ScriptEntry& entry);
    void RemoveScript(const std::string& name);
    void ExecuteScript(const std::string& name);
    void ToggleScript(const std::string& name);

    // Categories
    std::vector<std::string> GetCategories() const;
    void FilterByCategory(const std::string& category);
    std::string GetCurrentFilter() const { return m_CurrentFilter; }

    // Search
    void SetSearchQuery(const std::string& query) { m_SearchQuery = query; }
    std::string GetSearchQuery() const { return m_SearchQuery; }
    std::vector<ScriptEntry> GetFilteredScripts() const;

    // Bulk operations
    void EnableAll();
    void DisableAll();

private:
    ScriptHubManager() = default;
    void LoadDefaultScripts();

    std::vector<ScriptEntry> m_Scripts;
    std::string m_CurrentFilter;
    std::string m_SearchQuery;
};

// Helper to get script content by name
std::string GetScriptContent(const std::string& name);

} // namespace ScriptHub