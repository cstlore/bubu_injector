#pragma once

#include "../pch.h"
#include "LuaContext.h"

namespace Executor {

// High-level script management and execution
class ScriptEngine {
public:
    static ScriptEngine& Get();

    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_Initialized; }

    // Execution methods
    struct ScriptResult {
        bool Success;
        std::string Output;
        std::string Error;
        i64 ExecutionTime = 0; // milliseconds

        explicit operator bool() const { return Success; }
    };

    ScriptResult Execute(const std::string& source, const std::string& name = "unnamed");
    ScriptResult ExecuteFile(const std::string& path);
    ScriptResult ExecuteWithResult(const std::string& source);

    // Script lifecycle
    void AddScript(const std::string& name, const std::string& source);
    void RemoveScript(const std::string& name);
    void EnableScript(const std::string& name, bool enable);
    bool IsScriptEnabled(const std::string& name) const;

    // Bulk operations
    void EnableAllScripts();
    void DisableAllScripts();
    void TickEnabledScripts();

    // Output capture
    using OutputCallback = std::function<void(const std::string&)>;
    void SetOutputCallback(OutputCallback callback);

    // Console output (hook into Roblox print)
    void Print(const std::string& message);
    void PrintError(const std::string& error);
    void ClearOutput();

    // Script management
    struct Script {
        std::string Name;
        std::string Source;
        bool Enabled = false;
        bool Loop = false;
        std::chrono::system_clock::time_point LastExecute;
        int ExecuteCount = 0;
    };

    const std::unordered_map<std::string, Script>& GetScripts() const { return m_Scripts; }

private:
    ScriptEngine() = default;
    ScriptEngine(const ScriptEngine&) = delete;
    ScriptEngine& operator=(const ScriptEngine&) = delete;

    bool m_Initialized = false;
    std::unordered_map<std::string, Script> m_Scripts;
    std::vector<std::string> m_OutputBuffer;
    OutputCallback m_OutputCallback;
    std::mutex m_ScriptMutex;
    std::chrono::steady_clock::time_point m_LastTick;
};

// Script editor with syntax highlighting
class ScriptEditor {
public:
    ScriptEditor() = default;

    void Render();

    void SetContent(const std::string& content);
    std::string GetContent() const { return m_Content; }
    std::string& GetContent() { return m_Content; }

    void SetReadOnly(bool readOnly) { m_ReadOnly = readOnly; }
    bool IsReadOnly() const { return m_ReadOnly; }

    void SetLanguage(const std::string& lang) { m_Language = lang; }
    std::string GetLanguage() const { return m_Language; }

    // Line count
    int GetLineCount() const;
    int GetCursorLine() const { return m_CursorLine; }
    int GetCursorColumn() const { return m_CursorColumn; }

    // Undo/Redo
    void Undo();
    void Redo();
    bool CanUndo() const { return !m_UndoStack.empty(); }
    bool CanRedo() const { return !m_RedoStack.empty(); }

private:
    std::string m_Content;
    std::string m_Language = "lua";
    std::vector<std::string> m_UndoStack;
    std::vector<std::string> m_RedoStack;
    int m_CursorLine = 1;
    int m_CursorColumn = 1;
    bool m_ReadOnly = false;

    void PushUndo();
};

// Console widget for output display
class ConsoleWidget {
public:
    ConsoleWidget() = default;

    void Render();

    void AddLine(const std::string& text, ImU32 color = 0);
    void AddError(const std::string& text);
    void AddWarning(const std::string& text);
    void AddSuccess(const std::string& text);
    void Clear();

    bool IsAutoScroll() const { return m_AutoScroll; }
    void SetAutoScroll(bool enable) { m_AutoScroll = enable; }

    int GetLineCount() const { return static_cast<int>(m_Lines.size()); }

    enum class Level { Info, Warning, Error, Success };
    struct LogLine {
        std::string Text;
        Level Level;
        std::chrono::system_clock::time_point Timestamp;
    };

private:
    std::vector<LogLine> m_Lines;
    bool m_AutoScroll = true;
    bool m_ClearOnExecute = false;
};

} // namespace Executor