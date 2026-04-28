#pragma once

#include "../pch.h"

namespace Executor {

// Script editor with basic syntax highlighting
class ScriptEditor {
public:
    ScriptEditor() : m_Content(""), m_Language("lua"), m_ReadOnly(false),
        m_CursorLine(1), m_CursorColumn(1) {}

    void Render();

    void SetContent(const std::string& content);
    std::string GetContent() const { return m_Content; }
    std::string& GetContent() { return m_Content; }
    void SetReadOnly(bool readOnly) { m_ReadOnly = readOnly; }
    bool IsReadOnly() const { return m_ReadOnly; }
    void SetLanguage(const std::string& lang) { m_Language = lang; }
    std::string GetLanguage() const { return m_Language; }

    int GetLineCount() const {
        return static_cast<int>(std::count(m_Content.begin(), m_Content.end(), '\n')) + 1;
    }
    int GetCursorLine() const { return m_CursorLine; }
    int GetCursorColumn() const { return m_CursorColumn; }

    void Undo();
    void Redo();
    bool CanUndo() const { return !m_UndoStack.empty(); }
    bool CanRedo() const { return !m_RedoStack.empty(); }

private:
    void PushUndo();
    void RenderToolbar();
    void RenderEditor();
    void RenderSyntaxHighlight();
    void RenderStatusBar();

    std::string m_Content;
    std::string m_Language;
    std::vector<std::string> m_UndoStack;
    std::vector<std::string> m_RedoStack;
    int m_CursorLine;
    int m_CursorColumn;
    bool m_ReadOnly;
};

} // namespace Executor
