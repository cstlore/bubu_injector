#include "pch.h"
#include "UI/ScriptEditor.h"
#include "Executor/ScriptEngine.h"

namespace Executor {

// Script editor with basic syntax highlighting
class ScriptEditor {
public:
    ScriptEditor() : m_Content(""), m_Language("lua"), m_ReadOnly(false),
        m_CursorLine(1), m_CursorColumn(1) {}

    void Render() {
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 4));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

        // Toolbar
        RenderToolbar();

        ImGui::Separator();

        // Editor
        RenderEditor();

        // Status bar
        RenderStatusBar();

        ImGui::PopStyleVar(2);
    }

    void SetContent(const std::string& content) {
        if (content != m_Content) {
            PushUndo();
            m_Content = content;
        }
    }

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

    void Undo() {
        if (!m_UndoStack.empty()) {
            m_RedoStack.push_back(m_Content);
            m_Content = m_UndoStack.back();
            m_UndoStack.pop_back();
        }
    }

    void Redo() {
        if (!m_RedoStack.empty()) {
            m_UndoStack.push_back(m_Content);
            m_Content = m_RedoStack.back();
            m_RedoStack.pop_back();
        }
    }

    bool CanUndo() const { return !m_UndoStack.empty(); }
    bool CanRedo() const { return !m_RedoStack.empty(); }

private:
    void PushUndo() {
        m_UndoStack.push_back(m_Content);
        m_RedoStack.clear();

        const size_t MAX_UNDO = 100;
        while (m_UndoStack.size() > MAX_UNDO) {
            m_UndoStack.erase(m_UndoStack.begin());
        }
    }

    void RenderToolbar() {
        if (ImGui::Button("New")) {
            SetContent("");
        }
        ImGui::SameLine();

        if (ImGui::Button("Open")) {
            OPENFILENAMEA ofn{};
            char path[MAX_PATH] = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.lpstrFilter = "Lua Files\0*.lua\0All Files\0*.*\0";
            ofn.lpstrFile = path;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameA(&ofn)) {
                std::ifstream file(path);
                if (file.is_open()) {
                    std::stringstream buffer;
                    buffer << file.rdbuf();
                    SetContent(buffer.str());
                }
            }
        }
        ImGui::SameLine();

        if (ImGui::Button("Save")) {
            OPENFILENAMEA ofn{};
            char path[MAX_PATH] = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.lpstrFilter = "Lua Files\0*.lua\0All Files\0*.*\0";
            ofn.lpstrFile = path;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_OVERWRITEPROMPT;
            if (GetSaveFileNameA(&ofn)) {
                std::ofstream file(path);
                if (file.is_open()) {
                    file << m_Content;
                }
            }
        }
        ImGui::SameLine();

        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::SameLine();

        if (ImGui::Button("Undo") && CanUndo()) {
            Undo();
        }
        ImGui::SameLine();
        if (ImGui::Button("Redo") && CanRedo()) {
            Redo();
        }
        ImGui::SameLine();

        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::SameLine();

        // Language selector
        const char* langs[] = {"lua", "luau"};
        int current = (m_Language == "luau") ? 1 : 0;
        ImGui::SetNextItemWidth(80);
        if (ImGui::Combo("##Language", &current, langs, 2)) {
            m_Language = langs[current];
        }
    }

    void RenderEditor() {
        ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput |
            ImGuiInputTextFlags_CtrlEnterForNewLine |
            ImGuiInputTextFlags_NoHorizontalScroll;

        if (m_ReadOnly) {
            flags |= ImGuiInputTextFlags_ReadOnly;
        }

        ImGuiStyle& style = ImGui::GetStyle();
        ImVec2 size = ImGui::GetContentRegionAvail();
        size.y -= 24; // Reserve space for status bar

        // Line numbers gutter
        ImGui::BeginGroup();
        {
            ImGui::BeginChild("##LineNumbers", ImVec2(40, 0), false);

            int lineCount = GetLineCount();
            for (int i = 1; i <= lineCount; i++) {
                ImGui::TextColored(ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled), "%d", i);
            }

            ImGui::EndChild();

            ImGui::SameLine();
        }
        ImGui::EndGroup();

        ImGui::SameLine();

        // Main editor
        ImGuiInputTextCallback callback = [](ImGuiInputTextCallbackData* data) -> int {
            auto* editor = static_cast<ScriptEditor*>(data->UserData);

            if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory) {
                // Handle arrow keys for cursor movement
            }
            else if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
                // Filter characters
            }
            else if (data->EventFlag == ImGuiInputTextFlags_CallbackEdit) {
                // Content changed
                std::string newContent(data->Buf, data->BufTextLen);
                editor->SetContent(newContent);
            }

            return 0;
        };

        // Custom input text with highlighting
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 4));
        ImGui::InputTextMultiline("##ScriptEditor", m_Content.data(),
            m_Content.capacity() + 1, size, flags, callback, this);
        ImGui::PopStyleVar();

        // Simple syntax highlighting (basic approach)
        RenderSyntaxHighlight();
    }

    void RenderSyntaxHighlight() {
        // Basic Lua syntax highlighting
        // In a full implementation, this would parse tokens and color them

        struct SyntaxPattern {
            const char* keyword;
            ImU32 color;
        };

        static const SyntaxPattern keywords[] = {
            {"local", ImColor(86, 156, 214)},      // blue
            {"function", ImColor(220, 177, 89)},    // yellow
            {"if", ImColor(220, 177, 89)},
            {"then", ImColor(220, 177, 89)},
            {"else", ImColor(220, 177, 89)},
            {"end", ImColor(220, 177, 89)},
            {"for", ImColor(220, 177, 89)},
            {"while", ImColor(220, 177, 89)},
            {"return", ImColor(220, 177, 89)},
            {"nil", ImColor(171, 178, 191)},        // gray
            {"true", ImColor(86, 156, 214)},
            {"false", ImColor(86, 156, 214)},
            {"and", ImColor(171, 178, 191)},
            {"or", ImColor(171, 178, 191)},
            {"not", ImColor(171, 178, 191)},
        };
    }

    void RenderStatusBar() {
        ImGui::Separator();

        ImGui::Text("Ln %d, Col %d | %s | %s",
            m_CursorLine, m_CursorColumn, m_Language.c_str(),
            m_ReadOnly ? "Read Only" : "Editable");
    }

    std::string m_Content;
    std::string m_Language;
    std::vector<std::string> m_UndoStack;
    std::vector<std::string> m_RedoStack;
    int m_CursorLine;
    int m_CursorColumn;
    bool m_ReadOnly;
};

} // namespace Executor