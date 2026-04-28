#include "pch.h"
#include "Executor/ScriptEngine.h"
#include "Core/Config.h"
#include "Core/Globals.h"
#include "Memory/MemoryManager.h"

namespace Executor {

ScriptEngine& ScriptEngine::Get() {
    static ScriptEngine instance{};
    return instance;
}

bool ScriptEngine::Initialize() {
    if (m_Initialized) return true;

    if (!LuaContext::Get().Initialize()) {
        LOG_ERROR("Failed to initialize Lua context");
        return false;
    }

    m_Initialized = true;
    LOG_INFO("Script engine initialized");
    return true;
}

void ScriptEngine::Shutdown() {
    if (!m_Initialized) return;

    LuaContext::Get().Shutdown();
    m_Scripts.clear();
    m_OutputBuffer.clear();
    m_Initialized = false;
}

ScriptEngine::ScriptResult ScriptEngine::Execute(const std::string& source, const std::string& name) {
    ScriptResult result{};
    auto start = std::chrono::steady_clock::now();

    if (!m_Initialized) {
        result.Error = "Script engine not initialized";
        return result;
    }

    auto& ctx = LuaContext::Get();
    auto& config = Core::ConfigManager::Get();

    // Add to history
    config.AddToHistory(name, source);

    // Print execution start
    std::string output = "[";
    output += name;
    output += "] Executing...";
    Print(output);

    // Execute with current identity level
    auto execResult = ctx.Execute(source, name);

    auto end = std::chrono::steady_clock::now();
    result.ExecutionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (execResult.Success) {
        result.Success = true;

        // Collect output
        for (auto& ret : execResult.Returns) {
            std::visit([&](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, std::string>) {
                    result.Output += arg;
                    result.Output += "\n";
                }
            }, ret);
        }

        std::string successMsg = "[";
        successMsg += name;
        successMsg += "] Completed in ";
        successMsg += std::to_string(result.ExecutionTime);
        successMsg += "ms";
        Print(successMsg);
    } else {
        result.Error = execResult.Error;
        PrintError("Error: " + result.Error);
    }

    return result;
}

ScriptEngine::ScriptResult ScriptEngine::ExecuteFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return {false, {}, "Failed to open file: " + path};
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return Execute(buffer.str(), std::filesystem::path(path).filename().string());
}

ScriptEngine::ScriptResult ScriptEngine::ExecuteWithResult(const std::string& source) {
    ScriptResult result{};
    auto start = std::chrono::steady_clock::now();

    if (!m_Initialized) {
        result.Error = "Script engine not initialized";
        return result;
    }

    auto& ctx = LuaContext::Get();

    // Push a custom print function to capture output
    ctx.PushCFunction(reinterpret_cast<uptr>([](lua_State* L) -> int {
        int n = lua_gettop(L);
        std::string output;
        for (int i = 1; i <= n; i++) {
            if (i > 1) output += "\t";
            output += luaL_tolstring(L, i, nullptr);
        }

        // Store in script engine output
        auto& engine = ScriptEngine::Get();
        engine.Print(output);
        return 0;
    }));

    // Set as global print
    ctx.PushGlobal("_G");
    ctx.PushString("print");
    ctx.PushCFunction(reinterpret_cast<uptr>([](lua_State* L) -> int {
        int n = lua_gettop(L);
        std::string output;
        for (int i = 1; i <= n; i++) {
            if (i > 1) output += "\t";
            output += luaL_tolstring(L, i, nullptr);
        }

        auto& engine = ScriptEngine::Get();
        engine.Print(output);
        return 0;
    }));
    ctx.SetTop(-3);
    ctx.Pop(2);

    auto execResult = ctx.Execute(source);

    auto end = std::chrono::steady_clock::now();
    result.ExecutionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    result.Success = execResult.Success;
    result.Error = execResult.Error;

    // Restore original print function
    ctx.Pop(1);

    return result;
}

void ScriptEngine::AddScript(const std::string& name, const std::string& source) {
    std::lock_guard lock(m_ScriptMutex);
    m_Scripts[name] = Script{name, source, false};
}

void ScriptEngine::RemoveScript(const std::string& name) {
    std::lock_guard lock(m_ScriptMutex);
    m_Scripts.erase(name);
}

void ScriptEngine::EnableScript(const std::string& name, bool enable) {
    std::lock_guard lock(m_ScriptMutex);
    if (auto it = m_Scripts.find(name); it != m_Scripts.end()) {
        it->second.Enabled = enable;
        it->second.LastExecute = std::chrono::system_clock::now();
        if (enable) {
            it->second.ExecuteCount = 0;
        }
    }
}

bool ScriptEngine::IsScriptEnabled(const std::string& name) const {
    if (auto it = m_Scripts.find(name); it != m_Scripts.end()) {
        return it->second.Enabled;
    }
    return false;
}

void ScriptEngine::EnableAllScripts() {
    std::lock_guard lock(m_ScriptMutex);
    for (auto& [name, script] : m_Scripts) {
        script.Enabled = true;
        script.LastExecute = std::chrono::system_clock::now();
    }
}

void ScriptEngine::DisableAllScripts() {
    std::lock_guard lock(m_ScriptMutex);
    for (auto& [name, script] : m_Scripts) {
        script.Enabled = false;
    }
}

void ScriptEngine::TickEnabledScripts() {
    std::lock_guard lock(m_ScriptMutex);

    for (auto& [name, script] : m_Scripts) {
        if (!script.Enabled) continue;

        if (script.Loop) {
            Execute(script.Source, script.Name);
            script.ExecuteCount++;
            script.LastExecute = std::chrono::system_clock::now();
        }
    }
}

void ScriptEngine::SetOutputCallback(OutputCallback callback) {
    m_OutputCallback = std::move(callback);
}

void ScriptEngine::Print(const std::string& message) {
    m_OutputBuffer.push_back(message);
    if (m_OutputCallback) {
        m_OutputCallback(message);
    }
}

void ScriptEngine::PrintError(const std::string& error) {
    std::string msg = "[ERROR] ";
    msg += error;
    m_OutputBuffer.push_back(msg);
    if (m_OutputCallback) {
        m_OutputCallback(msg);
    }
}

void ScriptEngine::ClearOutput() {
    m_OutputBuffer.clear();
}

int ScriptEngine::ScriptEditor::GetLineCount() const {
    return static_cast<int>(std::count(m_Content.begin(), m_Content.end(), '\n')) + 1;
}

void ScriptEngine::ScriptEditor::SetContent(const std::string& content) {
    if (content != m_Content) {
        PushUndo();
        m_Content = content;
    }
}

void ScriptEngine::ScriptEditor::PushUndo() {
    m_UndoStack.push_back(m_Content);
    m_RedoStack.clear();

    // Limit undo stack size
    const size_t MAX_UNDO = 100;
    while (m_UndoStack.size() > MAX_UNDO) {
        m_UndoStack.erase(m_UndoStack.begin());
    }
}

void ScriptEngine::ScriptEditor::Undo() {
    if (!m_UndoStack.empty()) {
        m_RedoStack.push_back(m_Content);
        m_Content = m_UndoStack.back();
        m_UndoStack.pop_back();
    }
}

void ScriptEngine::ScriptEditor::Redo() {
    if (!m_RedoStack.empty()) {
        m_UndoStack.push_back(m_Content);
        m_Content = m_RedoStack.back();
        m_RedoStack.pop_back();
    }
}

// Console Widget Implementation
void ScriptEngine::ConsoleWidget::Render() {
    ImGui::BeginChild("Console", ImVec2(0, 0), true, ImGuiWindowFlags_NoMove);

    // Toolbar
    if (ImGui::Checkbox("Auto-scroll", &m_AutoScroll)) {}
    ImGui::SameLine();
    if (ImGui::Checkbox("Clear on execute", &m_ClearOnExecute)) {}
    ImGui::SameLine();
    if (ImGui::Button("Clear")) Clear();

    ImGui::Separator();

    // Log lines
    ImGui::BeginChild("LogArea", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), false);
    {
        ImGuiListClipper clipper;
        clipper.Begin(GetLineCount());

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                if (i < 0 || i >= static_cast<int>(m_Lines.size())) continue;

                const auto& line = m_Lines[i];

                // Format timestamp
                auto time = std::chrono::system_clock::to_time_t(line.Timestamp);
                tm timeTm{};
                localtime_s(&timeTm, &time);
                char timeStr[9];
                strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &timeTm);

                ImVec4 color;
                switch (line.Level) {
                    case Level::Error: color = ImVec4(1.0f, 0.3f, 0.3f, 1.0f); break;
                    case Level::Warning: color = ImVec4(1.0f, 0.8f, 0.4f, 1.0f); break;
                    case Level::Success: color = ImVec4(0.3f, 1.0f, 0.3f, 1.0f); break;
                    default: color = ImGui::GetStyleColorVec4(ImGuiCol_Text);
                }

                ImGui::TextColored(color, "[%s] %s", timeStr, line.Text.c_str());
            }
        }

        if (m_AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
    }
    ImGui::EndChild();

    ImGui::EndChild();
}

void ScriptEngine::ConsoleWidget::AddLine(const std::string& text, ImU32 color) {
    m_Lines.push_back({text, Level::Info, std::chrono::system_clock::now()});
}

void ScriptEngine::ConsoleWidget::AddError(const std::string& text) {
    m_Lines.push_back({text, Level::Error, std::chrono::system_clock::now()});
}

void ScriptEngine::ConsoleWidget::AddWarning(const std::string& text) {
    m_Lines.push_back({text, Level::Warning, std::chrono::system_clock::now()});
}

void ScriptEngine::ConsoleWidget::AddSuccess(const std::string& text) {
    m_Lines.push_back({text, Level::Success, std::chrono::system_clock::now()});
}

void ScriptEngine::ConsoleWidget::Clear() {
    m_Lines.clear();
}

} // namespace Executor