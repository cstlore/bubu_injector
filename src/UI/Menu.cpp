#include "UI/Menu.h"
#include "UI/ImGuiRenderer.h"
#include "Executor/ScriptEngine.h"
#include "Core/Config.h"
#include "Core/Globals.h"

namespace UI {

Menu& Menu::Get() {
    static Menu instance{};
    return instance;
}

Menu::Menu() : m_Editor() {}

void Menu::Render() {
    if (!m_IsOpen) return;

    ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(100, 100), ImGuiCond_FirstUseEver);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("##ExecutorMenu", &m_IsOpen, flags);

    // Custom title bar
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 4));
    if (ImGui::BeginTabBar("##MainTabs", ImGuiTabBarFlags_None)) {
        if (ImGui::BeginTabItem("Execute")) {
            RenderExecuteTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Script Hub")) {
            RenderScriptHubTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Settings")) {
            RenderSettingsTab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("About")) {
            RenderAboutTab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::PopStyleVar();

    ImGui::End();
}

void Menu::RenderExecuteTab() {
    ImGui::Columns(2, "##ExecuteLayout", true);

    // Left column - Editor
    ImGui::BeginChild("##EditorPanel", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() - 10));

    ImGui::Text("Script Editor");
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        m_Editor.SetContent("");
    }
    ImGui::SameLine();
    if (ImGui::Button("Load")) {
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
                m_Editor.SetContent(buffer.str());
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
                file << m_Editor.GetContent();
            }
        }
    }

    ImGui::Separator();

    // Editor area
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 4));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

    ImGuiInputTextFlags flags = ImGuiInputTextFlags_AllowTabInput |
        ImGuiInputTextFlags_CtrlEnterForNewLine;
    if (m_Editor.IsReadOnly()) {
        flags |= ImGuiInputTextFlags_ReadOnly;
    }

    ImGui::InputTextMultiline("##ScriptEditor", m_Editor.GetContent().data(),
        m_Editor.GetContent().capacity() + 1,
        ImVec2(-1, -1), flags);

    ImGui::PopStyleVar(2);

    ImGui::EndChild();

    ImGui::NextColumn();

    // Right column - Console
    ImGui::BeginChild("##ConsolePanel");

    ImGui::Text("Console Output");
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        m_Console.Clear();
    }

    ImGui::Separator();

    ImGui::EndChild();

    ImGui::NextColumn();

    ImGui::BeginChild("##BottomBar", ImVec2(0, 0), false);

    // Status bar
    ImGui::Separator();

    auto& engine = Executor::ScriptEngine::Get();
    ImGui::Text("Status: %s | Scripts: %zu",
        engine.IsInitialized() ? "Ready" : "Not Initialized",
        engine.GetScripts().size());

    ImGui::SameLine(ImGui::GetWindowWidth() - 100);

    // Execute button
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 120);
    if (ImGui::Button("Execute", ImVec2(100, 0))) {
        auto result = engine.Execute(m_Editor.GetContent(), "User Script");
        if (result.Success) {
            m_Console.AddSuccess("Script executed successfully");
        } else {
            m_Console.AddError(result.Error);
        }
    }

    ImGui::EndChild();
}

void Menu::RenderScriptHubTab() {
    static ScriptHub hub;
    if (hub.GetEntries().empty()) {
        hub.LoadDefaultScripts();
    }

    ImGui::Columns(2, "##ScriptHubLayout", true);

    // Left - Script list
    ImGui::BeginChild("##ScriptList");

    ImGui::Text("Scripts");
    ImGui::SameLine();
    ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 100);
    ImGui::PushItemWidth(100);
    ImGui::InputText("##Search", &hub.GetEntries()[0].Name); // Placeholder
    ImGui::PopItemWidth();

    ImGui::Separator();

    for (const auto& entry : hub.GetEntries()) {
        bool selected = false;
        ImGui::Selectable(entry.Name.c_str(), &selected);

        if (ImGui::IsItemClicked()) {
            m_Editor.SetContent(entry.Script);
        }

        ImGui::SameLine();
        ImGui::TextDisabled(" | %s", entry.Category.c_str());
    }

    ImGui::EndChild();

    ImGui::NextColumn();

    // Right - Script details
    ImGui::BeginChild("##ScriptDetails");

    ImGui::Text("Script Details");
    ImGui::Separator();

    ImGui::BeginChild("##PreviewArea");
    ImGui::TextWrapped("%s", m_Editor.GetContent().c_str());
    ImGui::EndChild();

    if (ImGui::Button("Execute Script", ImVec2(-1, 0))) {
        auto result = Executor::ScriptEngine::Get().Execute(m_Editor.GetContent());
        if (result.Success) {
            m_Console.AddSuccess("Script executed");
        } else {
            m_Console.AddError(result.Error);
        }
    }

    ImGui::EndChild();
}

void Menu::RenderSettingsTab() {
    auto& config = Core::ConfigManager::Get();

    if (ImGui::CollapsingHeader("Execution", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Auto Attach", &config.Execution().AutoAttach);
        ImGui::Checkbox("Show Console", &config.Execution().ShowConsole);
        ImGui::Checkbox("Context Bypass", &config.Execution().EnableContextBypass);
        ImGui::Checkbox("FireClicks Bypass", &config.Execution().EnableFireClicks);
        ImGui::Checkbox("Teleport Bypass", &config.Execution().EnableTPBypass);

        ImGui::Separator();

        ImGui::Text("Identity Level:");
        ImGui::SliderInt("##Identity", &config.Execution().IdentityLevel, 0, 7, "%d");

        if (ImGui::Button("Apply Identity")) {
            Executor::LuaContext::Roblox::SetIdentity(config.Execution().IdentityLevel);
        }
    }

    if (ImGui::CollapsingHeader("UI", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Show FPS", &config.UI().ShowFPS);
        ImGui::Checkbox("Show Menu Bar", &config.UI().ShowMenuBar);
        ImGui::Checkbox("Dark Mode", &config.UI().DarkMode);

        ImGui::Separator();

        ImGui::Text("Theme:");
        if (ImGui::Button("Dark")) { Style::ApplyDarkTheme(); }
        ImGui::SameLine();
        if (ImGui::Button("Cyberpunk")) { Style::Colors::Cyberpunk(); }
        ImGui::SameLine();
        if (ImGui::Button("Nord")) { Style::Colors::Nord(); }
        ImGui::SameLine();
        if (ImGui::Button("Dracula")) { Style::Colors::Dracula(); }
    }

    if (ImGui::CollapsingHeader("ESP", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Checkbox("Player ESP", &config.ESP().PlayerESP);
        ImGui::Checkbox("Box ESP", &config.ESP().BoxESP);
        ImGui::Checkbox("Name ESP", &config.ESP().NameESP);
        ImGui::Checkbox("Health ESP", &config.ESP().HealthESP);
        ImGui::Checkbox("Distance ESP", &config.ESP().DistanceESP);
        ImGui::Checkbox("Tracers", &config.ESP().Tracers);
        ImGui::Checkbox("Item ESP", &config.ESP().ItemESP);
        ImGui::Checkbox("Chest ESP", &config.ESP().ChestESP);
        ImGui::Checkbox("Coin ESP", &config.ESP().CoinESP);

        ImGui::Separator();

        ImGui::Text("ESP Distance:");
        ImGui::SliderFloat("##ESPDistance", &config.ESP().ESPDistance, 50.0f, 1000.0f, "%.0f studs");

        ImGui::Text("ESP Color:");
        ImGui::ColorEdit4("##ESPColor", &config.ESP().ESPColor.x);
    }

    ImGui::Separator();

    if (ImGui::Button("Save Settings", ImVec2(-1, 0))) {
        config.Save();
        m_Console.AddSuccess("Settings saved");
    }
}

void Menu::RenderAboutTab() {
    ImGui::Text("ENI Executor");
    ImGui::Text("Version: %s", EXECUTOR_VERSION);
    ImGui::Text("Build Date: %s", EXECUTOR_BUILD_DATE);

    ImGui::Separator();

    ImGui::TextWrapped(
        "A modern Roblox executor with advanced bypass capabilities.\n\n"
        "Features:\n"
        "- Manual mapping DLL injection\n"
        "- Lua C API execution\n"
        "- Identity spoofing\n"
        "- Full context bypass\n"
        "- Real-time ESP\n"
        "- Script hub\n"
        "- DirectX 11 overlay\n"
        "- Hotkey support"
    );

    ImGui::Separator();

    ImGui::Text("Controls:");
    ImGui::BulletText("F1 - Toggle Menu");
    ImGui::BulletText("Ctrl+S - Save Script");
    ImGui::BulletText("Ctrl+O - Open Script");
    ImGui::BulletText("Ctrl+Enter - Execute");

    ImGui::Separator();

    if (!Core::Globals().Is64Bit()) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 1.0f), "Warning: Running in 32-bit mode");
    } else {
        ImGui::TextColored(ImVec4(0.5f, 1.0f, 0.5f, 1.0f), "64-bit process detected");
    }
}

// ScriptHub implementation
ScriptHub::ScriptHub() {
    LoadDefaultScripts();
}

void ScriptHub::LoadDefaultScripts() {
    // Infinite Yield
    m_Entries.push_back({
        "Infinite Yield",
        "Full-featured admin commands",
        "Admin",
        R"lua(
-- Infinite Yield
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local CV = game:GetService("CoreGui")

local function getRoot(char)
    local rootPart = char:FindFirstChild("HumanoidRootPart")
    if rootPart then return rootPart end
    return char.PrimaryPart or char:FindFirstChildWhichIsA("BasePart")
end

local commands = {
    ["goto"] = function(args)
        local target = Players:FindFirstChild(args[1])
        if target and target.Character then
            local root = getRoot(target.Character)
            local myRoot = getRoot(LP.Character)
            if root and myRoot then
                myRoot.CFrame = root.CFrame
            end
        end
    end,
    ["tp"] = function(args)
        commands["goto"](args)
    end,
    ["fly"] = function()
        local myRoot = getRoot(LP.Character)
        if myRoot then
            local bodyVel = myRoot:FindFirstChild("BodyVelocity")
            if not bodyVel then
                bodyVel = Instance.new("BodyVelocity")
                bodyVel.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
                bodyVel.Velocity = Vector3.new(0, 0, 0)
                bodyVel.Parent = myRoot
            end
        end
    end,
    ["unfly"] = function()
        local myRoot = getRoot(LP.Character)
        if myRoot then
            local bodyVel = myRoot:FindFirstChild("BodyVelocity")
            if bodyVel then bodyVel:Destroy() end
        end
    end,
    ["speed"] = function(args)
        local char = LP.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.WalkSpeed = tonumber(args[1]) or 16
        end
    end,
    ["ws"] = function(args)
        commands["speed"](args)
    end,
    ["jumppower"] = function(args)
        local char = LP.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.JumpPower = tonumber(args[1]) or 50
        end
    end,
    ["jp"] = function(args)
        commands["jumppower"](args)
    end,
    ["noclip"] = function()
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then
                    part.CanCollide = false
                end
            end
        end
    end,
    ["clip"] = function()
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then
                    part.CanCollide = true
                end
            end
        end
    end,
}

-- Chat command detection
Players.PlayerAdded:Connect(function(player)
    player.Chatted:Connect(function(msg)
        if player == LP then
            local parts = string.split(msg, " ")
            local cmd = parts[1]:lower()
            local args = {}
            for i = 2, #parts do
                table.insert(args, parts[i])
            end
            if commands[cmd] then
                commands[cmd](args)
            end
        end
    end)
end)

print("Infinite Yield loaded!")
)lua"
    });

    // Remote Spy
    m_Entries.push_back({
        "Remote Spy",
        "View remote function calls",
        "Debug",
        R"lua(
-- Simple Remote Spy
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local CV = game:GetService("CoreGui")

local spying = false
local remoteFolder = Instance.new("Folder")
remoteFolder.Name = "RemoteSpy"

local function logRemote(parent, name, remote)
    spawn(function()
        if remote:IsA("RemoteFunction") then
            remote.OnClientInvoke = function(...)
                if spying then
                    print("[RemoteFunction] " .. parent:GetFullName() .. ":" .. name)
                    print("  Args:", ...)
                end
                return nil
            end
        elseif remote:IsA("RemoteEvent") then
            remote.OnClientEvent:Connect(function(...)
                if spying then
                    print("[RemoteEvent] " .. parent:GetFullName() .. ":" .. name)
                    print("  Args:", ...)
                end
            end)
        end
    end)
end

local function scanRemotes(parent)
    for _, child in pairs(parent:GetChildren()) do
        if child:IsA("RemoteFunction") or child:IsA("RemoteEvent") then
            logRemote(parent, child.Name, child)
        elseif child ~= remoteFolder then
            scanRemotes(child)
        end
    end
    parent.ChildAdded:Connect(function(child)
        if child:IsA("RemoteFunction") or child:IsA("RemoteEvent") then
            logRemote(parent, child.Name, child)
        end
    end)
end

local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "RemoteSpyUI"
ScreenGui.Parent = CV

local Toggle = Instance.new("TextButton")
Toggle.Name = "Toggle"
Toggle.Size = UDim2.new(0, 100, 0, 30)
Toggle.Position = UDim2.new(0, 10, 0, 10)
Toggle.Text = "Spy: OFF"
Toggle.Parent = ScreenGui

Toggle.MouseButton1Click:Connect(function()
    spying = not spying
    Toggle.Text = spying and "Spy: ON" or "Spy: OFF"
    Toggle.BackgroundColor3 = spying and Color3.fromRGB(0, 200, 0) or Color3.fromRGB(200, 0, 0)
end)

scanRemotes(ReplicatedStorage)
print("Remote Spy loaded! Click the button to toggle.")
)lua"
    });

    // Simple ESP
    m_Entries.push_back({
        "Player ESP",
        "Basic player ESP with boxes and names",
        "Visual",
        R"lua(
-- Player ESP
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local RunService = game:GetService("RunService")
local CV = game:GetService("CoreGui")

local ESPFolder = Instance.new("Folder")
ESPFolder.Name = "ESPFolder"
ESPFolder.Parent = CV

local function createESP(player)
    if player == LP then return end
    if not player.Character then return end

    local highlight = Instance.new("Highlight")
    highlight.Name = player.Name .. "_ESP"
    highlight.FillColor = Color3.fromRGB(0, 255, 0)
    highlight.OutlineColor = Color3.fromRGB(255, 255, 255)
    highlight.FillTransparency = 0.5
    highlight.OutlineTransparency = 0
    highlight.Parent = ESPFolder

    local function update()
        if player.Character then
            highlight.Adornee = player.Character
        else
            highlight.Adornee = nil
        end
    end

    player.CharacterAdded:Connect(function(char)
        char:WaitForChild("HumanoidRootPart")
        update()
    end)

    update()
end

local function removeESP(player)
    local esp = ESPFolder:FindFirstChild(player.Name .. "_ESP")
    if esp then esp:Destroy() end
end

Players.PlayerAdded:Connect(createESP)
Players.PlayerRemoving:Connect(removeESP)

for _, player in pairs(Players:GetPlayers()) do
    createESP(player)
end

print("Player ESP loaded!")
)lua"
    });

    // Admin GUI
    m_Entries.push_back({
        "Admin GUI",
        "Visual admin panel",
        "Admin",
        R"lua(
-- Admin GUI
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local CV = game:GetService("CoreGui")
local TweenService = game:GetService("TweenService")

local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "AdminGUI"
ScreenGui.ResetOnSpawn = false
ScreenGui.Parent = CV

local MainFrame = Instance.new("Frame")
MainFrame.Name = "MainFrame"
MainFrame.Size = UDim2.new(0, 300, 0, 400)
MainFrame.Position = UDim2.new(0.5, -150, 0.5, -200)
MainFrame.BackgroundColor3 = Color3.fromRGB(30, 30, 40)
MainFrame.BorderSizePixel = 0
MainFrame.Parent = ScreenGui

local Corner = Instance.new("UICorner")
Corner.CornerRadius = UDim.new(0, 8)
Corner.Parent = MainFrame

local Title = Instance.new("TextLabel")
Title.Name = "Title"
Title.Size = UDim2.new(1, 0, 0, 40)
Title.BackgroundColor3 = Color3.fromRGB(20, 20, 30)
Title.Text = "Admin Panel"
Title.TextColor3 = Color3.fromRGB(255, 255, 255)
Title.TextSize = 18
Title.Font = Enum.Font.GothamBold
Title.Parent = MainFrame

local function getRoot()
    local char = LP.Character
    if char then
        return char:FindFirstChild("HumanoidRootPart") or char.PrimaryPart
    end
end

local actions = {
    {"Fly", function()
        local root = getRoot()
        if root then
            local vel = root:FindFirstChild("BV") or Instance.new("BodyVelocity")
            vel.Name = "BV"
            vel.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
            vel.Velocity = Vector3.new(0, 0, 0)
            vel.Parent = root
        end
    end},
    {"Unfly", function()
        local root = getRoot()
        if root then
            local vel = root:FindFirstChild("BV")
            if vel then vel:Destroy() end
        end
    end},
    {"Noclip", function()
        local char = LP.Character
        if char then
            for _, p in pairs(char:GetDescendants()) do
                if p:IsA("BasePart") then
                    p.CanCollide = false
                end
            end
        end
    end},
    {"Teleport to HQ", function()
        local root = getRoot()
        if root then
            root.CFrame = CFrame.new(-75.5, 2.9, 85.5)
        end
    end},
    {"God Mode", function()
        local char = LP.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.MaxHealth = math.huge
            char.Humanoid.Health = math.huge
        end
    end}
}

local y = 50
for _, action in pairs(actions) do
    local btn = Instance.new("TextButton")
    btn.Name = action[1]
    btn.Size = UDim2.new(0.9, 0, 0, 35)
    btn.Position = UDim2.new(0.05, 0, 0, y)
    btn.BackgroundColor3 = Color3.fromRGB(50, 50, 70)
    btn.Text = action[1]
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.TextSize = 14
    btn.Font = Enum.Font.Gotham
    btn.Parent = MainFrame

    local btnCorner = Instance.new("UICorner")
    btnCorner.CornerRadius = UDim.new(0, 4)
    btnCorner.Parent = btn

    btn.MouseButton1Click:Connect(action[2])

    y = y + 45
end

print("Admin GUI loaded!")
)lua"
    });

    // Anti-AFK
    m_Entries.push_back({
        "Anti-AFK",
        "Prevents being kicked for inactivity",
        "Utility",
        R"lua(
-- Anti-AFK
local VirtualUser = game:GetService("VirtualUser")
local Players = game:GetService("Players")
local LP = Players.LocalPlayer

LP.Idled:Connect(function()
    VirtualUser:CaptureController()
    VirtualUser:ClickButton2(Vector2.new())
end)

-- Also patch the idle kick
local PlayerScripts = LP:WaitForChild("PlayerScripts")
local CoreScripts = PlayerScripts:WaitForChild("CoreScripts")

-- Disable idle timer
task.spawn(function()
    while true do
        task.wait(30)
        if LP and LP.Parent then
            -- Re-capture to prevent AFK
            VirtualUser:CaptureController()
        end
    end
end)

print("Anti-AFK activated!")
)lua"
    });
}

void ScriptHub::AddEntry(const ScriptHubEntry& entry) {
    m_Entries.push_back(entry);
}

void ScriptHub::RemoveEntry(const std::string& name) {
    m_Entries.erase(
        std::remove_if(m_Entries.begin(), m_Entries.end(),
            [&name](const ScriptHubEntry& e) { return e.Name == name; }),
        m_Entries.end()
    );
}

void ScriptHub::ToggleScript(const std::string& name) {
    for (auto& entry : m_Entries) {
        if (entry.Name == name) {
            entry.Enabled = !entry.Enabled;
            if (entry.Enabled) {
                Executor::ScriptEngine::Get().Execute(entry.Script, entry.Name);
            }
            break;
        }
    }
}

bool ScriptHub::IsScriptEnabled(const std::string& name) const {
    for (const auto& entry : m_Entries) {
        if (entry.Name == name) {
            return entry.Enabled;
        }
    }
    return false;
}

std::vector<std::string> ScriptHub::GetCategories() const {
    std::vector<std::string> categories;
    std::unordered_set<std::string> seen;

    for (const auto& entry : m_Entries) {
        if (seen.find(entry.Category) == seen.end()) {
            seen.insert(entry.Category);
            categories.push_back(entry.Category);
        }
    }

    return categories;
}

void ScriptHub::SetCategoryFilter(const std::string& category) {
    m_CategoryFilter = category;
}

// SettingsPanel implementation
SettingsPanel::SettingsPanel() {}

void SettingsPanel::Render() {
    ImGui::Columns(2, "##SettingsLayout", true);

    ImGui::BeginChild("##SettingsNav");
    ImGui::Text("Settings");

    const char* pages[] = {"General", "Execution", "UI", "Hotkeys", "ESP"};
    for (int i = 0; i < 5; i++) {
        if (ImGui::Selectable(pages[i], m_SelectedPage == i)) {
            m_SelectedPage = i;
        }
    }

    ImGui::EndChild();

    ImGui::NextColumn();

    ImGui::BeginChild("##SettingsContent");
    switch (m_SelectedPage) {
        case 0: RenderGeneralSettings(); break;
        case 1: RenderExecutionSettings(); break;
        case 2: RenderUISettings(); break;
        case 3: RenderHotkeySettings(); break;
        case 4: RenderESPSettings(); break;
    }
    ImGui::EndChild();
}

void SettingsPanel::RenderGeneralSettings() {
    ImGui::Text("General Settings");

    auto& config = Core::ConfigManager::Get();

    ImGui::Separator();

    if (ImGui::Button("Attach to Roblox")) {
        Core::AttachToRoblox();
    }

    ImGui::SameLine();

    if (ImGui::Button("Initialize Executor")) {
        Executor::ScriptEngine::Get().Initialize();
    }

    ImGui::Separator();

    ImGui::Text("Status:");
    ImGui::Text("  Process: %s", Core::Globals().Handle ? "Attached" : "Not Attached");
    ImGui::Text("  Engine: %s", Executor::ScriptEngine::Get().IsInitialized() ? "Ready" : "Not Ready");
}

void SettingsPanel::RenderExecutionSettings() {
    ImGui::Text("Execution Settings");

    auto& exec = Core::ConfigManager::Get().Execution();

    ImGui::Separator();

    ImGui::Checkbox("Auto Attach", &exec.AutoAttach);
    ImGui::Checkbox("Show Console", &exec.ShowConsole);
    ImGui::Checkbox("Context Bypass", &exec.EnableContextBypass);
    ImGui::Checkbox("FireClicks Bypass", &exec.EnableFireClicks);
    ImGui::Checkbox("Teleport Bypass", &exec.EnableTPBypass);

    ImGui::Separator();

    ImGui::Text("Identity Level:");
    ImGui::SliderInt("##Identity", &exec.IdentityLevel, 0, 7, "%d");

    if (ImGui::Button("Apply")) {
        Executor::LuaContext::Roblox::SetIdentity(exec.IdentityLevel);
    }
}

void SettingsPanel::RenderUISettings() {
    ImGui::Text("UI Settings");

    auto& ui = Core::ConfigManager::Get().UI();

    ImGui::Separator();

    ImGui::Checkbox("Show FPS", &ui.ShowFPS);
    ImGui::Checkbox("Show Menu Bar", &ui.ShowMenuBar);
    ImGui::Checkbox("Dark Mode", &ui.DarkMode);

    ImGui::Separator();

    ImGui::Text("Theme:");
    if (ImGui::Button("Dark")) Style::ApplyDarkTheme();
    ImGui::SameLine();
    if (ImGui::Button("Cyberpunk")) Style::Colors::Cyberpunk();
    ImGui::SameLine();
    if (ImGui::Button("Nord")) Style::Colors::Nord();

    ImGui::Separator();

    ImGui::Text("Menu Colors:");
    ImGui::ColorEdit4("Accent", &ui.AccentColor.x);
    ImGui::ColorEdit4("Background", &ui.MenuColor.x);
}

void SettingsPanel::RenderHotkeySettings() {
    ImGui::Text("Hotkey Settings");

    ImGui::Separator();

    ImGui::Text("F1 - Toggle Menu");
    ImGui::Text("Ctrl+S - Save Script");
    ImGui::Text("Ctrl+O - Open Script");
    ImGui::Text("Ctrl+Enter - Execute Script");
}

void SettingsPanel::RenderESPSettings() {
    ImGui::Text("ESP Settings");

    auto& esp = Core::ConfigManager::Get().ESP();

    ImGui::Separator();

    ImGui::Checkbox("Player ESP", &esp.PlayerESP);
    ImGui::Checkbox("Box ESP", &esp.BoxESP);
    ImGui::Checkbox("Name ESP", &esp.NameESP);
    ImGui::Checkbox("Health ESP", &esp.HealthESP);
    ImGui::Checkbox("Distance ESP", &esp.DistanceESP);
    ImGui::Checkbox("Tracers", &esp.Tracers);

    ImGui::Separator();

    ImGui::Checkbox("Item ESP", &esp.ItemESP);
    ImGui::Checkbox("Chest ESP", &esp.ChestESP);
    ImGui::Checkbox("Coin ESP", &esp.CoinESP);

    ImGui::Separator();

    ImGui::Text("ESP Distance:");
    ImGui::SliderFloat("##ESPDistance", &esp.ESPDistance, 50.0f, 1000.0f, "%.0f");

    ImGui::Text("ESP Color:");
    ImGui::ColorEdit4("##ESPColor", &esp.ESPColor.x);
}

} // namespace UI