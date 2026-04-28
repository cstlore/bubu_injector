#include "ScriptHub/ScriptHub.h"
#include "Executor/ScriptEngine.h"
#include "Core/Config.h"

namespace ScriptHub {

ScriptHubManager& ScriptHubManager::Get() {
    static ScriptHubManager instance{};
    return instance;
}

void ScriptHubManager::Initialize() {
    LoadDefaultScripts();
    LOG_INFO("Script hub initialized with %zu scripts", m_Scripts.size());
}

void ScriptHubManager::Shutdown() {
    m_Scripts.clear();
}

void ScriptHubManager::LoadDefaultScripts() {
    m_Scripts = {
        // Admin Scripts
        {
            "Infinite Yield",
            "Full admin command system with fly, speed, teleport, and more",
            "Admin",
            R"lua(
-- Infinite Yield Admin Commands
local Players = game:GetService("Players")
local LP = Players.LocalPlayer

local function getRoot()
    local char = LP.Character
    if char then
        return char:FindFirstChild("HumanoidRootPart") or char.PrimaryPart
    end
end

local function getChar(player)
    return player and player.Character
end

local commands = {
    fly = function(args)
        local root = getRoot()
        if root then
            local fly = root:FindFirstChild("FlyBodyVelocity")
            if fly then return end

            fly = Instance.new("BodyVelocity")
            fly.Name = "FlyBodyVelocity"
            fly.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
            fly.Velocity = Vector3.new(0, 0, 0)
            fly.Parent = root

            local gyroscope = Instance.new("BodyGyro")
            gyroscope.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
            gyroscope.P = 9e4
            gyroscope.Parent = root
        end
    end,
    unfly = function(args)
        local root = getRoot()
        if root then
            for _, child in pairs(root:GetChildren()) do
                if child.Name == "FlyBodyVelocity" or child:IsA("BodyGyro") then
                    child:Destroy()
                end
            end
        end
    end,
    speed = function(args)
        local speed = tonumber(args[1]) or 16
        local char = LP.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.WalkSpeed = speed
        end
    end,
    goto = function(args)
        local target = args[1]
        if not target then return end

        local player = Players:FindFirstChild(target)
        if player and player ~= LP then
            local targetRoot = getRoot(player.Character)
            local myRoot = getRoot()
            if targetRoot and myRoot then
                myRoot.CFrame = targetRoot.CFrame * CFrame.new(0, 0, 3)
            end
        end
    end,
    noclip = function(args)
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then
                    part.CanCollide = false
                end
            end
        end
    end,
    clip = function(args)
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then
                    part.CanCollide = true
                end
            end
        end
    end,
    invis = function(args)
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then
                    part.Transparency = 1
                elseif part:IsA("Decal") then
                    part.Transparency = 1
                end
            end
        end
    end,
    vis = function(args)
        local char = LP.Character
        if char then
            for _, part in pairs(char:GetDescendants()) do
                if part:IsA("BasePart") then
                    part.Transparency = 0
                elseif part:IsA("Decal") then
                    part.Transparency = 0
                end
            end
        end
    end,
    godmode = function(args)
        local char = LP.Character
        if char and char:FindFirstChild("Humanoid") then
            char.Humanoid.MaxHealth = math.huge
            char.Humanoid.Health = math.huge
        end
    end,
}

-- Chat detection
LP.Chatted:Connect(function(msg)
    local parts = string.split(msg, " ")
    local cmd = string.lower(parts[1])
    local args = {}
    for i = 2, #parts do
        table.insert(args, parts[i])
    end

    if commands[cmd] then
        commands[cmd](args)
    end
end)

print("Infinite Yield loaded! Chat commands are active.")
)"
        },
        {
            "Simple Admin",
            "Basic admin commands for local player",
            "Admin",
            R"lua(
-- Simple Admin
local Players = game:GetService("Players")
local LP = Players.LocalPlayer

local function cmd(...)
    local args = {...}
    local fn = loadstring(args[1])
    if fn then fn() end
end

LP.Chatted:Connect(function(msg)
    if msg:sub(1, 1) == "/" then
        cmd(msg:sub(2))
    end
end)

-- Commands available via /cmd
print("Simple Admin loaded!")
)"
        },

        // ESP Scripts
        {
            "Player ESP",
            "ESP for all players",
            "ESP",
            R"lua(
-- Player ESP
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local CV = game:GetService("CoreGui")

local function makeESP(player)
    if player == LP then return end

    local highlight = Instance.new("Highlight")
    highlight.Name = player.Name .. "_ESP"
    highlight.FillColor = Color3.fromRGB(0, 255, 0)
    highlight.OutlineColor = Color3.fromRGB(255, 255, 255)
    highlight.FillTransparency = 0.5
    highlight.Parent = CV

    player.CharacterAdded:Connect(function(char)
        highlight.Adornee = char
    end)

    if player.Character then
        highlight.Adornee = player.Character
    end
end

Players.PlayerAdded:Connect(makeESP)
for _, p in pairs(Players:GetPlayers()) do
    makeESP(p)
end

Players.PlayerRemoving:Connect(function(p)
    local esp = CV:FindFirstChild(p.Name .. "_ESP")
    if esp then esp:Destroy() end
end)

print("Player ESP loaded!")
)"
        },
        {
            "Cham ESP",
            "Character ESP with transparency",
            "ESP",
            R"lua(
-- Cham ESP
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local CV = game:GetService("CoreGui")

for _, player in pairs(Players:GetPlayers()) do
    if player ~= LP and player.Character then
        for _, part in pairs(player.Character:GetDescendants()) do
            if part:IsA("BasePart") then
                local origColor = part.Color
                local origTransparency = part.Transparency

                -- Create outline
                local outline = Instance.new("SurfaceGui")
                outline.Name = "ChamOutline"
                outline.Face = Enum.NormalId.Front
                outline.Parent = part

                local frame = Instance.new("Frame")
                frame.Size = UDim2.new(1, 0, 1, 0)
                frame.BackgroundColor3 = Color3.fromRGB(0, 255, 0)
                frame.BackgroundTransparency = 0.5
                frame.BorderSizePixel = 0
                frame.Parent = outline
            end
        end
    end
end

print("Cham ESP loaded!")
)"
        },

        // Utility Scripts
        {
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

print("Anti-AFK activated!")
)"
        },
        {
            "Rejoin",
            "Quick rejoin script",
            "Utility",
            R"lua(
-- Rejoin Script
local TeleportService = game:GetService("TeleportService")
local Players = game:GetService("Players")
local LP = Players.LocalPlayer

local function rejoin()
    TeleportService:TeleportToPlaceAsync(game.PlaceId, LP)
end

-- Create rejoin button in chat
local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "RejoinGui"
ScreenGui.ResetOnSpawn = false
ScreenGui.Parent = game:GetService("CoreGui")

local Button = Instance.new("TextButton")
Button.Name = "Rejoin"
Button.Size = UDim2.new(0, 80, 0, 30)
Button.Position = UDim2.new(0, 10, 0, 10)
Button.Text = "Rejoin"
Button.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
Button.TextColor3 = Color3.fromRGB(255, 255, 255)
Button.Parent = ScreenGui

Button.MouseButton1Click:Connect(rejoin)

print("Rejoin script loaded!")
)"
        },
        {
            "Server Hop",
            "Hop between servers",
            "Utility",
            R"lua(
-- Server Hop
local TeleportService = game:GetService("TeleportService")
local HttpService = game:GetService("HttpService")

local function getServers(page)
    local url = "https://games.roblox.com/v1/games/" .. game.PlaceId .. "/servers/Public?sortOrder=Asc&limit=100"
    if page then
        url = url .. "&cursor=" .. page
    end

    local success, result = pcall(function()
        return HttpService:GetAsync(url)
    end)

    if success then
        return HttpService:JSONDecode(result)
    end
    return nil
end

local function hop()
    local servers = getServers()
    if not servers then
        print("Failed to get servers")
        return
    end

    local nextPage = servers.nextPageCursor
    for _, server in pairs(servers.data) do
        if server.id ~= game.JobId and server.playing < server.maxPlayers then
            TeleportService:TeleportToPlaceInstance(game.PlaceId, server.id)
            return
        end
    end

    if nextPage then
        hop(nextPage)
    else
        print("No available servers found")
    end
end

-- Create hop button
local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name = "HopGui"
ScreenGui.ResetOnSpawn = false
ScreenGui.Parent = game:GetService("CoreGui")

local Button = Instance.new("TextButton")
Button.Name = "ServerHop"
Button.Size = UDim2.new(0, 100, 0, 30)
Button.Position = UDim2.new(0, 100, 0, 10)
Button.Text = "Server Hop"
Button.BackgroundColor3 = Color3.fromRGB(50, 50, 50)
Button.TextColor3 = Color3.fromRGB(255, 255, 255)
Button.Parent = ScreenGui

Button.MouseButton1Click:Connect(hop)

print("Server Hop loaded!")
)"
        },

        // Fun Scripts
        {
            "Btools",
            "Building tools for editing",
            "Fun",
            R"lua(
-- Btools
local Tool = Instance.new("Tool")
Tool.Name = "Bricks"
Tool.RequiresHandle = true
Tool.CanBeDropped = false

local Handle = Instance.new("Part")
Handle.Name = "Handle"
Handle.Size = Vector3.new(1, 1, 1)
Handle.Parent = Tool

local Mesh = Instance.new("SpecialMesh")
Mesh.MeshType = Enum.MeshType.Brick
Mesh.Scale = Vector3.new(1, 1, 1)
Mesh.Parent = Handle

Tool.Parent = game:GetService("Players").LocalPlayer.Backpack

local Tool2 = Instance.new("Tool")
Tool2.Name = "Clone"
Tool2.RequiresHandle = true
Tool2.CanBeDropped = false

local Handle2 = Instance.new("Part")
Handle2.Name = "Handle"
Handle2.Size = Vector3.new(1, 1, 1)
Handle2.Parent = Tool2

local Mesh2 = Instance.new("SpecialMesh")
Mesh2.MeshType = Enum.MeshType.Brick
Mesh2.Scale = Vector3.new(1, 1, 1)
Mesh2.Parent = Handle2

Tool2.Parent = game:GetService("Players").LocalPlayer.Backpack

local Tool3 = Instance.new("Tool")
Tool3.Name = "Delete"
Tool3.RequiresHandle = true
Tool3.CanBeDropped = false

local Handle3 = Instance.new("Part")
Handle3.Name = "Handle"
Handle3.Size = Vector3.new(1, 1, 1)
Handle3.Parent = Tool3

local Mesh3 = Instance.new("SpecialMesh")
Mesh3.MeshType = Enum.MeshType.Brick
Mesh3.Scale = Vector3.new(1, 1, 1)
Mesh3.Parent = Handle3

Tool3.Parent = game:GetService("Players").LocalPlayer.Backpack

print("Btools spawned!")
)"
        },
        {
            "Float Pad",
            "Creates a floating platform",
            "Fun",
            R"lua(
-- Float Pad
local Players = game:GetService("Players")
local LP = Players.LocalPlayer

local screenGui = Instance.new("ScreenGui")
screenGui.Parent = game:GetService("CoreGui")

local button = Instance.new("TextButton")
button.Size = UDim2.new(0, 100, 0, 30)
button.Position = UDim2.new(0, 200, 0, 10)
button.Text = "Create Pad"
button.Parent = screenGui

button.MouseButton1Click:Connect(function()
    local char = LP.Character
    if char then
        local root = char:FindFirstChild("HumanoidRootPart")
        if root then
            local pad = Instance.new("Part")
            pad.Size = Vector3.new(10, 1, 10)
            pad.Anchored = true
            pad.CFrame = root.CFrame * CFrame.new(0, -3, 0)
            pad.Material = Enum.Material.Neon
            pad.BrickColor = BrickColor.new("Bright violet")
            pad.Parent = workspace

            -- Float effect
            local beach = Instance.new("BodyPosition")
            beach.Position = pad.Position + Vector3.new(0, 5, 0)
            beach.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
            beach.Parent = pad
        end
    end
end)

print("Float Pad loaded!")
)"
        },

        // Game-Specific Scripts
        {
            "Murder Mystery 2 - ESP",
            "ESP for Murder Mystery 2",
            "Game ESP",
            R"lua(
-- MM2 ESP
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local CV = game:GetService("CoreGui")

local function isMurderer(player)
    return player.Backpack:FindFirstChild("Knife") or player.Character and player.Character:FindFirstChild("Knife")
end

local function isSheriff(player)
    return player.Backpack:FindFirstChild("Gun") or player.Character and player.Character:FindFirstChild("Gun")
end

local function makeESP(player, color)
    if player == LP then return end
    if player.Character then
        local highlight = Instance.new("Highlight")
        highlight.FillColor = color
        highlight.OutlineColor = Color3.fromRGB(255, 255, 255)
        highlight.Parent = CV
        highlight.Adornee = player.Character
    end
end

Players.PlayerAdded:Connect(function(player)
    player.CharacterAdded:Connect(function(char)
        if isMurderer(player) then
            makeESP(player, Color3.fromRGB(255, 0, 0))
        elseif isSheriff(player) then
            makeESP(player, Color3.fromRGB(0, 0, 255))
        end
    end)
end)

for _, player in pairs(Players:GetPlayers()) do
    if isMurderer(player) then
        makeESP(player, Color3.fromRGB(255, 0, 0))
    elseif isSheriff(player) then
        makeESP(player, Color3.fromRGB(0, 0, 255))
    end
end

print("MM2 ESP loaded!")
)"
        },
        {
            "Arsenal - Aimbot",
            "Basic aimbot for Arsenal",
            "Game ESP",
            R"lua(
-- Arsenal Aimbot
local Players = game:GetService("Players")
local LP = Players.LocalPlayer
local UIS = game:GetService("UserInputService")
local RS = game:GetService("RunService")

local aiming = false
local target = nil
local fov = 50

local function getMouse()
    return LP:GetMouse()
end

local function getClosestPlayer()
    local closest = nil
    local closestDist = math.huge
    local mouse = getMouse()

    for _, player in pairs(Players:GetPlayers()) do
        if player ~= LP and player.Character then
            local root = player.Character:FindFirstChild("HumanoidRootPart")
            if root then
                local screenPos, onScreen = workspace.CurrentCamera:WorldToScreenPoint(root.Position)
                if onScreen then
                    local dist = (Vector2.new(screenPos.X, screenPos.Y) - Vector2.new(mouse.X, mouse.Y)).Magnitude
                    if dist < closestDist then
                        closestDist = dist
                        closest = player
                    end
                end
            end
        end
    end

    return closest, closestDist
end

UIS.InputBegan:Connect(function(input, processed)
    if input.UserInputType == Enum.UserInputType.MouseButton2 then
        aiming = true
    end
end)

UIS.InputEnded:Connect(function(input, processed)
    if input.UserInputType == Enum.UserInputType.MouseButton2 then
        aiming = false
        target = nil
    end
end)

RS.RenderStepped:Connect(function()
    if aiming then
        target, _ = getClosestPlayer()
    end
end)

print("Arsenal Aimbot loaded! Right-click to aim.")
)"
        }
    };
}

void ScriptHubManager::AddScript(const ScriptEntry& entry) {
    m_Scripts.push_back(entry);
}

void ScriptHubManager::RemoveScript(const std::string& name) {
    m_Scripts.erase(
        std::remove_if(m_Scripts.begin(), m_Scripts.end(),
            [&name](const ScriptEntry& e) { return e.Name == name; }),
        m_Scripts.end()
    );
}

void ScriptHubManager::ExecuteScript(const std::string& name) {
    for (const auto& script : m_Scripts) {
        if (script.Name == name) {
            Executor::ScriptEngine::Get().Execute(script.Content, script.Name);
            return;
        }
    }
}

void ScriptHubManager::ToggleScript(const std::string& name) {
    for (auto& script : m_Scripts) {
        if (script.Name == name) {
            script.Enabled = !script.Enabled;
            if (script.Enabled) {
                ExecuteScript(name);
            }
            return;
        }
    }
}

std::vector<std::string> ScriptHubManager::GetCategories() const {
    std::vector<std::string> categories;
    std::unordered_set<std::string> seen;

    for (const auto& script : m_Scripts) {
        if (seen.find(script.Category) == seen.end()) {
            seen.insert(script.Category);
            categories.push_back(script.Category);
        }
    }

    return categories;
}

void ScriptHubManager::FilterByCategory(const std::string& category) {
    m_CurrentFilter = category;
}

std::vector<ScriptEntry> ScriptHubManager::GetFilteredScripts() const {
    std::vector<ScriptEntry> filtered;

    for (const auto& script : m_Scripts) {
        bool matchesCategory = m_CurrentFilter.empty() || script.Category == m_CurrentFilter;
        bool matchesSearch = m_SearchQuery.empty() ||
            script.Name:find(m_SearchQuery) != std::string::npos ||
            script.Description:find(m_SearchQuery) != std::string::npos;

        if (matchesCategory && matchesSearch) {
            filtered.push_back(script);
        }
    }

    return filtered;
}

void ScriptHubManager::EnableAll() {
    for (auto& script : m_Scripts) {
        script.Enabled = true;
        ExecuteScript(script.Name);
    }
}

void ScriptHubManager::DisableAll() {
    for (auto& script : m_Scripts) {
        script.Enabled = false;
    }
}

std::string GetScriptContent(const std::string& name) {
    for (const auto& script : ScriptHubManager::Get().GetScripts()) {
        if (script.Name == name) {
            return script.Content;
        }
    }
    return "";
}

} // namespace ScriptHub