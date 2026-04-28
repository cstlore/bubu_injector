#pragma once

#include "../pch.h"

namespace Executor {

// Lua C API wrapper with Roblox-specific bypasses
class LuaContext {
public:
    static LuaContext& Get();

    // State management
    bool Initialize();
    void Shutdown();
    bool IsValid() const { return m_LuaState != 0; }

    // Get raw Lua state
    uptr GetState() const { return m_LuaState; }

    // Core execution methods
    enum class LoadMode { Text, Bytecode };

    struct LoadResult {
        bool Success;
        std::string Error;
        uptr Function = 0;

        explicit operator bool() const { return Success; }
    };

    LoadResult LoadScript(const std::string& source, const std::string& chunkName = "loadstring", LoadMode mode = LoadMode::Text);
    LoadResult LoadFile(const std::string& path);

    // Execution
    struct ExecResult {
        bool Success;
        int ReturnCount = 0;
        std::string Error;
        std::vector<std::variant<i64, f64, std::string>> Returns;

        explicit operator bool() const { return Success; }
    };

    ExecResult Execute(const std::string& source, const std::string& chunkName = "execute");
    ExecResult ExecuteFunction(uptr func, int argCount = 0);
    ExecResult PCall(uptr func, int argCount = 0, int errFunc = 0);

    // Global manipulation
    void SetGlobal(const char* name, uptr ref);
    void PushGlobal(const char* name);
    uptr GetGlobalRef(const char* name);

    // Stack operations
    void PushNil();
    void PushInteger(i64 value);
    void PushNumber(f64 value);
    void PushString(const std::string& value);
    void PushBoolean(bool value);
    void PushPointer(uptr ptr);
    void PushCFunction(uptr func);

    i64 ToInteger(int index = -1);
    f64 ToNumber(int index = -1);
    std::string ToString(int index = -1);
    bool ToBoolean(int index = -1);
    int GetTop() const;
    void SetTop(int index);
    void Pop(int count = 1);
    void Remove(int index);
    void Insert(int index);
    void Rotate(int index, int count);

    // Reference system
    int Ref();
    void Unref(int ref);
    void PushRef(int ref);

    // Metatable operations
    bool GetMetatable(int index);
    bool SetMetatable(int index);
    uptr NewTable();

    // Environment (fenv)
    bool GetFEnv(uptr func);
    bool SetFEnv(uptr func);

    // Roblox-specific exploit functions
    namespace Roblox {
        // Identity/spawn context bypass
        uptr GetIdentity();
        void SetIdentity(int level);

        // Raw metatable access (bypasses rbxscriptsign)
        uptr GetRawMetaTable(const char* name);
        bool SetRawMetaTable(const char* name, uptr metatable);

        // Script context manipulation
        uptr GetCallingScript();
        uptr GetScriptClosure(int level = 1);

        // cloneref bypass
        uptr CloneRef(uptr object);

        // UI bypass - fireclick
        void FireClick(uptr button);
        void FireInputbegan(uptr inputObject);
        void FireInputEnded(uptr inputObject);

        // Teleport bypass
        bool CanTeleport();
        void ForceTeleport(uptr teleportService, uptr args);
    }

    // Script hub execution with specific identity
    ExecResult ExecuteWithIdentity(const std::string& source, int identity);

private:
    LuaContext() = default;
    LuaContext(const LuaContext&) = delete;
    LuaContext& operator=(const LuaContext&) = delete;

    uptr m_LuaState = 0;
    uptr m_LuauLoad = 0;
    uptr m_LuaPCall = 0;

    // Cached Roblox function pointers
    uptr m_GetIdentity = 0;
    uptr m_SetIdentity = 0;
    uptr m_GetRawMetaTable = 0;
    uptr m_SetRawMetaTable = 0;
    uptr m_GetCallingScript = 0;
    uptr m_GetScriptContext = 0;
    uptr m_CloneRef = 0;
    uptr m_FireClick = 0;
    uptr m_FireInputBegan = 0;
    uptr m_FireInputEnded = 0;

    // Original environment storage for fenv bypass
    std::unordered_map<uptr, uptr> m_EnvironmentCache;
};

// RAII scope guard for Lua stack
class LuaStackGuard {
public:
    explicit LuaStackGuard(LuaContext& ctx) : m_Context(ctx), m_Snapshot(ctx.GetTop()) {}
    ~LuaStackGuard() { m_Context.SetTop(m_Snapshot); }

    int GetStackChange() const { return m_Context.GetTop() - m_Snapshot; }

private:
    LuaContext& m_Context;
    int m_Snapshot = 0;
};

} // namespace Executor