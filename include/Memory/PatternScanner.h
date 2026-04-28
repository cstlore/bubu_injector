#pragma once

#include "../pch.h"

namespace Memory {

// Pattern byte representation - supports wildcards (? or * for any byte)
struct PatternByte {
    u8 value;
    bool wildcard;

    PatternByte(u8 val, bool wc = false) : value(val), wildcard(wc) {}
    PatternByte(char c) : value(static_cast<u8>(c)), wildcard(c == '?' || c == '*') {}
};

// Pattern string parser
std::vector<PatternByte> ParsePattern(const char* pattern);

// Result of a pattern scan
struct ScanResult {
    uptr address = 0;
    usize size = 0;

    explicit operator bool() const { return address != 0; }
};

// Scanner interface
class IPatternScanner {
public:
    virtual ~IPatternScanner() = default;
    virtual ScanResult Scan(const char* pattern, usize alignment = 1) = 0;
    virtual std::vector<ScanResult> ScanAll(const char* pattern) = 0;
};

// Region-based scanner
class RegionScanner : public IPatternScanner {
public:
    RegionScanner(uptr start, usize size);

    ScanResult Scan(const char* pattern, usize alignment = 1) override;
    std::vector<ScanResult> ScanAll(const char* pattern) override;

    void SetRange(uptr start, usize size) { m_Start = start; m_Size = size; }
    void SetProcess(HANDLE hProcess) { m_hProcess = hProcess; }

protected:
    uptr m_Start = 0;
    usize m_Size = 0;
    HANDLE m_hProcess = nullptr;
};

// Module scanner (wrapper around RegionScanner for specific modules)
class ModuleScanner : public IPatternScanner {
public:
    explicit ModuleScanner(HANDLE hProcess, const wchar_t* moduleName);
    explicit ModuleScanner(HANDLE hProcess, uptr baseAddress, usize size);

    ScanResult Scan(const char* pattern, usize alignment = 1) override;
    std::vector<ScanResult> ScanAll(const char* pattern) override;

    uptr GetBaseAddress() const { return m_BaseAddress; }
    usize GetSize() const { return m_Size; }

private:
    uptr m_BaseAddress = 0;
    usize m_Size = 0;
    HANDLE m_hProcess = nullptr;
};

// Remote scanner - scans process memory remotely
class RemoteScanner {
public:
    explicit RemoteScanner(HANDLE hProcess);

    // Scan in a region
    ScanResult Scan(uptr regionStart, usize regionSize, const char* pattern);

    // Scan entire process
    ScanResult Scan(const char* pattern);

    // Find signature near a reference address
    ScanResult ScanNear(uptr reference, usize maxDistance, const char* pattern);

    // Scan with offset calculation: pattern+offset gives pointer to data
    uptr ScanWithOffset(const char* pattern, int offset, usize alignment = 1);

    // Scan for pointer: pattern+offset points to address
    uptr ScanForPointer(const char* pattern, int offset, usize alignment = 1);

    // Scan then dereference multiple times
    uptr ScanAndDereference(const char* pattern, int offsets[], int count);

private:
    HANDLE m_hProcess = nullptr;
};

// Signature data structure for compile-time patterns
struct Signature {
    const char* pattern;
    int offset = 0;
    usize size = 0;

    constexpr Signature(const char* p, int o = 0, usize s = 0) : pattern(p), offset(o), size(s) {}
};

// Common Roblox signatures
namespace Signatures {
    // Lua state pointer (multiplied by 8 in Roblox)
    constexpr Signature LuaState{ "48 8B 05 ? ? ? ? 48 85 C0 75 ? 48 89 1F", 3 };

    // luau_load function
    constexpr Signature LuauLoad{ "48 89 5C 24 ? 57 48 83 EC 30 48 8B F9 E8 ? ? ? ? 48 8B 5C 24", 0, 40 };

    // lua_pcall
    constexpr Signature LuaPcall{ "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 33 C0", 0, 30 };

    // DataModel pointer (IGame scripts)
    constexpr Signature DataModel{ "48 8B 0D ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 01 FF 50 ? 48 8B 08", 3 };

    // getrawmetatable
    constexpr Signature GetRawMetaTable{ "48 8B 81 ? ? ? ? C1 E8 ? 83 F8 ? 0F 84", 0, 20 };

    // getcallingscript
    constexpr Signature GetCallingScript{ "48 8B 89 ? ? ? ? 48 85 C9 74 ? 48 8B 01", 0, 15 };

    // getfenv replacement (internal)
    constexpr Signature GetFEnv{ "48 8B 89 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 63", 0, 20 };

    // fireclick / UI bypass
    constexpr Signature FireClick{ "48 8B 81 ? ? ? ? 8B 80 ? ? ? ? 2B 80 ? ? ? ? 3B 80", 0, 25 };

    // Teleport bypass
    constexpr Signature TeleportService{ "48 8B 0D ? ? ? ? 48 85 C9 74 ? 33 C0 48 89 1F", 3 };

    // WebSocket support
    constexpr Signature WebSocket{ "48 8B 0D ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 48 8B 01", 3 };
}

} // namespace Memory