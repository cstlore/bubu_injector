#pragma once

#include "../pch.h"

namespace Utils {

// Sleep for milliseconds (cross-platform wrapper)
void Sleep(int milliseconds);

// Get current timestamp
i64 GetTimestamp();

// Format timestamp to string
std::string FormatTimestamp(i64 timestamp, const char* format = "%Y-%m-%d %H:%M:%S");

// String manipulation
std::vector<std::string> Split(const std::string& str, char delimiter);
std::string Trim(const std::string& str);
std::string ToLower(const std::string& str);
std::string ToUpper(const std::string& str);

// File operations
bool FileExists(const std::string& path);
bool CreateDirectory(const std::string& path);
std::string ReadFile(const std::string& path);
bool WriteFile(const std::string& path, const std::string& content);
i64 GetFileSize(const std::string& path);

// Process operations
bool IsElevated();
bool SetPrivilege(const char* name, bool enable);

// Xor string encryption/decryption
template<size_t N>
std::string XorString(const char(&key)[N], const std::string& input) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); i++) {
        output[i] = input[i] ^ key[i % (N - 1)];
    }
    return output;
}

// CRC32 calculation
u32 CRC32(const u8* data, usize size);

// Hash functions
u32 HashString(const std::string& str);

// Time measure helper
class Timer {
public:
    void Start() { m_Start = std::chrono::high_resolution_clock::now(); }
    void Stop() { m_End = std::chrono::high_resolution_clock::now(); }

    template<typename T = std::chrono::milliseconds>
    i64 Elapsed() const {
        return std::chrono::duration_cast<T>(m_End - m_Start).count();
    }

private:
    std::chrono::high_resolution_clock::time_point m_Start;
    std::chrono::high_resolution_clock::time_point m_End;
};

// RAII Timer for scope-based timing
class ScopedTimer {
public:
    ScopedTimer(const char* name) : m_Name(name) { Start(); }
    ~ScopedTimer() {
        Stop();
        LOG_INFO("[Timer] %s took %lld ms", m_Name, Elapsed());
    }

    void Start() { m_Start = std::chrono::high_resolution_clock::now(); }
    void Stop() { m_End = std::chrono::high_resolution_clock::now(); }

    i64 Elapsed() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(m_End - m_Start).count();
    }

private:
    const char* m_Name;
    std::chrono::high_resolution_clock::time_point m_Start;
    std::chrono::high_resolution_clock::time_point m_End;
};

// Min/Max helpers for cross-compiler compatibility
template<typename T>
T Min(T a, T b) { return (a < b) ? a : b; }

template<typename T>
T Max(T a, T b) { return (a > b) ? a : b; }

template<typename T>
T Clamp(T value, T minVal, T maxVal) { return Max(minVal, Min(maxVal, value)); }

// Lerp
template<typename T>
T Lerp(T a, T b, float t) { return a + (b - a) * t; }

// Vector operations
struct Vec2 {
    float x, y;
    Vec2() : x(0), y(0) {}
    Vec2(float _x, float _y) : x(_x), y(_y) {}
};

struct Vec3 {
    float x, y, z;
    Vec3() : x(0), y(0), z(0) {}
    Vec3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}
};

struct Vec4 {
    float x, y, z, w;
    Vec4() : x(0), y(0), z(0), w(0) {}
    Vec4(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w) {}
};

// Module information
struct ModuleInfo {
    uptr BaseAddress;
    usize Size;
    std::string Name;
};

ModuleInfo GetModuleInfo(HANDLE hProcess, const wchar_t* moduleName);

// Clean shutdown
void CleanExit(int code = 0);

} // namespace Utils