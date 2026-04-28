#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <tlhelp32.h>
#include <d3d11.h>
#include <dxgi.h>
#include <GL/gl.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <unordered_map>
#include <filesystem>
#include <fstream>

// Project version
#define EXECUTOR_VERSION "2.4.1"
#define EXECUTOR_BUILD_DATE __DATE__

// Platform detection
#ifdef _WIN64
    #define PLATFORM_X64
#else
    #define PLATFORM_X86
#endif

// Compiler detection
#ifdef _MSC_VER
    #define COMPILER_MSVC
    #define FORCE_INLINE __forceinline
#elif defined(__GNUC__)
    #define COMPILER_GCC
    #define FORCE_INLINE inline
#else
    #define FORCE_INLINE inline
#endif

// Unsigned types for clarity
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using f32 = float;
using f64 = double;
using usize = size_t;
using uptr = uintptr_t;
using iptr = intptr_t;

// Memory macros
#define MEMORY_READ(type, addr) MemoryManager::Read<type>(reinterpret_cast<uptr>(addr))
#define MEMORY_WRITE(type, addr, val) MemoryManager::Write<type>(reinterpret_cast<uptr>(addr), val)

// Signatures
#define IGNORE_SIG(x) static_assert(true, "")

// Export macro for DLL
#ifdef EXECUTOR_EXPORTS
    #define EXECUTOR_API __declspec(dllexport)
#else
    #define EXECUTOR_API __declspec(dllimport)
#endif

// Disable structure alignment warnings on MSVC
#ifdef COMPILER_MSVC
    #pragma warning(disable: 4324)
#endif

// String conversion helpers
namespace String {
    inline std::wstring ToWide(const std::string& str) {
        if (str.empty()) return {};
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
        return wstr;
    }

    inline std::string ToNarrow(const std::wstring& wstr) {
        if (wstr.empty()) return {};
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
        return str;
    }
}

// Debug logging
#ifdef _DEBUG
    #define LOG_DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", __VA_ARGS__)
    #define LOG_INFO(fmt, ...) fprintf(stderr, "[INFO] " fmt "\n", __VA_ARGS__)
    #define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", __VA_ARGS__)
    #define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN] " fmt "\n", __VA_ARGS__)
#else
    #define LOG_DEBUG(...) (void)0
    #define LOG_INFO(fmt, ...) fprintf(stderr, "[INFO] " fmt "\n", __VA_ARGS__)
    #define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", __VA_ARGS__)
    #define LOG_WARN(fmt, ...) fprintf(stderr, "[WARN] " fmt "\n", __VA_ARGS__)
#endif

// Runtime assertions
#ifdef _DEBUG
    #define ASSERT(cond, msg) \
        do { if (!(cond)) { \
            LOG_ERROR("Assertion failed: %s", msg); \
            __debugbreak(); \
        }} while(0)
#else
    #define ASSERT(cond, msg) (void)0
#endif