// =============================================================================
// Log.cpp - the payload's tiny file-only logger
// =============================================================================

#include "Hyperion/Log.h"

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <windows.h>

namespace ENI::Hyperion::Log {

namespace {

HANDLE           g_File = INVALID_HANDLE_VALUE;
CRITICAL_SECTION g_Lock;
bool             g_LockReady = false;

// Format the current local time as "HH:MM:SS.mmm". Returns the number
// of chars written (excluding null).
int FormatTimestamp(char* buf, std::size_t bufLen) {
    SYSTEMTIME t{};
    GetLocalTime(&t);
    return std::snprintf(buf, bufLen, "%02u:%02u:%02u.%03u ",
                         t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
}

// Wide → UTF-8. `out` is filled, `outLen` is the buffer capacity.
// Returns bytes written excluding null. Truncates on overflow.
int WideToUtf8(const wchar_t* in, int inChars, char* out, int outCap) {
    if (inChars <= 0) return 0;
    const int n = WideCharToMultiByte(CP_UTF8, 0, in, inChars,
                                      out, outCap, nullptr, nullptr);
    return n > 0 ? n : 0;
}

} // namespace

void Open(const wchar_t* path) {
    if (g_File != INVALID_HANDLE_VALUE) return;
    if (!path || !*path) return;

    if (!g_LockReady) {
        InitializeCriticalSection(&g_Lock);
        g_LockReady = true;
    }

    // Make sure the directory exists. We don't ship a recursive mkdir -
    // BootInfo's LogsDir is supposed to be created by the launcher.
    g_File = CreateFileW(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);

    // Banner line so subsequent runs are visually separated in the log.
    if (g_File != INVALID_HANDLE_VALUE) {
        const char* banner = "\n----- ENIPayload boot -----\n";
        DWORD written = 0;
        WriteFile(g_File, banner, static_cast<DWORD>(std::strlen(banner)),
                  &written, nullptr);
    }
}

void Close() {
    if (g_File != INVALID_HANDLE_VALUE) {
        CloseHandle(g_File);
        g_File = INVALID_HANDLE_VALUE;
    }
    if (g_LockReady) {
        DeleteCriticalSection(&g_Lock);
        g_LockReady = false;
    }
}

void LineV(const char* fmt, std::va_list ap) {
    if (g_File == INVALID_HANDLE_VALUE) return;
    if (!g_LockReady) return;

    char line[1024];
    const int tsLen = FormatTimestamp(line, sizeof(line));
    if (tsLen <= 0) return;

    int bodyLen = std::vsnprintf(line + tsLen, sizeof(line) - tsLen - 2, fmt, ap);
    if (bodyLen < 0) bodyLen = 0;
    const int total = tsLen + bodyLen;
    if (total < static_cast<int>(sizeof(line)) - 1) {
        line[total] = '\n';
        line[total + 1] = '\0';
    } else {
        line[sizeof(line) - 2] = '\n';
        line[sizeof(line) - 1] = '\0';
    }
    const int writeLen = static_cast<int>(std::strlen(line));

    EnterCriticalSection(&g_Lock);
    DWORD written = 0;
    WriteFile(g_File, line, static_cast<DWORD>(writeLen), &written, nullptr);
    LeaveCriticalSection(&g_Lock);
}

void Line(const char* fmt, ...) {
    std::va_list ap;
    va_start(ap, fmt);
    LineV(fmt, ap);
    va_end(ap);
}

} // namespace ENI::Hyperion::Log
