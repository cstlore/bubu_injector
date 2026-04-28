#include "pch.h"
#include "Utils/Utils.h"

namespace Utils {

void Sleep(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

i64 GetTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string FormatTimestamp(i64 timestamp, const char* format) {
    time_t time = static_cast<time_t>(timestamp);
    tm timeTm{};
    localtime_s(&timeTm, &time);

    char buffer[64];
    strftime(buffer, sizeof(buffer), format, &timeTm);
    return std::string(buffer);
}

std::vector<std::string> Split(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string token;

    while (std::getline(ss, token, delimiter)) {
        result.push_back(token);
    }

    return result;
}

std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string ToUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

bool FileExists(const std::string& path) {
    return std::filesystem::exists(path);
}

bool CreateDirectory(const std::string& path) {
    return std::filesystem::create_directories(path);
}

std::string ReadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool WriteFile(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    file << content;
    return true;
}

i64 GetFileSize(const std::string& path) {
    if (!std::filesystem::exists(path)) return 0;
    return static_cast<i64>(std::filesystem::file_size(path));
}

bool IsElevated() {
    bool elevated = false;
    HANDLE token = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation{};
        DWORD len = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &len)) {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }

    return elevated;
}

bool SetPrivilege(const char* name, bool enable) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, name, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    bool result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0;

    CloseHandle(token);
    return result;
}

// CRC32 lookup table
static const u32 CRC32_TABLE[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91
};

u32 CRC32(const u8* data, usize size) {
    u32 crc = 0xFFFFFFFF;
    for (usize i = 0; i < size; i++) {
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ data[i]) & 0xFF];
    }
    return ~crc;
}

u32 HashString(const std::string& str) {
    u32 hash = 5381;
    for (char c : str) {
        hash = ((hash << 5) + hash) + static_cast<u32>(c);
    }
    return hash;
}

ModuleInfo GetModuleInfo(HANDLE hProcess, const wchar_t* moduleName) {
    ModuleInfo info{};
    info.BaseAddress = 0;
    info.Size = 0;
    info.Name = Utils::ToNarrow(moduleName);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) return info;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(MODULEENTRY32W);

    for (BOOL ok = Module32FirstW(hSnap, &me); ok; ok = Module32NextW(hSnap, &me)) {
        if (wcscmp(me.szModule, moduleName) == 0) {
            info.BaseAddress = reinterpret_cast<uptr>(me.modBaseAddr);
            info.Size = me.modBaseSize;
            break;
        }
    }

    CloseHandle(hSnap);
    return info;
}

void CleanExit(int code) {
    std::exit(code);
}

} // namespace Utils