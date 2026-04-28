#include "pch.h"
#include "Memory/PatternScanner.h"
#include "Memory/MemoryManager.h"

namespace Memory {

std::vector<PatternByte> ParsePattern(const char* pattern) {
    std::vector<PatternByte> result;

    // Skip whitespace
    while (*pattern && *pattern == ' ') pattern++;

    while (*pattern) {
        if (*pattern == ' ') {
            pattern++;
            continue;
        }

        if (*pattern == '?' || *pattern == '*') {
            result.emplace_back(0, true);
            pattern++;
        } else if (isxdigit(*pattern)) {
            // Parse hex byte
            char byteStr[3] = { pattern[0], pattern[1], 0 };
            u8 byte = static_cast<u8>(strtoul(byteStr, nullptr, 16));
            result.emplace_back(byte, false);
            pattern += 2;
        } else {
            pattern++;
        }
    }

    return result;
}

RegionScanner::RegionScanner(uptr start, usize size)
    : m_Start(start), m_Size(size) {}

ScanResult RegionScanner::Scan(const char* pattern, usize alignment) {
    auto bytes = ParsePattern(pattern);
    if (bytes.empty()) return {};

    usize scanned = 0;
    usize matchStart = 0;
    uptr currentAddress = m_Start;
    uptr endAddress = m_Start + m_Size;

    while (currentAddress < endAddress) {
        u8 byte = 0;
        SIZE_T bytesRead = 0;

        // Read one byte at a time for pattern matching
        if (!ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(currentAddress), &byte, 1, &bytesRead)) {
            break;
        }

        if (bytes[scanned].wildcard || byte == bytes[scanned].value) {
            if (scanned == 0) matchStart = currentAddress;
            scanned++;

            if (scanned == bytes.size()) {
                // Found match - verify alignment
                if (alignment == 1 || ((matchStart - m_Start) % alignment) == 0) {
                    return ScanResult{matchStart, bytes.size()};
                }
                // Continue searching
                scanned = 0;
            }
        } else {
            scanned = 0;
        }

        currentAddress++;
    }

    return {};
}

std::vector<ScanResult> RegionScanner::ScanAll(const char* pattern) {
    std::vector<ScanResult> results;
    auto bytes = ParsePattern(pattern);
    if (bytes.empty()) return results;

    usize scanned = 0;
    usize matchStart = 0;
    uptr currentAddress = m_Start;
    uptr endAddress = m_Start + m_Size;

    while (currentAddress < endAddress) {
        u8 byte = 0;
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(currentAddress), &byte, 1, &bytesRead)) {
            break;
        }

        if (bytes[scanned].wildcard || byte == bytes[scanned].value) {
            if (scanned == 0) matchStart = currentAddress;
            scanned++;

            if (scanned == bytes.size()) {
                results.push_back(ScanResult{matchStart, bytes.size()});
                scanned = 0;
                currentAddress = matchStart + 1; // Move past the match
            }
        } else {
            scanned = 0;
        }

        currentAddress++;
    }

    return results;
}

ModuleScanner::ModuleScanner(HANDLE hProcess, const wchar_t* moduleName)
    : m_hProcess(hProcess) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(MODULEENTRY32W);

    for (BOOL ok = Module32FirstW(hSnap, &me); ok; ok = Module32NextW(hSnap, &me)) {
        if (wcscmp(me.szModule, moduleName) == 0) {
            m_BaseAddress = reinterpret_cast<uptr>(me.modBaseAddr);
            m_Size = me.modBaseSize;
            break;
        }
    }

    CloseHandle(hSnap);
}

ModuleScanner::ModuleScanner(HANDLE hProcess, uptr baseAddress, usize size)
    : m_BaseAddress(baseAddress), m_Size(size), m_hProcess(hProcess) {}

ScanResult ModuleScanner::Scan(const char* pattern, usize alignment) {
    RegionScanner scanner(m_BaseAddress, m_Size);
    scanner.SetProcess(m_hProcess);
    return scanner.Scan(pattern, alignment);
}

std::vector<ScanResult> ModuleScanner::ScanAll(const char* pattern) {
    RegionScanner scanner(m_BaseAddress, m_Size);
    scanner.SetProcess(m_hProcess);
    return scanner.ScanAll(pattern);
}

RemoteScanner::RemoteScanner(HANDLE hProcess) : m_hProcess(hProcess) {}

ScanResult RemoteScanner::Scan(uptr regionStart, usize regionSize, const char* pattern) {
    auto bytes = ParsePattern(pattern);
    if (bytes.empty()) return {};

    constexpr usize CHUNK_SIZE = 0x1000;
    usize scanned = 0;
    usize matchStart = 0;

    for (uptr addr = regionStart; addr < regionStart + regionSize; addr += CHUNK_SIZE) {
        std::vector<u8> buffer(CHUNK_SIZE);
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(addr), buffer.data(), CHUNK_SIZE, &bytesRead)) {
            continue;
        }

        for (usize i = 0; i < bytesRead; i++) {
            if (bytes[scanned].wildcard || buffer[i] == bytes[scanned].value) {
                if (scanned == 0) matchStart = addr + i;
                scanned++;

                if (scanned == bytes.size()) {
                    return ScanResult{matchStart, bytes.size()};
                }
            } else {
                scanned = 0;
            }
        }
    }

    return {};
}

ScanResult RemoteScanner::Scan(const char* pattern) {
    // Scan through all committed memory regions
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);

    MEMORY_BASIC_INFORMATION memInfo{};
    uptr address = 0;

    while (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(address), &memInfo, sizeof(memInfo))) {
        if (memInfo.State == MEM_COMMIT &&
            (memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            auto result = Scan(address, memInfo.RegionSize, pattern);
            if (result) return result;
        }
        address += memInfo.RegionSize;
    }

    return {};
}

ScanResult RemoteScanner::ScanNear(uptr reference, usize maxDistance, const char* pattern) {
    uptr start = (reference > maxDistance) ? (reference - maxDistance) : 0;
    uptr end = reference + maxDistance;
    return Scan(start, end - start, pattern);
}

uptr RemoteScanner::ScanWithOffset(const char* pattern, int offset, usize alignment) {
    auto result = Scan(pattern);
    if (!result) return 0;
    return result.address + offset;
}

uptr RemoteScanner::ScanForPointer(const char* pattern, int offset, usize alignment) {
    auto addr = ScanWithOffset(pattern, offset, alignment);
    if (!addr) return 0;
    return MemoryManager::Read<uptr>(addr);
}

uptr RemoteScanner::ScanAndDereference(const char* pattern, int offsets[], int count) {
    auto result = Scan(pattern);
    if (!result) return 0;

    uptr value = result.address;
    for (int i = 0; i < count; i++) {
        value = MemoryManager::Read<uptr>(value + offsets[i]);
        if (!value) return 0;
    }

    return value;
}

} // namespace Memory