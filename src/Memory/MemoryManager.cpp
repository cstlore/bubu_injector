#include "pch.h"
#include "Memory/MemoryManager.h"
#include "Core/Globals.h"

namespace Memory {

void RemoteBuffer::Free() {
    if (m_Address && m_Owns) {
        auto& mm = MemoryManager::Get();
        if (mm.GetProcess()) {
            VirtualFreeEx(mm.GetProcess(), reinterpret_cast<LPVOID>(m_Address), 0, MEM_RELEASE);
        }
    }
    m_Address = 0;
    m_Size = 0;
    m_Owns = false;
}

MemoryManager& MemoryManager::Get() {
    static MemoryManager instance{};
    return instance;
}

void MemoryManager::SetProcess(HANDLE hProcess) {
    m_hProcess = hProcess;
    m_PID = GetProcessId(hProcess);
}

HANDLE MemoryManager::GetProcess() const { return m_hProcess; }
DWORD MemoryManager::GetPID() const { return m_PID; }

std::vector<u8> MemoryManager::ReadBytes(uptr address, usize size) {
    std::vector<u8> buffer(size, 0);
    auto& mm = Get();
    if (mm.m_hProcess) {
        SIZE_T bytesRead = 0;
        ReadProcessMemory(mm.m_hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytesRead);
        buffer.resize(bytesRead);
    }
    return buffer;
}

RemoteBuffer MemoryManager::Allocate(usize size, Protection prot) {
    if (!m_hProcess) return {};

    uptr address = reinterpret_cast<uptr>(
        VirtualAllocEx(m_hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, static_cast<DWORD>(prot))
    );

    if (address == 0) {
        LOG_ERROR("VirtualAllocEx failed: %lu", GetLastError());
        return {};
    }

    LOG_DEBUG("Allocated remote memory at 0x%llX (size: %llu)", address, size);
    return RemoteBuffer{address, size, true};
}

RemoteBuffer MemoryManager::AllocateNear(uptr target, usize size, usize maxDistance) {
    if (!m_hProcess) return {};

    MEMORY_BASIC_INFORMATION info{};
    uptr searchStart = target - maxDistance;
    uptr searchEnd = target + maxDistance;

    for (uptr addr = searchStart; addr < searchEnd; addr += 0x1000) {
        if (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(addr), &info, sizeof(info))) {
            if (info.State == MEM_FREE) {
                uptr alloc = reinterpret_cast<uptr>(
                    VirtualAllocEx(m_hProcess, reinterpret_cast<LPVOID>(addr), size,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
                );
                if (alloc) {
                    return RemoteBuffer{alloc, size, true};
                }
            }
        }
    }

    return Allocate(size);
}

bool MemoryManager::Free(RemoteBuffer& buffer) {
    buffer.Free();
    return true;
}

bool MemoryManager::Protect(uptr address, usize size, Protection prot) {
    if (!m_hProcess) return false;

    DWORD oldProtect = 0;
    return VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(address), size,
        static_cast<DWORD>(prot), &oldProtect) != 0;
}

MemoryManager::Protection MemoryManager::QueryProtection(uptr address) {
    if (!m_hProcess) return Protection::NoAccess;

    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(address), &info, sizeof(info))) {
        return static_cast<Protection>(info.Protect);
    }
    return Protection::NoAccess;
}

uptr MemoryManager::CreateRemoteThread(uptr address, uptr parameter) {
    if (!m_hProcess) return 0;

    HANDLE hThread = CreateRemoteThread(m_hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(address), reinterpret_cast<LPVOID>(parameter), 0, nullptr);

    if (!hThread) {
        LOG_ERROR("CreateRemoteThread failed: %lu", GetLastError());
        return 0;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    return exitCode;
}

bool MemoryManager::QueueApc(uptr thread, uptr address, uptr parameter) {
    if (!m_hProcess) return false;
    return QueueUserAPC(reinterpret_cast<PAPCFUNC>(address), reinterpret_cast<HANDLE>(thread), parameter) != 0;
}

uptr MemoryManager::GetBaseAddress(HANDLE hProcess) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(MODULEENTRY32W);

    uptr baseAddress = 0;
    if (Module32FirstW(hSnap, &me)) {
        baseAddress = reinterpret_cast<uptr>(me.modBaseAddr);
    }

    CloseHandle(hSnap);
    return baseAddress;
}

usize MemoryManager::GetImageSize(HANDLE hProcess) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(MODULEENTRY32W);

    usize size = 0;
    if (Module32FirstW(hSnap, &me)) {
        size = me.modBaseSize;
    }

    CloseHandle(hSnap);
    return size;
}

bool MemoryManager::IsProcess64Bit(HANDLE hProcess) {
    BOOL is64Bit = FALSE;
    IsWow64Process(hProcess, &is64Bit);
    return !is64Bit;
}

std::string MemoryManager::ReadString(uptr address, usize maxLength) {
    std::vector<char> buffer(maxLength + 1, 0);
    auto& mm = Get();
    if (mm.m_hProcess) {
        SIZE_T bytesRead = 0;
        ReadProcessMemory(mm.m_hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), maxLength, &bytesRead);
    }
    return std::string(buffer.data());
}

std::wstring MemoryManager::ReadWString(uptr address, usize maxLength) {
    std::vector<wchar_t> buffer(maxLength + 1, 0);
    auto& mm = Get();
    if (mm.m_hProcess) {
        SIZE_T bytesRead = 0;
        ReadProcessMemory(mm.m_hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), maxLength * sizeof(wchar_t), &bytesRead);
    }
    return std::wstring(buffer.data());
}

bool MemoryManager::WriteString(uptr address, const std::string& str) {
    return WriteArray(address, str.c_str(), str.length() + 1);
}

bool MemoryManager::WriteWString(uptr address, const std::wstring& wstr) {
    return WriteArray(address, wstr.c_str(), (wstr.length() + 1) * sizeof(wchar_t));
}

uptr MemoryManager::ReadVTABLE(uptr object, int index) {
    if (!object) return 0;

    uptr vtable = Read<uptr>(object);
    if (!vtable) return 0;

    return Read<uptr>(vtable + (index * sizeof(uptr)));
}

} // namespace Memory