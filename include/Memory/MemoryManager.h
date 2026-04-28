#pragma once

#include "../pch.h"

namespace Memory {

// Memory protection constants
enum class Protection : DWORD {
    Read = PAGE_READONLY,
    Write = PAGE_WRITECOPY,
    Execute = PAGE_EXECUTE,
    ReadWrite = PAGE_READWRITE,
    ReadExecute = PAGE_EXECUTE_READ,
    ReadWriteExecute = PAGE_EXECUTE_READWRITE,
    NoAccess = PAGE_NOACCESS,
    Guard = PAGE_GUARD
};

// RAII wrapper for remote memory
class RemoteBuffer {
public:
    RemoteBuffer() = default;

    RemoteBuffer(uptr address, usize size, bool owns = true)
        : m_Address(address), m_Size(size), m_Owns(owns) {}

    RemoteBuffer(RemoteBuffer&& other) noexcept
        : m_Address(other.m_Address), m_Size(other.m_Size), m_Owns(other.m_Owns) {
        other.m_Address = 0;
        other.m_Size = 0;
        other.m_Owns = false;
    }

    RemoteBuffer& operator=(RemoteBuffer&& other) noexcept {
        if (this != &other) {
            Free();
            m_Address = other.m_Address;
            m_Size = other.m_Size;
            m_Owns = other.m_Owns;
            other.m_Address = 0;
            other.m_Size = 0;
            other.m_Owns = false;
        }
        return *this;
    }

    ~RemoteBuffer() { Free(); }

    RemoteBuffer(const RemoteBuffer&) = delete;
    RemoteBuffer& operator=(const RemoteBuffer&) = delete;

    bool IsValid() const { return m_Address != 0 && m_Size > 0; }
    uptr GetAddress() const { return m_Address; }
    usize GetSize() const { return m_Size; }
    void* GetPointer() const { return reinterpret_cast<void*>(m_Address); }

    void Detach() { m_Owns = false; }

private:
    void Free();

    uptr m_Address = 0;
    usize m_Size = 0;
    bool m_Owns = false;
};

class MemoryManager {
public:
    static MemoryManager& Get();

    // Process information
    void SetProcess(HANDLE hProcess);
    HANDLE GetProcess() const;
    DWORD GetPID() const;

    // Basic operations
    template<typename T>
    static T Read(uptr address);

    template<typename T>
    static void Write(uptr address, T value);

    static std::vector<u8> ReadBytes(uptr address, usize size);

    template<typename T>
    static bool WriteArray(uptr address, const T* data, usize count);

    // Remote memory allocation
    RemoteBuffer Allocate(usize size, Protection prot = Protection::ReadWriteExecute);
    RemoteBuffer AllocateNear(uptr target, usize size, usize maxDistance = 0x10000000);
    bool Free(RemoteBuffer& buffer);

    // Protection changes
    bool Protect(uptr address, usize size, Protection prot);
    Protection QueryProtection(uptr address);

    // Thread operations
    uptr CreateRemoteThread(uptr address, uptr parameter = 0);
    bool QueueApc(uptr thread, uptr address, uptr parameter = 0);

    // Process introspection
    static uptr GetBaseAddress(HANDLE hProcess);
    static usize GetImageSize(HANDLE hProcess);
    static bool IsProcess64Bit(HANDLE hProcess);

    // String operations
    static std::string ReadString(uptr address, usize maxLength = 256);
    static std::wstring ReadWString(uptr address, usize maxLength = 256);
    static bool WriteString(uptr address, const std::string& str);
    static bool WriteWString(uptr address, const std::wstring& wstr);

    // Function calling
    template<typename Ret = uptr, typename... Args>
    Ret Call(uptr address, Args... args);

    // Virtual method table
    static uptr ReadVTABLE(uptr object, int index);

private:
    MemoryManager() = default;
    MemoryManager(const MemoryManager&) = delete;
    MemoryManager& operator=(const MemoryManager&) = delete;

    HANDLE m_hProcess = nullptr;
    DWORD m_PID = 0;
};

// Template implementations
template<typename T>
T MemoryManager::Read(uptr address) {
    T value{};
    if (auto& mm = Get(); mm.m_hProcess) {
        SIZE_T bytesRead = 0;
        ReadProcessMemory(mm.m_hProcess, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), &bytesRead);
    }
    return value;
}

template<typename T>
void MemoryManager::Write(uptr address, T value) {
    if (auto& mm = Get(); mm.m_hProcess) {
        SIZE_T bytesWritten = 0;
        WriteProcessMemory(mm.m_hProcess, reinterpret_cast<LPVOID>(address), &value, sizeof(T), &bytesWritten);
    }
}

template<typename T>
bool MemoryManager::WriteArray(uptr address, const T* data, usize count) {
    if (auto& mm = Get(); mm.m_hProcess) {
        SIZE_T bytesWritten = 0;
        return WriteProcessMemory(mm.m_hProcess, reinterpret_cast<LPVOID>(address), data, sizeof(T) * count, &bytesWritten) != 0;
    }
    return false;
}

template<typename Ret, typename... Args>
Ret MemoryManager::Call(uptr address, Args... args) {
    if (!Get().m_hProcess) return Ret{};

    // Create invocation buffer
    using FuncType = Ret(*)(Args...);
    auto func = reinterpret_cast<FuncType>(address);

    if constexpr (std::is_void_v<Ret>) {
        func(args...);
    } else {
        return func(args...);
    }
}

} // namespace Memory