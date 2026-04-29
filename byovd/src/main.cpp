// =============================================================================
// ENIKernelDumper - BYOVD-backed Roblox memory snapshot tool
// =============================================================================
//
// One-shot CLI. Workflow:
//
//   1. Locate the signed driver .sys we ship alongside this exe
//      (look in the exe's directory).
//   2. Find RobloxPlayerBeta.exe by name (FindProcessByName below).
//   3. LoadDriver() - copy .sys, register service, start, get device.
//   4. Iterate the target's modules (read PEB.Ldr remotely via
//      KernelRead) and pick dump targets:
//        - Modules with a .byfron section
//        - Or modules named RobloxPlayerBeta.{exe,dll}
//   5. For each target: page-walk the image extent, KernelRead each
//      4 KB page, write to <localappdata>/ENI/logs/<basename>_<base>_<size>.bin.
//   6. UnloadDriver() - tear everything down.
//
// All of this runs in a separate process from Roblox. Roblox doesn't
// know we exist - we never touched its handle table or address space
// from user-mode. Hyperion's only avenue to detect us is enumerating
// loaded kernel modules during the ~2-3 second window our driver is up.
// =============================================================================

#include "../include/DriverLoader.h"
#include "../include/KernelRead.h"

#include <windows.h>
#include <winternl.h>     // UNICODE_STRING (and the no-op PROCESS_BASIC_INFORMATION
                          // we explicitly shadow below)
#include <tlhelp32.h>
#include <shlobj.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdint>

#pragma comment(lib, "shell32.lib")

using namespace ENI::Byovd;

namespace {

// -----------------------------------------------------------------------------
// Stuff we shamelessly lift from payload/dumper/src/DumperEntry.cpp
// (with the in-process memcpy swapped for KernelRead)
// -----------------------------------------------------------------------------

struct ImageExtent {
    std::uintptr_t base;
    std::size_t    size;
    std::wstring   name;       // basename (e.g. "RobloxPlayerBeta.exe")
    bool           hasByfron;
};

// Find a process by case-insensitive basename match.
DWORD FindProcessByName(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                found = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// Enumerate loaded modules in a remote process by walking its PEB.
//
// We use NtQueryInformationProcess(ProcessBasicInformation) to get the
// remote PEB address - PROCESS_QUERY_LIMITED_INFORMATION is enough on
// Win10+, which PPL allows. Then we KernelRead the PEB struct, then the
// LDR struct it points at, then walk InLoadOrderModuleList.
typedef LONG (NTAPI *NtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

struct PROCESS_BASIC_INFORMATION_min {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
};

// PEB layout (relevant fields only). Offsets stable on x64 Win10+.
struct PEB_min {
    BYTE    Reserved1[2];
    BYTE    BeingDebugged;
    BYTE    Reserved2[1];
    PVOID   Reserved3[2];
    PVOID   Ldr;                 // PPEB_LDR_DATA
    // ... rest unused
};

struct LIST_ENTRY_x64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
};

struct PEB_LDR_DATA_min {
    ULONG          Length;
    BOOLEAN        Initialized;
    PVOID          SsHandle;
    LIST_ENTRY_x64 InLoadOrderModuleList;
    // ... rest unused
};

// Slice of LDR_DATA_TABLE_ENTRY we actually use.
struct LDR_DATA_TABLE_ENTRY_min {
    LIST_ENTRY_x64 InLoadOrderLinks;
    LIST_ENTRY_x64 InMemoryOrderLinks;
    LIST_ENTRY_x64 InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    BYTE           _pad1[4];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

bool ReadStruct(const DriverHandle& drv, DWORD pid,
                std::uintptr_t va, void* out, std::size_t size) {
    return KernelReadProcessMemory(drv, pid, va, out, size) == size;
}

std::wstring ReadUnicodeString(const DriverHandle& drv, DWORD pid,
                               const UNICODE_STRING& us) {
    if (us.Length == 0 || !us.Buffer) return L"";
    std::vector<wchar_t> buf(us.Length / 2 + 1, 0);
    std::size_t got = KernelReadProcessMemory(
        drv, pid, reinterpret_cast<std::uintptr_t>(us.Buffer),
        buf.data(), us.Length);
    if (got != us.Length) return L"";
    return std::wstring(buf.data(), us.Length / 2);
}

std::wstring BasenameW(const std::wstring& full) {
    auto pos = full.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? full : full.substr(pos + 1);
}

// Look at the first page of an image to decide if it has a .byfron
// section. We KernelRead the headers, parse the section table inline.
bool ImageHasByfronSection(const DriverHandle& drv, DWORD pid,
                           std::uintptr_t base) {
    unsigned char hdrs[0x1000]{};
    if (KernelReadProcessMemory(drv, pid, base, hdrs, sizeof(hdrs)) != sizeof(hdrs))
        return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hdrs);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x800) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(hdrs + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sect = IMAGE_FIRST_SECTION(nt);
    auto remaining = (sizeof(hdrs) - (reinterpret_cast<unsigned char*>(sect) - hdrs))
                     / sizeof(IMAGE_SECTION_HEADER);
    auto count = (nt->FileHeader.NumberOfSections < remaining)
                 ? nt->FileHeader.NumberOfSections : remaining;
    for (unsigned i = 0; i < count; ++i) {
        char name9[9]{};
        std::memcpy(name9, sect[i].Name, 8);
        if (std::strcmp(name9, ".byfron") == 0) return true;
    }
    return false;
}

std::vector<ImageExtent> EnumModules(const DriverHandle& drv, DWORD pid) {
    std::vector<ImageExtent> out;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQueryInformationProcess =
        reinterpret_cast<NtQueryInformationProcess_t>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) return out;

    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return out;

    PROCESS_BASIC_INFORMATION_min pbi{};
    LONG status = NtQueryInformationProcess(
        proc, 0 /* ProcessBasicInformation */,
        &pbi, sizeof(pbi), nullptr);
    CloseHandle(proc);
    if (status < 0 || !pbi.PebBaseAddress) return out;

    PEB_min peb{};
    if (!ReadStruct(drv, pid,
                    reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress),
                    &peb, sizeof(peb)))
        return out;
    if (!peb.Ldr) return out;

    PEB_LDR_DATA_min ldr{};
    if (!ReadStruct(drv, pid, reinterpret_cast<std::uintptr_t>(peb.Ldr),
                    &ldr, sizeof(ldr)))
        return out;

    const std::uintptr_t listHead =
        reinterpret_cast<std::uintptr_t>(peb.Ldr) +
        offsetof(PEB_LDR_DATA_min, InLoadOrderModuleList);
    std::uintptr_t flink = ldr.InLoadOrderModuleList.Flink;
    int safety = 0;
    while (flink && flink != listHead && safety++ < 1024) {
        LDR_DATA_TABLE_ENTRY_min entry{};
        if (!ReadStruct(drv, pid, flink, &entry, sizeof(entry))) break;

        ImageExtent ext{};
        ext.base = reinterpret_cast<std::uintptr_t>(entry.DllBase);
        ext.size = entry.SizeOfImage;
        ext.name = BasenameW(ReadUnicodeString(drv, pid, entry.BaseDllName));

        if (ext.base && ext.size) {
            ext.hasByfron = ImageHasByfronSection(drv, pid, ext.base);
            out.push_back(std::move(ext));
        }
        flink = entry.InLoadOrderLinks.Flink;
    }
    return out;
}

// -----------------------------------------------------------------------------
// Dump output
// -----------------------------------------------------------------------------

std::wstring LogsDir() {
    wchar_t lad[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA,
                                 nullptr, 0, lad)))
        return L"";
    std::wstring out = lad;
    out += L"\\ENI\\logs";
    SHCreateDirectoryExW(nullptr, out.c_str(), nullptr);
    return out;
}

std::wstring DumpFilenameFor(const ImageExtent& m) {
    wchar_t buf[MAX_PATH];
    std::wstring stem = m.name;
    // sanitize . to _ for filesystem ergonomics
    for (auto& c : stem) if (c == L'.') c = L'_';
    swprintf_s(buf, L"%ls_%llx_%zx.bin",
               stem.c_str(), static_cast<unsigned long long>(m.base), m.size);
    return buf;
}

bool DumpModule(const DriverHandle& drv, DWORD pid,
                const ImageExtent& m, const std::wstring& outDir,
                std::size_t& dumpedBytes, std::size_t& failedPages) {
    dumpedBytes = 0;
    failedPages = 0;

    const std::wstring path = outDir + L"\\" + DumpFilenameFor(m);
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;

    constexpr std::size_t PAGE = 0x1000;
    std::vector<unsigned char> page(PAGE);
    std::vector<unsigned char> zero(PAGE, 0);

    for (std::size_t off = 0; off < m.size; off += PAGE) {
        const std::size_t want = (m.size - off < PAGE) ? (m.size - off) : PAGE;
        std::size_t got = KernelReadProcessMemory(
            drv, pid, m.base + off, page.data(), want);

        DWORD wrote = 0;
        if (got == want) {
            WriteFile(f, page.data(), static_cast<DWORD>(want), &wrote, nullptr);
            dumpedBytes += want;
        } else {
            // Hole - write zeros so the file's offsets line up with the
            // virtual layout. The decryption sanity check at the end
            // will tell us if too many pages came back zero.
            WriteFile(f, zero.data(), static_cast<DWORD>(want), &wrote, nullptr);
            failedPages++;
        }
    }

    CloseHandle(f);
    return true;
}

// -----------------------------------------------------------------------------
// Driver discovery
// -----------------------------------------------------------------------------

std::wstring ExeDir() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s = path;
    auto pos = s.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"." : s.substr(0, pos);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    // Args: optional --driver <path>, optional --pid <n>, optional --device <name>
    // Defaults match our own EniDrv.sys (bin/EniDrv.sys, \\.\EniDrv).
    std::wstring driverPath = ExeDir() + L"\\EniDrv.sys";
    std::wstring deviceName = L"\\\\.\\EniDrv";
    DWORD pid = 0;

    for (int i = 1; i < argc - 1; ++i) {
        if (wcscmp(argv[i], L"--driver") == 0) driverPath = argv[++i];
        else if (wcscmp(argv[i], L"--device") == 0) deviceName = argv[++i];
        else if (wcscmp(argv[i], L"--pid") == 0) pid = _wtoi(argv[++i]);
    }

    if (pid == 0) {
        pid = FindProcessByName(L"RobloxPlayerBeta.exe");
        if (pid == 0) {
            wprintf(L"[!] RobloxPlayerBeta.exe not running. Launch Roblox first.\n");
            return 1;
        }
    }
    wprintf(L"[+] Target PID: %u\n", pid);
    wprintf(L"[+] Driver: %ls\n", driverPath.c_str());
    wprintf(L"[+] Device: %ls\n", deviceName.c_str());

    wprintf(L"[*] Loading driver ...\n");
    DriverHandle drv = LoadDriver(driverPath, deviceName);
    if (drv.device == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] LoadDriver failed: GetLastError = %lu\n", GetLastError());
        return 2;
    }
    wprintf(L"[+] Driver up. Service: %ls\n", drv.serviceName.c_str());

    wprintf(L"[*] Enumerating modules in target ...\n");
    auto modules = EnumModules(drv, pid);
    wprintf(L"[+] %zu modules\n", modules.size());

    const std::wstring logsDir = LogsDir();
    if (logsDir.empty()) {
        wprintf(L"[!] Could not resolve %%LOCALAPPDATA%%\\ENI\\logs\n");
        UnloadDriver(drv);
        return 3;
    }
    wprintf(L"[+] Output: %ls\n", logsDir.c_str());

    int dumpsAttempted = 0, dumpsOK = 0;
    for (const auto& m : modules) {
        const bool isRoblox = (_wcsicmp(m.name.c_str(), L"RobloxPlayerBeta.exe") == 0
                            || _wcsicmp(m.name.c_str(), L"RobloxPlayerBeta.dll") == 0);
        if (!m.hasByfron && !isRoblox) continue;

        wprintf(L"[*] Dumping %ls @ %llx (%zu bytes, byfron=%c) ...\n",
                m.name.c_str(),
                static_cast<unsigned long long>(m.base),
                m.size,
                m.hasByfron ? L'Y' : L'N');
        dumpsAttempted++;
        std::size_t dumped = 0, failed = 0;
        if (DumpModule(drv, pid, m, logsDir, dumped, failed)) {
            dumpsOK++;
            wprintf(L"    -> %zu bytes dumped, %zu pages unreadable\n",
                    dumped, failed);
        } else {
            wprintf(L"    -> FAILED to open output file\n");
        }
    }

    wprintf(L"[*] Tearing down driver ...\n");
    UnloadDriver(drv);
    wprintf(L"[+] Done. %d/%d dumps OK.\n", dumpsOK, dumpsAttempted);
    return (dumpsOK > 0) ? 0 : 4;
}
