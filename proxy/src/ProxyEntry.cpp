// =============================================================================
// ProxyEntry.cpp - libHttpClient.GDK.dll search-order-hijack dumper
// =============================================================================
//
// What this DLL does, end to end:
//
//   1. Operator drops bin/libHttpClient.GDK.dll into Roblox's install dir
//      (next to RobloxPlayerBeta.exe). The filename matches the basename
//      Roblox lists in its delay-load import table.
//   2. Roblox starts. RobloxPlayerBeta.exe's static loader resolves the
//      delay-load entry on first call (or, on some Windows versions,
//      eagerly during image initialization). Either way, our DLL gets
//      pulled in via LoadLibraryExW, with the install dir winning the
//      search order ahead of System32.
//   3. Our DllMain runs ON THE LOADER LOCK. We do nothing real there -
//      just spawn a worker thread and return TRUE.
//   4. Worker thread polls until the engine .text section's first bytes
//      look like decrypted x64 code (function prologue patterns), then
//      runs the v2 dump pipeline:
//        - Module census (PEB walk)
//        - Per-module pagewise dump for any .byfron-bearing module
//        - Sanity scan for the literal "RobloxPlayerBeta"
//      Output goes under %LOCALAPPDATA%\ENI\logs\.
//   5. Worker thread exits. Our DLL stays loaded. Operator collects the
//      .bin files when Roblox is still running, or after it exits.
//
// =============================================================================
//
// CRT environment: this DLL is loaded by LdrLoadDll inside a fully booted
// process. The CRT TLS callbacks fire normally, std::* is safe, the heap
// is initialized. NONE of the freestanding constraints from
// payload/dumper/ apply here. We could use std::ofstream / std::wstring /
// the full STL.
//
// In practice we keep the dumper primitives hand-rolled (Logger,
// AppendStr, AppendHex, AppendDec) because they're already proven and
// porting them costs us nothing. The CRT availability matters only for
// SHGetFolderPathW + std::thread-style ergonomics, which we don't even
// use - bare CreateThread does the job.
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdio>      // _snprintf_s, swprintf_s for sentinel write
#include <windows.h>
#include <winternl.h>
#include <shlobj.h>

#include "Pagewise.h"

// -----------------------------------------------------------------------------
// Forward decls of the byte-level primitives we share with the v2 dumper.
// Implementations are at the bottom of this file in an anonymous namespace.
// -----------------------------------------------------------------------------

namespace {

constexpr std::size_t kPageSize = 4096;
constexpr DWORD kPostInitDelayMs = 5000;
constexpr DWORD kMaxDecryptWaitMs = 30000;
constexpr DWORD kPollIntervalMs = 250;

// -----------------------------------------------------------------------------
// CRT-free byte ops (ported from payload/dumper/src/DumperEntry.cpp:76-92).
// We prefer these over std::memcpy/memset to keep the dump-side codegen
// hermetic - useful when reasoning about what runs after Hyperion is up.
// -----------------------------------------------------------------------------

inline void ZeroBytes(void* dst, std::size_t n) {
    auto* p = static_cast<volatile std::uint8_t*>(dst);
    for (std::size_t i = 0; i < n; ++i) p[i] = 0;
}

inline void CopyBytes(void* dst, const void* src, std::size_t n) {
    auto*       d = static_cast<std::uint8_t*>(dst);
    const auto* s = static_cast<const std::uint8_t*>(src);
    for (std::size_t i = 0; i < n; ++i) d[i] = s[i];
}

inline std::size_t WLen(const wchar_t* s) {
    if (!s) return 0;
    std::size_t n = 0;
    while (s[n]) ++n;
    return n;
}

// -----------------------------------------------------------------------------
// ASCII formatters (DumperEntry.cpp:100-136).
// -----------------------------------------------------------------------------

inline std::size_t AppendStr(char* buf, std::size_t cap, std::size_t len, const char* s) {
    while (*s && len + 1 < cap) buf[len++] = *s++;
    buf[len] = '\0';
    return len;
}

inline std::size_t AppendHex(char* buf, std::size_t cap, std::size_t len,
                             std::uint64_t v, int digits) {
    if (len + static_cast<std::size_t>(digits) + 1 >= cap) return len;
    static const char hex[] = "0123456789ABCDEF";
    for (int i = digits - 1; i >= 0; --i) {
        buf[len + i] = hex[v & 0xF];
        v >>= 4;
    }
    len += digits;
    buf[len] = '\0';
    return len;
}

inline std::size_t AppendDec(char* buf, std::size_t cap, std::size_t len,
                             std::uint64_t v) {
    char tmp[24];
    int n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v) {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    while (n > 0 && len + 1 < cap) buf[len++] = tmp[--n];
    buf[len] = '\0';
    return len;
}

// -----------------------------------------------------------------------------
// PEB walk + section table (DumperEntry.cpp:146-251).
// -----------------------------------------------------------------------------

struct LDR_DATA_TABLE_ENTRY_min {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

inline PEB* GetPEB() {
    return reinterpret_cast<PEB*>(__readgsqword(0x60));
}

inline bool BaseNameEqualsCI(const UNICODE_STRING& s, const wchar_t* expected) {
    if (!s.Buffer || !expected) return false;
    const std::size_t expectedLen = WLen(expected);
    if (s.Length / sizeof(wchar_t) != expectedLen) return false;
    for (std::size_t i = 0; i < expectedLen; ++i) {
        wchar_t a = s.Buffer[i];
        wchar_t b = expected[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b - L'A' + L'a');
        if (a != b) return false;
    }
    return true;
}

using ModuleCb = bool (*)(const LDR_DATA_TABLE_ENTRY_min*, void*);

void EnumModules(ModuleCb cb, void* ctx) {
    PEB* peb = GetPEB();
    if (!peb || !peb->Ldr) return;

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;

    int guard = 4096;
    for (LIST_ENTRY* cur = head->Flink;
         cur && cur != head && guard > 0;
         cur = cur->Flink, --guard) {
        auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_min*>(
            reinterpret_cast<std::uint8_t*>(cur) -
            offsetof(LDR_DATA_TABLE_ENTRY_min, InMemoryOrderLinks));
        if (!cb(entry, ctx)) break;
    }
}

bool FindSection(std::uintptr_t moduleBase,
                 const std::uint8_t name[8],
                 std::uintptr_t& outStart,
                 std::size_t& outSize) {
    if (!moduleBase) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        bool eq = true;
        for (int j = 0; j < 8; ++j) {
            if (sec->Name[j] != name[j]) { eq = false; break; }
        }
        if (eq) {
            outStart = moduleBase + sec->VirtualAddress;
            outSize  = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

bool FindSectionByName(std::uintptr_t moduleBase, const char* asciiName,
                       std::uintptr_t& outStart, std::size_t& outSize) {
    std::uint8_t pad[8] = {};
    for (int i = 0; i < 8 && asciiName[i]; ++i) {
        pad[i] = static_cast<std::uint8_t>(asciiName[i]);
    }
    return FindSection(moduleBase, pad, outStart, outSize);
}

inline bool HasByfronSection(std::uintptr_t moduleBase) {
    std::uintptr_t s = 0;
    std::size_t    n = 0;
    return FindSectionByName(moduleBase, ".byfron", s, n);
}

// -----------------------------------------------------------------------------
// Logger (DumperEntry.cpp:257-282).
// -----------------------------------------------------------------------------

struct Logger {
    HANDLE hFile = INVALID_HANDLE_VALUE;
};

void LogOpen(Logger& L, const wchar_t* path) {
    if (!path || !*path) return;
    L.hFile = CreateFileW(path,
                          FILE_APPEND_DATA,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          nullptr,
                          OPEN_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                          nullptr);
    if (L.hFile != INVALID_HANDLE_VALUE) {
        const char* banner = "\r\n----- ENIProxy boot -----\r\n";
        DWORD w = 0;
        WriteFile(L.hFile, banner, 30, &w, nullptr);
    }
}

void LogRaw(Logger& L, const char* line, std::size_t n) {
    if (L.hFile == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(L.hFile, line, static_cast<DWORD>(n), &w, nullptr);
    WriteFile(L.hFile, "\r\n", 2, &w, nullptr);
}

inline void LogLit(Logger& L, const char* lit) {
    if (L.hFile == INVALID_HANDLE_VALUE) return;
    std::size_t n = 0;
    while (lit[n]) ++n;
    LogRaw(L, lit, n);
}

// -----------------------------------------------------------------------------
// Path composition (DumperEntry.cpp:288-365).
// -----------------------------------------------------------------------------

void ComposePathW(const wchar_t* dir, const wchar_t* leaf,
                  wchar_t* out, std::size_t outCap) {
    if (!dir || !*dir || !out || outCap < 32) {
        if (out && outCap) out[0] = L'\0';
        return;
    }
    const std::size_t n = WLen(dir);
    const std::size_t m = WLen(leaf);
    if (n + m + 2 >= outCap) { out[0] = L'\0'; return; }

    for (std::size_t i = 0; i < n; ++i) out[i] = dir[i];
    std::size_t cur = n;
    if (cur > 0 && out[cur - 1] != L'\\' && out[cur - 1] != L'/') {
        out[cur++] = L'\\';
    }
    for (std::size_t i = 0; i <= m; ++i) out[cur + i] = leaf[i];
}

void ComposeNamedOutputPath(const wchar_t* dir, const wchar_t* stem,
                            std::uint64_t base, std::uint64_t size,
                            const wchar_t* ext,
                            wchar_t* out, std::size_t outCap) {
    wchar_t leaf[160];
    static const wchar_t hex[] = L"0123456789ABCDEF";

    std::size_t i = 0;
    if (stem) {
        for (std::size_t j = 0; stem[j] && i < 80; ++j) {
            wchar_t c = stem[j];
            if (!((c >= L'a' && c <= L'z') ||
                  (c >= L'A' && c <= L'Z') ||
                  (c >= L'0' && c <= L'9') ||
                   c == L'_' || c == L'-')) {
                c = L'_';
            }
            if (c >= L'A' && c <= L'Z') {
                c = static_cast<wchar_t>(c - L'A' + L'a');
            }
            leaf[i++] = c;
        }
    }
    if (i == 0) {
        const wchar_t* fallback = L"mod";
        for (std::size_t j = 0; fallback[j]; ++j) leaf[i++] = fallback[j];
    }
    leaf[i++] = L'_';
    for (int b = 15; b >= 0; --b) leaf[i++] = hex[(base >> (b * 4)) & 0xF];
    leaf[i++] = L'_';
    for (int b = 15; b >= 0; --b) leaf[i++] = hex[(size >> (b * 4)) & 0xF];
    leaf[i++] = L'.';
    for (std::size_t j = 0; ext[j]; ++j) leaf[i++] = ext[j];
    leaf[i] = L'\0';

    ComposePathW(dir, leaf, out, outCap);
}

void StemFromUnicodeString(const UNICODE_STRING& s, wchar_t* out, std::size_t cap) {
    if (cap < 2 || !s.Buffer) { if (cap) out[0] = L'\0'; return; }
    const std::size_t n = s.Length / sizeof(wchar_t);
    std::size_t k = 0;
    for (std::size_t i = 0; i < n && k + 1 < cap; ++i) {
        wchar_t c = s.Buffer[i];
        if (c == L'.') c = L'_';
        out[k++] = c;
    }
    out[k] = L'\0';
}

// -----------------------------------------------------------------------------
// VirtualQuery walk for image extent (DumperEntry.cpp:372-394).
// -----------------------------------------------------------------------------

void DiscoverImageExtent(std::uintptr_t startAddr,
                         std::uintptr_t& outBase,
                         std::size_t& outSize) {
    outBase = startAddr;
    outSize = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<void*>(startAddr), &mbi, sizeof(mbi))) {
        return;
    }

    const auto allocBase = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
    if (!allocBase) return;
    outBase = allocBase;

    std::uintptr_t cursor = allocBase;
    while (true) {
        if (!VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi))) break;
        if (reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) != allocBase) break;
        cursor = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    outSize = static_cast<std::size_t>(cursor - allocBase);
}

// -----------------------------------------------------------------------------
// Region report (DumperEntry.cpp:400-462).
// -----------------------------------------------------------------------------

void WriteRegionLine(HANDLE hFile, const MEMORY_BASIC_INFORMATION& mbi) {
    std::uint8_t head[16] = {};
    if (mbi.State == MEM_COMMIT &&
        mbi.Protect != PAGE_NOACCESS &&
        !(mbi.Protect & PAGE_GUARD)) {
        const std::size_t n = mbi.RegionSize < sizeof(head) ? mbi.RegionSize : sizeof(head);
        ENI::Dumper::ReadPageSEH(head, mbi.BaseAddress, n);
    }

    char line[320];
    std::size_t L = 0;
    L = AppendStr(line, sizeof(line), L, "AllocBase=0x");
    L = AppendHex(line, sizeof(line), L,
        reinterpret_cast<std::uintptr_t>(mbi.AllocationBase), 16);
    L = AppendStr(line, sizeof(line), L, "  Base=0x");
    L = AppendHex(line, sizeof(line), L,
        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), 16);
    L = AppendStr(line, sizeof(line), L, "  Size=0x");
    L = AppendHex(line, sizeof(line), L, mbi.RegionSize, 10);
    L = AppendStr(line, sizeof(line), L, "  State=");
    L = AppendDec(line, sizeof(line), L, mbi.State);
    L = AppendStr(line, sizeof(line), L, "  Protect=0x");
    L = AppendHex(line, sizeof(line), L, mbi.Protect, 8);
    L = AppendStr(line, sizeof(line), L, "  Type=");
    L = AppendDec(line, sizeof(line), L, mbi.Type);
    L = AppendStr(line, sizeof(line), L, "  Head=[");
    for (int i = 0; i < 16; ++i) {
        L = AppendHex(line, sizeof(line), L, head[i], 2);
        if (i < 15) L = AppendStr(line, sizeof(line), L, " ");
    }
    L = AppendStr(line, sizeof(line), L, "]\r\n");

    DWORD w = 0;
    WriteFile(hFile, line, static_cast<DWORD>(L), &w, nullptr);
}

std::uint32_t WriteRegionReport(const wchar_t* path, std::uintptr_t imageBase) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    std::uint32_t matched = 0;
    std::uintptr_t addr = 0;
    while (true) {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T n = VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi));
        if (n == 0) break;
        if (mbi.RegionSize == 0) break;

        if (reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) == imageBase) {
            WriteRegionLine(hFile, mbi);
            ++matched;
        }

        const std::uintptr_t next =
            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    CloseHandle(hFile);
    return matched;
}

// -----------------------------------------------------------------------------
// Pagewise dump (DumperEntry.cpp:468-528).
// -----------------------------------------------------------------------------

struct DumpStats {
    std::uint64_t BytesWritten;
    std::uint32_t PagesCopied;
    std::uint32_t PagesSkippedUncommitted;
    std::uint32_t PagesSkippedProtect;
    std::uint32_t PagesSkippedSEH;
};

DumpStats WritePagewiseDump(const wchar_t* path,
                            std::uintptr_t imageBase,
                            std::size_t imageSize) {
    DumpStats s{};

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return s;

    auto* buf = static_cast<std::uint8_t*>(
        HeapAlloc(GetProcessHeap(), 0, kPageSize));
    if (!buf) { CloseHandle(hFile); return s; }

    const std::uintptr_t end = imageBase + imageSize;
    for (std::uintptr_t page = imageBase; page < end; page += kPageSize) {
        const std::size_t n =
            (end - page) < kPageSize ? static_cast<std::size_t>(end - page) : kPageSize;

        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T qn = VirtualQuery(reinterpret_cast<void*>(page), &mbi, sizeof(mbi));

        bool skip = false;
        if (qn == 0 || mbi.State != MEM_COMMIT) {
            skip = true;
            ++s.PagesSkippedUncommitted;
        } else if (mbi.Protect == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) {
            skip = true;
            ++s.PagesSkippedProtect;
        }

        if (skip) {
            ZeroBytes(buf, n);
        } else {
            const bool ok = ENI::Dumper::ReadPageSEH(
                buf, reinterpret_cast<const void*>(page), n);
            if (!ok) {
                ZeroBytes(buf, n);
                ++s.PagesSkippedSEH;
            } else {
                ++s.PagesCopied;
            }
        }

        DWORD w = 0;
        if (WriteFile(hFile, buf, static_cast<DWORD>(n), &w, nullptr) && w == n) {
            s.BytesWritten += w;
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(hFile);
    return s;
}

// -----------------------------------------------------------------------------
// Sanity scan (DumperEntry.cpp:537-586).
// -----------------------------------------------------------------------------

std::uintptr_t FindNeedle(std::uintptr_t base, std::size_t size,
                          const std::uint8_t* needle, std::size_t needleLen) {
    if (needleLen == 0 || size < needleLen) return 0;
    const auto* p = reinterpret_cast<const std::uint8_t*>(base);
    const std::size_t last = size - needleLen;

    for (std::size_t i = 0; i <= last; ++i) {
        std::uint8_t window[32];
        const bool ok = ENI::Dumper::ReadPageSEH(window, p + i, needleLen);
        if (!ok) {
            const std::uintptr_t addr = base + i;
            const std::uintptr_t nextPage = (addr + kPageSize) & ~(kPageSize - 1);
            const std::size_t jump = static_cast<std::size_t>(nextPage - addr);
            if (jump == 0) break;
            i += jump - 1;
            continue;
        }
        bool match = true;
        for (std::size_t k = 0; k < needleLen; ++k) {
            if (window[k] != needle[k]) { match = false; break; }
        }
        if (match) return base + i;
    }
    return 0;
}

void SanityScan(Logger& L, std::uintptr_t imageBase, std::size_t imageSize) {
    static const std::uint8_t needle[] = {
        'R','o','b','l','o','x','P','l','a','y','e','r','B','e','t','a'
    };

    const std::uintptr_t hit = FindNeedle(imageBase, imageSize, needle, sizeof(needle));

    char line[128];
    std::size_t n = 0;
    if (hit) {
        n = AppendStr(line, sizeof(line), n, "[proxy] sanity scan: hit at 0x");
        n = AppendHex(line, sizeof(line), n, hit, 16);
        n = AppendStr(line, sizeof(line), n, " rva=0x");
        n = AppendHex(line, sizeof(line), n, hit - imageBase, 8);
    } else {
        n = AppendStr(line, sizeof(line), n,
            "[proxy] sanity scan: needle not found");
    }
    LogRaw(L, line, n);
}

// -----------------------------------------------------------------------------
// Dump-target predicate (DumperEntry.cpp:606-614). Same rules as v2.
// -----------------------------------------------------------------------------

bool ShouldDumpModule(const LDR_DATA_TABLE_ENTRY_min* e) {
    const auto base = reinterpret_cast<std::uintptr_t>(e->DllBase);
    if (HasByfronSection(base)) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxPlayerBeta.exe")) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxPlayerBeta.dll")) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxStudioBeta.exe")) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxStudioBeta.dll")) return true;
    return false;
}

// -----------------------------------------------------------------------------
// Per-module dump pipeline (DumperEntry.cpp:616-691).
// -----------------------------------------------------------------------------

struct CensusCtx {
    Logger& L;
    int     Count;
};

struct DumpCtx {
    const wchar_t* LogsDir;
    Logger&        L;
    int            Dumped;
};

void DumpOneModule(DumpCtx& dctx, const LDR_DATA_TABLE_ENTRY_min* e) {
    const auto base = reinterpret_cast<std::uintptr_t>(e->DllBase);
    const std::size_t pe_size = e->SizeOfImage;

    std::uintptr_t walkedBase = 0;
    std::size_t    walkedSize = 0;
    DiscoverImageExtent(base, walkedBase, walkedSize);

    std::size_t dumpSize = pe_size > walkedSize ? pe_size : walkedSize;
    if (dumpSize == 0) {
        LogLit(dctx.L, "[proxy] target: extent zero, skipping");
        return;
    }

    wchar_t stem[160] = {};
    StemFromUnicodeString(e->BaseDllName, stem,
                          sizeof(stem) / sizeof(stem[0]));

    constexpr std::size_t kPathCap = 520;
    wchar_t binPath[kPathCap] = {};
    wchar_t regPath[kPathCap] = {};
    ComposeNamedOutputPath(dctx.LogsDir, stem, base, dumpSize, L"bin",
                           binPath, kPathCap);
    ComposeNamedOutputPath(dctx.LogsDir, stem, base, dumpSize, L"regions.txt",
                           regPath, kPathCap);

    {
        char line[256];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[proxy] === target base=0x");
        n = AppendHex(line, sizeof(line), n, base, 16);
        n = AppendStr(line, sizeof(line), n, " peSize=0x");
        n = AppendHex(line, sizeof(line), n, pe_size, 8);
        n = AppendStr(line, sizeof(line), n, " walked=0x");
        n = AppendHex(line, sizeof(line), n, walkedSize, 8);
        n = AppendStr(line, sizeof(line), n, " dumpSize=0x");
        n = AppendHex(line, sizeof(line), n, dumpSize, 8);
        LogRaw(dctx.L, line, n);
    }

    const std::uint32_t regions = WriteRegionReport(regPath, base);
    {
        char line[80];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[proxy] regions matched: ");
        n = AppendDec(line, sizeof(line), n, regions);
        LogRaw(dctx.L, line, n);
    }

    const DumpStats s = WritePagewiseDump(binPath, base, dumpSize);
    {
        char line[256];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[proxy] dump: bytes=");
        n = AppendDec(line, sizeof(line), n, s.BytesWritten);
        n = AppendStr(line, sizeof(line), n, " copied=");
        n = AppendDec(line, sizeof(line), n, s.PagesCopied);
        n = AppendStr(line, sizeof(line), n, " skipUncommit=");
        n = AppendDec(line, sizeof(line), n, s.PagesSkippedUncommitted);
        n = AppendStr(line, sizeof(line), n, " skipProtect=");
        n = AppendDec(line, sizeof(line), n, s.PagesSkippedProtect);
        n = AppendStr(line, sizeof(line), n, " skipSEH=");
        n = AppendDec(line, sizeof(line), n, s.PagesSkippedSEH);
        LogRaw(dctx.L, line, n);
    }

    SanityScan(dctx.L, base, dumpSize);
    ++dctx.Dumped;
}

bool DumpCallback(const LDR_DATA_TABLE_ENTRY_min* e, void* ctx) {
    auto* dctx = static_cast<DumpCtx*>(ctx);
    if (ShouldDumpModule(e)) {
        DumpOneModule(*dctx, e);
    }
    return true;
}

bool CensusCallback(const LDR_DATA_TABLE_ENTRY_min* e, void* ctx) {
    auto* state = static_cast<CensusCtx*>(ctx);
    ++state->Count;

    const auto base = reinterpret_cast<std::uintptr_t>(e->DllBase);
    const std::size_t size = e->SizeOfImage;
    const bool hasByfron = HasByfronSection(base);

    char line[400];
    std::size_t n = 0;
    n = AppendStr(line, sizeof(line), n, "[proxy] mod base=0x");
    n = AppendHex(line, sizeof(line), n, base, 16);
    n = AppendStr(line, sizeof(line), n, " size=0x");
    n = AppendHex(line, sizeof(line), n, size, 8);
    n = AppendStr(line, sizeof(line), n, " byfron=");
    n = AppendStr(line, sizeof(line), n, hasByfron ? "Y" : "N");
    n = AppendStr(line, sizeof(line), n, " name=");
    if (e->BaseDllName.Buffer) {
        const std::size_t wn = e->BaseDllName.Length / sizeof(wchar_t);
        const std::size_t lim = wn > 96 ? 96 : wn;
        for (std::size_t i = 0; i < lim && n + 1 < sizeof(line); ++i) {
            wchar_t c = e->BaseDllName.Buffer[i];
            line[n++] = (c >= 0x20 && c < 0x7F)
                        ? static_cast<char>(c) : '?';
        }
        line[n] = '\0';
    }
    LogRaw(state->L, line, n);
    return true;
}

// -----------------------------------------------------------------------------
// Decryption-readiness probe.
//
// On entry to our DllMain the engine .text MAY still be ciphertext - the
// loader can resolve our delay-import slot before stage-2 decryption has
// run if Roblox eagerly resolves the import table during image init.
//
// Plaintext x64 code is overwhelmingly recognizable: function prologues
// like `48 89 5C 24` (mov [rsp+X], rbx), `40 53` (push rbx), `48 83 EC`
// (sub rsp, imm) appear hundreds of times per MB. Ciphertext is uniform
// random distribution. We sniff the first 64 KB of the EXE's .text and
// count prologue hits; below a threshold we sleep and retry.
//
// This is a heuristic - it can yield false positives on a single page
// of plaintext (e.g. small visible bootstrap). But sampling 64 KB makes
// the false-positive probability vanishingly small for high-entropy
// ciphertext.
// -----------------------------------------------------------------------------

bool LooksLikePlaintextCode(std::uintptr_t base, std::size_t scanLen) {
    const std::size_t nPages = (scanLen + kPageSize - 1) / kPageSize;
    int hits = 0;
    int pagesScanned = 0;

    for (std::size_t p = 0; p < nPages; ++p) {
        std::uint8_t window[kPageSize];
        const std::uintptr_t addr = base + p * kPageSize;
        const bool ok = ENI::Dumper::ReadPageSEH(
            window, reinterpret_cast<const void*>(addr), kPageSize);
        if (!ok) continue;
        ++pagesScanned;

        for (std::size_t i = 0; i + 4 < kPageSize; ++i) {
            // 48 89 5C 24 ?? - mov [rsp+disp8], rbx
            if (window[i] == 0x48 && window[i+1] == 0x89 &&
                window[i+2] == 0x5C && window[i+3] == 0x24) ++hits;
            // 48 83 EC ?? - sub rsp, imm8
            else if (window[i] == 0x48 && window[i+1] == 0x83 &&
                     window[i+2] == 0xEC) ++hits;
            // 40 53 - push rbx (REX.B)
            else if (window[i] == 0x40 && window[i+1] == 0x53) ++hits;
            // 40 55 - push rbp
            else if (window[i] == 0x40 && window[i+1] == 0x55) ++hits;
        }
    }

    if (pagesScanned == 0) return false;
    // Threshold: at least ~20 prologue-shaped hits per scanned page.
    // Plaintext code easily clears 100 per page; ciphertext averages
    // (4 patterns * 65536 byte positions * (1/256)^pattern_len) ~= 5
    // expected hits per page from random bytes alone, so 20 is a
    // comfortable margin.
    return hits >= pagesScanned * 20;
}

bool FindRobloxPlayerExe(std::uintptr_t& outBase, std::size_t& outSize) {
    struct FindCtx {
        std::uintptr_t Base;
        std::size_t Size;
        bool Found;
    } ctx{0, 0, false};

    auto cb = [](const LDR_DATA_TABLE_ENTRY_min* e, void* p) -> bool {
        auto* c = static_cast<FindCtx*>(p);
        if (BaseNameEqualsCI(e->BaseDllName, L"RobloxPlayerBeta.exe")) {
            c->Base = reinterpret_cast<std::uintptr_t>(e->DllBase);
            c->Size = e->SizeOfImage;
            c->Found = true;
            return false;
        }
        return true;
    };

    EnumModules(cb, &ctx);
    if (!ctx.Found) return false;
    outBase = ctx.Base;
    outSize = ctx.Size;
    return true;
}

// -----------------------------------------------------------------------------
// Output directory: %LOCALAPPDATA%\ENI\logs\
// -----------------------------------------------------------------------------

bool ResolveLogsDir(wchar_t* out, std::size_t cap) {
    if (cap < 64) return false;
    wchar_t local[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local))) {
        return false;
    }
    wchar_t eni[MAX_PATH + 16] = {};
    ComposePathW(local, L"ENI", eni, sizeof(eni) / sizeof(eni[0]));
    CreateDirectoryW(eni, nullptr);

    ComposePathW(eni, L"logs", out, cap);
    CreateDirectoryW(out, nullptr);
    return true;
}

// -----------------------------------------------------------------------------
// Sentinel file: first thing the worker writes, with PID + timestamp,
// so the operator can confirm "yes, our DLL got loaded into Roblox".
// Writing this BEFORE the decryption-wait makes diagnosis easier when
// Roblox crashes mid-poll: we know we got that far.
// -----------------------------------------------------------------------------

void WriteSentinel(const wchar_t* logsDir) {
    wchar_t path[600];
    ComposePathW(logsDir, L"proxy_alive.txt", path, sizeof(path) / sizeof(path[0]));

    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    char buf[256];
    std::size_t n = 0;
    n = AppendStr(buf, sizeof(buf), n, "ENIProxy alive\r\npid=");
    n = AppendDec(buf, sizeof(buf), n, GetCurrentProcessId());
    n = AppendStr(buf, sizeof(buf), n, "\r\ntid=");
    n = AppendDec(buf, sizeof(buf), n, GetCurrentThreadId());
    n = AppendStr(buf, sizeof(buf), n, "\r\ntick=");
    n = AppendDec(buf, sizeof(buf), n, GetTickCount64());
    n = AppendStr(buf, sizeof(buf), n, "\r\n");

    DWORD w = 0;
    WriteFile(h, buf, static_cast<DWORD>(n), &w, nullptr);
    CloseHandle(h);
}

// -----------------------------------------------------------------------------
// Worker thread - runs the dump pipeline off the loader lock.
// -----------------------------------------------------------------------------

DWORD WINAPI DumperWorker(LPVOID) {
    wchar_t logsDir[600] = {};
    if (!ResolveLogsDir(logsDir, sizeof(logsDir) / sizeof(logsDir[0]))) {
        return 1;
    }
    WriteSentinel(logsDir);

    Logger L{};
    {
        wchar_t logPath[700] = {};
        ComposePathW(logsDir, L"dumper.log", logPath,
                     sizeof(logPath) / sizeof(logPath[0]));
        LogOpen(L, logPath);
    }

    {
        char line[160];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[proxy] worker entry pid=");
        n = AppendDec(line, sizeof(line), n, GetCurrentProcessId());
        n = AppendStr(line, sizeof(line), n, " tick=");
        n = AppendDec(line, sizeof(line), n, GetTickCount64());
        LogRaw(L, line, n);
    }

    // Phase 1: short fixed delay. Roblox is still in early init - some
    // modules haven't loaded yet, the engine .text is probably still
    // ciphertext. Don't waste cycles polling immediately.
    Sleep(kPostInitDelayMs);
    LogLit(L, "[proxy] post-init delay elapsed; entering decryption poll");

    // Phase 2: poll for the engine .text to look decrypted. Up to 30s.
    DWORD waited = 0;
    bool decrypted = false;
    std::uintptr_t exeBase = 0;
    std::size_t exeSize = 0;
    while (waited < kMaxDecryptWaitMs) {
        if (FindRobloxPlayerExe(exeBase, exeSize)) {
            // Probe the first 64 KB of the .text region. RobloxPlayerBeta.exe
            // has its .text starting at the first PE section (RVA 0x1000),
            // 89 MB long, encrypted on disk. After decryption the first
            // chunk will look like normal code.
            if (LooksLikePlaintextCode(exeBase + 0x1000, 0x10000)) {
                decrypted = true;
                break;
            }
        }
        Sleep(kPollIntervalMs);
        waited += kPollIntervalMs;
    }

    {
        char line[160];
        std::size_t n = 0;
        if (decrypted) {
            n = AppendStr(line, sizeof(line), n,
                "[proxy] decryption probe: PASS after ");
        } else {
            n = AppendStr(line, sizeof(line), n,
                "[proxy] decryption probe: TIMEOUT after ");
        }
        n = AppendDec(line, sizeof(line), n, waited);
        n = AppendStr(line, sizeof(line), n, "ms - dumping anyway");
        LogRaw(L, line, n);
    }

    // Phase 3: census + per-module dump. Same as v2 ENIDumper.
    LogLit(L, "[proxy] === module census ===");
    CensusCtx ccx{ L, 0 };
    EnumModules(&CensusCallback, &ccx);

    {
        char line[64];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[proxy] census total: ");
        n = AppendDec(line, sizeof(line), n, static_cast<std::uint64_t>(ccx.Count));
        LogRaw(L, line, n);
    }

    LogLit(L, "[proxy] === dumping targets ===");
    DumpCtx dctx{ logsDir, L, 0 };
    EnumModules(&DumpCallback, &dctx);

    {
        char line[64];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[proxy] dump targets processed: ");
        n = AppendDec(line, sizeof(line), n, static_cast<std::uint64_t>(dctx.Dumped));
        LogRaw(L, line, n);
    }

    LogLit(L, "[proxy] worker done");
    if (L.hFile != INVALID_HANDLE_VALUE) CloseHandle(L.hFile);
    return 0;
}

} // anonymous namespace

// =============================================================================
// DllMain - spawn the worker and return immediately.
// =============================================================================
//
// MUST NOT do real work here. The loader lock is held; CreateFileW that
// triggers any LoadLibraryW (e.g. via filter drivers) will deadlock.
// CreateThread is safe - it queues the thread but doesn't initialize it
// until the lock is released.

// Resolved by Stubs.cpp (libHttpClient build, no-op) or
// WebView2Forwarders.cpp (WebView2 build, real LoadLibrary + GetProcAddress).
// Linker picks whichever TU defines it for each target.
extern "C" void ENI_ResolveWebView2Forwarders(HMODULE);

// Sentinel write - the FIRST thing we do when ATTACH fires. Tells us
// "DllMain ran" without any other side effects. Path: %TEMP%\eni_proxy_loaded.txt.
// Content: PID + timestamp. We use raw Win32 (no STL, no heap) because
// we're under the loader lock and want zero risk of re-entering the
// loader. CreateFileW into %TEMP% is safe - the path resolution and
// the filesystem write are both kernel32 calls that don't trigger
// further LoadLibrary.
//
// IMPORTANT: this fires unconditionally on DLL_PROCESS_ATTACH, which
// means it tells us whether our DLL got mapped, not whether Roblox
// reached any specific point afterward. If Hyperion crashes/exits
// the process *before* we get here, no sentinel. If it crashes after
// our DllMain returns, the sentinel still exists.
static void WriteAttachSentinel() {
    wchar_t tmp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmp);
    if (n == 0 || n > MAX_PATH) return;

    wchar_t path[MAX_PATH];
    int written = swprintf_s(path, MAX_PATH, L"%seni_proxy_loaded.txt", tmp);
    if (written < 0) return;

    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[256];
    int len = _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                          "DllMain DLL_PROCESS_ATTACH fired\r\n"
                          "PID=%lu\r\n"
                          "TID=%lu\r\n"
                          "TIME=%04u-%02u-%02u %02u:%02u:%02u.%03u\r\n",
                          GetCurrentProcessId(),
                          GetCurrentThreadId(),
                          st.wYear, st.wMonth, st.wDay,
                          st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    if (len > 0) {
        DWORD wrote = 0;
        WriteFile(f, buf, static_cast<DWORD>(len), &wrote, nullptr);
    }
    CloseHandle(f);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Write sentinel BEFORE anything else - we want to know we ran
        // even if subsequent calls in this DllMain raise or hang.
        WriteAttachSentinel();

        DisableThreadLibraryCalls(hModule);
        // Resolve runtime forwarders FIRST. The WebView2 build needs the
        // five PFN_* pointers populated before any caller can invoke our
        // exports - which is technically possible the moment DllMain
        // returns. The libHttpClient build's stub returns immediately.
        // LoadLibraryW under the loader lock is safe HERE because the
        // target DLL imports only system DLLs already mapped into the
        // process (KERNEL32 / ADVAPI32 / ole32).
        ENI_ResolveWebView2Forwarders(hModule);
        HANDLE h = CreateThread(nullptr, 0, &DumperWorker, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }
    return TRUE;
}
