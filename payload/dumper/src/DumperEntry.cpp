// =============================================================================
// DumperEntry.cpp - ENIDumper.dll entry point (freestanding)
// =============================================================================
//
// What this DLL does, end-to-end (v2 - multi-module):
//
//   1. Get manual-mapped into a live, fully-booted RobloxPlayerBeta.exe via
//      `ENILoader.exe --payload bin\ENIDumper.dll --pid <N>`.
//   2. Validate BootInfo (same magic / version / size guard as the production
//      payload's Boot.cpp).
//   3. Open <LogsDir>\dumper.log via direct CreateFileW.
//   4. Walk PEB->Ldr->InMemoryOrderModuleList. For each loaded module:
//        - log a census line with base, size, has-.byfron flag, ASCII name
//        - if it's a dump target (.byfron present, OR named match against
//          RobloxPlayerBeta.{exe,dll} / RobloxStudioBeta.{exe,dll}), run
//          the per-module dump pipeline:
//            * VirtualQuery-walk to find the real contiguous extent
//              (Hyperion can grow .byfron past PE-declared SizeOfImage)
//            * Write a region report to <stem>_<base>_<size>.regions.txt
//            * Page-by-page (4096 B) copy bytes into <stem>_<base>_<size>.bin
//              with Pagewise::ReadPageSEH guarding access violations
//            * Run the "RobloxPlayerBeta" sanity-string scan over the dump
//   5. Return 0.
//
// =============================================================================
//
// CRITICAL INVARIANT: this translation unit must be FREESTANDING. The
// manual mapper invokes our entry point on a brand-new CreateRemoteThread
// thread that has NEVER passed through LdrInitializeThunk. The CRT's
// TLS callback (__dyn_tls_init) tries to register the thread with the
// FLS subsystem and fails with NTSTATUS 0xC000071C
// (STATUS_INVALID_THREAD), which is what we observed in practice.
//
// Avoidance plan:
//   * No std::snprintf / std::vsnprintf / std::swprintf - they touch
//     __acrt_locale state that's never been initialized.
//   * No std::memset / std::memcpy in scope that might inline to a CRT
//     intrinsic - we use the intrinsics directly (RtlZeroMemory,
//     RtlCopyMemory) so the symbols come from kernel32 / ntdll, not CRT.
//   * No thread_local - that would force a TLS directory and re-trigger
//     the same TLS-callback crash path we just escaped.
//   * No <cstdio>, <cwchar>, no global C++ ctors / dtors that touch
//     locale tables.
//   * Hand-rolled hex/decimal formatters, hand-rolled wstrlen / wcat.
//
// What this DLL deliberately does NOT do: arm Sentry, hook anything,
// install MinHook, register dll-notify callbacks, write to Roblox's
// memory, encrypt itself, register .pdata for unwinding. Pure read-only
// observation.
// =============================================================================

#include "Pagewise.h"

#include <cstddef>
#include <cstdint>
#include <windows.h>
#include <winternl.h>   // for PEB / PEB_LDR_DATA / UNICODE_STRING / LIST_ENTRY

#include "BootInfo.h"

namespace {

constexpr std::uint32_t kStatusOk              = 0;
constexpr std::uint32_t kStatusInvalidBootInfo = 1;
constexpr std::uint32_t kStatusVersionMismatch = 2;

constexpr std::size_t kPageSize = 4096;

// -----------------------------------------------------------------------------
// CRT-free byte ops. RtlCopyMemory / RtlZeroMemory are macros around
// memcpy/memset on Windows headers, which the linker resolves to the
// compiler's intrinsics; those don't touch CRT state. We re-expose them
// under local names for clarity at the call site.
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
    std::size_t n = 0;
    if (!s) return 0;
    while (s[n]) ++n;
    return n;
}

// -----------------------------------------------------------------------------
// Hand-rolled formatters. All output is ASCII so we never touch wide-char
// locale state. Buffers are caller-owned.
// -----------------------------------------------------------------------------

// Append a literal C string. Returns new length.
inline std::size_t AppendStr(char* buf, std::size_t cap, std::size_t len, const char* s) {
    while (*s && len + 1 < cap) buf[len++] = *s++;
    buf[len] = '\0';
    return len;
}

// Append a 64-bit hex value, exactly `digits` wide, uppercase, zero-padded.
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

// Append an unsigned decimal value.
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
// PEB->Ldr walk and section-table parsing (CRT-free, freestanding).
//
// Ported from payload/src/SigScan.cpp:111-195. Re-implemented inline here
// so the dumper TU stays self-contained - no Log.cpp/SigScan.cpp drag-in,
// nothing that could touch CRT init on the bare CreateRemoteThread thread.
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

// ASCII-only case fold for module-name compare. UNICODE_STRING.Buffer
// from PEB->Ldr is short and well-formed for module names; full Unicode
// case folding is unnecessary.
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

// Iterate every loaded module via PEB->Ldr->InMemoryOrderModuleList.
// Callback: bool(const LDR_DATA_TABLE_ENTRY_min*) - return false to stop.
// We pass it as a raw function pointer + opaque ctx so we don't need
// templates (keeps codegen flat - one function, no instantiation surprises).
using ModuleCb = bool (*)(const LDR_DATA_TABLE_ENTRY_min*, void*);

void EnumModules(ModuleCb cb, void* ctx) {
    PEB* peb = GetPEB();
    if (!peb || !peb->Ldr) return;

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;

    // Bounded loop - if Hyperion ever scrambles the list pointers we
    // don't want an infinite walk. 4096 modules is comically high but
    // cheap insurance.
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

// Find a section by exact 8-byte name (zero-padded). Generalized from
// SigScan.cpp:172-195's hardcoded ".text\0..." memcmp.
//
// `name` MUST be exactly 8 bytes. Use the literal-array helper below
// if you have a shorter ASCII name like ".byfron".
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

// Convenience: pack an ASCII name into 8 zero-padded bytes and look it up.
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
// Mini logger. Writes directly via WriteFile, no CRT formatters.
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
        const char* banner = "\r\n----- ENIDumper boot -----\r\n";
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

// -----------------------------------------------------------------------------
// Path composition (CRT-free).
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
    for (std::size_t i = 0; i <= m; ++i) out[cur + i] = leaf[i]; // copy null too
}

// Append "<stem>_<base16>_<size16>.<ext>" to dir, into out.
// Stem is an arbitrary lowercase-ASCII string; we sanitize each char to
// keep the result a valid filename leaf (path separators and dots become
// underscores). Caller-owned wide buffers, no CRT calls.
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
            // Sanitize: replace anything outside [a-z0-9_-] with '_'.
            if (!((c >= L'a' && c <= L'z') ||
                  (c >= L'A' && c <= L'Z') ||
                  (c >= L'0' && c <= L'9') ||
                   c == L'_' || c == L'-')) {
                c = L'_';
            }
            // Lowercase A-Z.
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

// Build a filename stem from a UNICODE_STRING basename (e.g.
// "RobloxPlayerBeta.dll" -> "robloxplayerbeta_dll"). Wide chars are
// truncated to ASCII low byte; sanitization happens in the caller
// (ComposeNamedOutputPath).
void StemFromUnicodeString(const UNICODE_STRING& s, wchar_t* out, std::size_t cap) {
    if (cap < 2 || !s.Buffer) { if (cap) out[0] = L'\0'; return; }
    const std::size_t n = s.Length / sizeof(wchar_t);
    std::size_t k = 0;
    for (std::size_t i = 0; i < n && k + 1 < cap; ++i) {
        wchar_t c = s.Buffer[i];
        if (c == L'.') c = L'_'; // .dll -> _dll
        out[k++] = c;
    }
    out[k] = L'\0';
}

// -----------------------------------------------------------------------------
// VirtualQuery walk: same algorithm as Boot.cpp::DiscoverSelfExtent, but
// starting from BootInfo.Process.BaseAddress.
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
// Region report
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
// Pagewise byte dump
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
// Sanity scan: walk the image looking for the literal "RobloxPlayerBeta".
// We do this CRT-free with a hand-rolled needle compare so we don't pull
// in SigScan's templated path (which is fine functionally but adds
// complexity we don't need here).
// -----------------------------------------------------------------------------

std::uintptr_t FindNeedle(std::uintptr_t base, std::size_t size,
                          const std::uint8_t* needle, std::size_t needleLen) {
    if (needleLen == 0 || size < needleLen) return 0;
    const auto* p = reinterpret_cast<const std::uint8_t*>(base);
    const std::size_t last = size - needleLen;

    for (std::size_t i = 0; i <= last; ++i) {
        // Each candidate position lives in one or more pages; we have to
        // be defensive because some pages are PAGE_NOACCESS even though
        // they're MEM_COMMIT inside the same allocation.
        std::uint8_t window[32]; // needleLen <= 32 in practice
        const bool ok = ENI::Dumper::ReadPageSEH(window, p + i, needleLen);
        if (!ok) {
            // Skip to the next page boundary.
            const std::uintptr_t addr = base + i;
            const std::uintptr_t nextPage = (addr + kPageSize) & ~(kPageSize - 1);
            const std::size_t jump = static_cast<std::size_t>(nextPage - addr);
            if (jump == 0) break;
            i += jump - 1; // -1 because the loop ++ adds 1
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
        n = AppendStr(line, sizeof(line), n, "[dumper] sanity scan: hit at 0x");
        n = AppendHex(line, sizeof(line), n, hit, 16);
        n = AppendStr(line, sizeof(line), n, " rva=0x");
        n = AppendHex(line, sizeof(line), n, hit - imageBase, 8);
    } else {
        n = AppendStr(line, sizeof(line), n,
            "[dumper] sanity scan: needle not found");
    }
    LogRaw(L, line, n);
}

// -----------------------------------------------------------------------------
// Per-module dump pipeline: extent + region report + pagewise + sanity scan.
// Reuses the v1 primitives. Caller passes the LDR entry and the BootInfo
// (for LogsDir). All log lines are tagged with the module's basename so
// the operator can correlate output files with census entries.
// -----------------------------------------------------------------------------

struct CensusCtx {
    Logger& L;
    int     Count;
};

struct DumpCtx {
    const ENI::Boot::BootInfo* Info;
    Logger&                    L;
    int                        Dumped;
};

bool ShouldDumpModule(const LDR_DATA_TABLE_ENTRY_min* e) {
    const auto base = reinterpret_cast<std::uintptr_t>(e->DllBase);
    if (HasByfronSection(base)) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxPlayerBeta.exe")) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxPlayerBeta.dll")) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxStudioBeta.exe")) return true;
    if (BaseNameEqualsCI(e->BaseDllName, L"RobloxStudioBeta.dll")) return true;
    return false;
}

void DumpOneModule(DumpCtx& dctx, const LDR_DATA_TABLE_ENTRY_min* e) {
    const auto base = reinterpret_cast<std::uintptr_t>(e->DllBase);
    const std::size_t pe_size = e->SizeOfImage;

    // PE-declared size is sometimes smaller than the actual contiguous
    // AllocationBase span post-decryption (Hyperion's stage-2 expands
    // .byfron beyond its header-declared VirtualSize). Walk forward to
    // get the real extent and pick max(pe_size, walked).
    std::uintptr_t walkedBase = 0;
    std::size_t    walkedSize = 0;
    DiscoverImageExtent(base, walkedBase, walkedSize);

    std::size_t dumpSize = pe_size > walkedSize ? pe_size : walkedSize;
    if (dumpSize == 0) {
        LogRaw(dctx.L, "[dumper] target: extent zero, skipping", 39);
        return;
    }

    // Build filename stem from the basename (e.g. "RobloxPlayerBeta.dll"
    // -> "robloxplayerbeta_dll" after the sanitizer in
    // ComposeNamedOutputPath).
    wchar_t stem[160] = {};
    StemFromUnicodeString(e->BaseDllName, stem,
                          sizeof(stem) / sizeof(stem[0]));

    wchar_t binPath[ENI::Boot::MaxPathChars] = {};
    wchar_t regPath[ENI::Boot::MaxPathChars] = {};
    ComposeNamedOutputPath(dctx.Info->LogsDir, stem, base, dumpSize, L"bin",
                           binPath, sizeof(binPath) / sizeof(binPath[0]));
    ComposeNamedOutputPath(dctx.Info->LogsDir, stem, base, dumpSize, L"regions.txt",
                           regPath, sizeof(regPath) / sizeof(regPath[0]));

    // Per-target header line.
    {
        char line[256];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[dumper] === target base=0x");
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
        n = AppendStr(line, sizeof(line), n, "[dumper] regions matched: ");
        n = AppendDec(line, sizeof(line), n, regions);
        LogRaw(dctx.L, line, n);
    }

    const DumpStats s = WritePagewiseDump(binPath, base, dumpSize);
    {
        char line[256];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[dumper] dump: bytes=");
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
    n = AppendStr(line, sizeof(line), n, "[dumper] mod base=0x");
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

} // namespace

// =============================================================================
// Entry point
// =============================================================================

// Tiny helper: write a string + newline directly via WriteFile. Used for
// diagnostic checkpoints so we can tell from the log exactly where the
// thread died if it doesn't reach the end. Caller must compute strlen
// (we hand-roll it here because we're freestanding).
static inline void LogLit(Logger& L, const char* lit) {
    if (L.hFile == INVALID_HANDLE_VALUE) return;
    std::size_t n = 0;
    while (lit[n]) ++n;
    LogRaw(L, lit, n);
}

extern "C" __declspec(dllexport) std::uint32_t ENIBootEntry(
        const ENI::Boot::BootInfo* info) {
    using namespace ENI;

    // -- 0. EARLY SENTINEL ---------------------------------------------
    //
    // Before we trust `info` at all, drop a footprint at a hardcoded
    // path so we know the entry function got called and what process
    // it's actually running in. This file lives in the user's profile
    // directory so it's writable from any user-mode process.
    {
        wchar_t early[256] = {};
        DWORD n = GetEnvironmentVariableW(L"USERPROFILE", early, 200);
        if (n > 0 && n < 200) {
            wchar_t* p = early + n;
            const wchar_t* leaf = L"\\enidumper_alive.txt";
            while (*leaf) *p++ = *leaf++;
            *p = L'\0';
            HANDLE h = CreateFileW(early, GENERIC_WRITE, FILE_SHARE_READ,
                                   nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                                   nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                char buf[128];
                std::size_t k = 0;
                k = AppendStr(buf, sizeof(buf), k, "alive pid=");
                k = AppendDec(buf, sizeof(buf), k, GetCurrentProcessId());
                k = AppendStr(buf, sizeof(buf), k, " tid=");
                k = AppendDec(buf, sizeof(buf), k, GetCurrentThreadId());
                k = AppendStr(buf, sizeof(buf), k, " info=0x");
                k = AppendHex(buf, sizeof(buf), k,
                              reinterpret_cast<std::uint64_t>(info), 16);
                buf[k++] = '\r'; buf[k++] = '\n';
                DWORD w = 0;
                WriteFile(h, buf, static_cast<DWORD>(k), &w, nullptr);
                CloseHandle(h);
            }
        }
    }

    // -- 1. Validate BootInfo ------------------------------------------
    //
    // We can't log this stage - we don't have a log path until we've
    // validated `info` is non-null and points at a recognizable struct.
    // If validation fails, the thread returns immediately with no
    // filesystem footprint. That's fine for an obvious garbage-input
    // case; the loader sees the non-zero return and reports it.
    if (!info)                                       ExitThread(kStatusInvalidBootInfo);
    if (info->Magic != Boot::Magic)                  ExitThread(kStatusInvalidBootInfo);
    if (info->Version != Boot::ProtocolVersion)      ExitThread(kStatusVersionMismatch);
    if (info->StructSize != sizeof(Boot::BootInfo))  ExitThread(kStatusVersionMismatch);

    // -- 2. Open log via direct CreateFileW (FIRST thing after validate)
    //
    // Diagnostic checkpoints from this point onward let us pin down
    // exactly where the thread died if it doesn't reach the end. Each
    // LogLit call hits FILE_FLAG_WRITE_THROUGH so the line is on disk
    // before the next instruction runs.
    Logger L{};
    {
        wchar_t logPath[Boot::MaxPathChars] = {};
        ComposePathW(info->LogsDir, L"dumper.log", logPath,
                     sizeof(logPath) / sizeof(logPath[0]));
        LogOpen(L, logPath);
    }
    LogLit(L, "[ckpt] post-LogOpen");

    {
        char line[256];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[dumper] entry pid=");
        n = AppendDec(line, sizeof(line), n, info->Process.Pid);
        n = AppendStr(line, sizeof(line), n, " base=0x");
        n = AppendHex(line, sizeof(line), n, info->Process.BaseAddress, 16);
        n = AppendStr(line, sizeof(line), n, " size=0x");
        n = AppendHex(line, sizeof(line), n, info->Process.ImageSize, 16);
        n = AppendStr(line, sizeof(line), n, " flags=0x");
        n = AppendHex(line, sizeof(line), n, info->Flags, 8);
        LogRaw(L, line, n);
    }
    LogLit(L, "[ckpt] post-banner");

    if (!info->Process.BaseAddress) {
        LogLit(L, "[dumper] WARN: Process.BaseAddress is zero (proceeding via PEB walk)");
    }

    // -- 3. Module census ---------------------------------------------
    //
    // Walk PEB->Ldr once and log every module with its name, base, size,
    // and a flag for whether it carries a .byfron section. This is the
    // operator-facing "what's loaded?" record - useful even if no module
    // ends up dump-eligible.

    LogLit(L, "[ckpt] pre-census");
    LogLit(L, "[dumper] === module census ===");
    CensusCtx ccx{ L, 0 };
    EnumModules(&CensusCallback, &ccx);
    LogLit(L, "[ckpt] post-census");

    {
        char line[64];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[dumper] census total: ");
        n = AppendDec(line, sizeof(line), n, static_cast<std::uint64_t>(ccx.Count));
        LogRaw(L, line, n);
    }

    // -- 4. Dump targets ------------------------------------------------
    //
    // A module is dump-eligible if it has .byfron, OR if its basename
    // matches one of the Roblox EXE/DLL names we expect. The named match
    // is a belt-and-suspenders fallback in case Hyperion ever renames
    // .byfron, or post-decryption replaces the section with .text.

    LogLit(L, "[ckpt] pre-dump");
    DumpCtx dctx{ info, L, 0 };
    EnumModules(&DumpCallback, &dctx);
    LogLit(L, "[ckpt] post-dump");

    {
        char line[64];
        std::size_t n = 0;
        n = AppendStr(line, sizeof(line), n, "[dumper] dump targets processed: ");
        n = AppendDec(line, sizeof(line), n, static_cast<std::uint64_t>(dctx.Dumped));
        LogRaw(L, line, n);
    }

    // -- 5. Done -------------------------------------------------------
    //
    // ExitThread instead of plain `return`. The manual mapper invoked
    // us via a CreateRemoteThread on a tiny stub that does `call
    // ENIBootEntry; ret`. When that `ret` flows back through
    // BaseThreadInitThunk, the kernel's thread-exit path runs CRT-style
    // cleanup that needs FLS state our synthetic thread never had,
    // and tears the thread down with STATUS_INVALID_THREAD
    // (0xC000071C) - which is what the loader's GetExitCodeThread
    // observes regardless of what we returned.
    //
    // ExitThread short-circuits that: it sets the thread's exit code
    // and yanks the thread out of the run queue without going through
    // the trampoline epilogue.
    LogLit(L, "[ckpt] pre-ExitThread");
    if (L.hFile != INVALID_HANDLE_VALUE) CloseHandle(L.hFile);
    ExitThread(kStatusOk);
}

// =============================================================================
// DllMain - minimal stub
// =============================================================================
//
// Manual mapper invokes ENIBootEntry directly; DllMain only fires for
// LoadLibrary calls (no one should be doing that to us). Keep it
// freestanding - no CRT calls, no DisableThreadLibraryCalls (which
// looks safe but pulls in module-handle bookkeeping that the static
// CRT init expects).

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
