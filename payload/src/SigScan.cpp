// =============================================================================
// Hyperion::SigScan - byte-pattern matcher implementation
// =============================================================================
//
// The header carries the doc-block on intent and the public API contract.
// This file owns:
//
//   * Compile()     - parser for IDA-style "48 8B ?? ..." into a CompiledPattern
//   * Find()        - thin wrapper that returns first match or 0
//   * FindInModule() - PEB->Ldr walker + .text section locator + Find
//
// Compile is the only non-trivial piece. The scanner itself lives as a
// template in the header so FindAll can construct it without going through
// type erasure (we'd otherwise need std::function and pull in <functional>).
//
// Why we hand-walk PEB instead of GetModuleHandleW: same reason NtApi.cpp
// does it. The payload runs from a manually-mapped image that the loader
// doesn't know about. We can't trust kernel32 hooks haven't been installed
// before our hooks are. PEB->Ldr is filled by the kernel itself before any
// user thread runs, and reading it directly skips the entire forwarding
// chain that GetModuleHandle traverses.
// =============================================================================

#include "Hyperion/SigScan.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>

#include <windows.h>
#include <winternl.h>

namespace ENI::Hyperion::SigScan {

namespace {

// ---- pattern parsing -------------------------------------------------------

// "0".."9", "a".."f", "A".."F" -> 0..15. -1 on anything else.
int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool IsSpace(char c) {
    // Tabs and spaces are the realistic separators in IDA-style sigs;
    // newlines show up when someone copy-pastes a multi-line dump.
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

// Walks `text` and emits one (byte, isWildcard) pair per token. Returns
// false on the first malformed token. Tokens are separated by whitespace;
// each token must be either "??", "?", or exactly two hex chars.
bool TokenizePattern(std::string_view text,
                     std::uint8_t* outBytes,
                     std::uint8_t* outMask,
                     std::size_t   maxLen,
                     std::size_t&  outLen) {
    outLen = 0;
    std::size_t i = 0;
    const std::size_t n = text.size();

    while (i < n) {
        // Skip leading whitespace.
        while (i < n && IsSpace(text[i])) i++;
        if (i >= n) break;

        // Capture token.
        const std::size_t tokStart = i;
        while (i < n && !IsSpace(text[i])) i++;
        const std::size_t tokLen = i - tokStart;
        const char* tok = text.data() + tokStart;

        if (outLen >= maxLen) return false;     // pattern too long

        if (tokLen == 2 && tok[0] == '?' && tok[1] == '?') {
            outBytes[outLen] = 0;
            outMask[outLen]  = 0;
            outLen++;
            continue;
        }
        if (tokLen == 1 && tok[0] == '?') {
            outBytes[outLen] = 0;
            outMask[outLen]  = 0;
            outLen++;
            continue;
        }
        if (tokLen == 2) {
            const int hi = HexNibble(tok[0]);
            const int lo = HexNibble(tok[1]);
            if (hi < 0 || lo < 0) return false;
            outBytes[outLen] = static_cast<std::uint8_t>((hi << 4) | lo);
            outMask[outLen]  = 1;
            outLen++;
            continue;
        }

        // Anything else - "0x48", "48,", "[48]", single hex char without
        // the wildcard marker - rejected. Better to fail loud than guess.
        return false;
    }

    return true;
}

// ---- module/section discovery ---------------------------------------------

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

PEB* GetPEB() {
    return reinterpret_cast<PEB*>(__readgsqword(0x60));
}

// Case-insensitive ASCII fold for the wide-char compare. UNICODE_STRING
// from PEB->Ldr is short and well-formed; we don't need full Unicode
// case folding, just A-Z -> a-z.
bool BaseNameEqualsCI(const UNICODE_STRING& s, const wchar_t* expected) {
    if (!s.Buffer || !expected) return false;
    const std::size_t expectedLen = std::wcslen(expected);
    if (s.Length / sizeof(wchar_t) != expectedLen) return false;
    for (std::size_t i = 0; i < expectedLen; i++) {
        wchar_t a = s.Buffer[i];
        wchar_t b = expected[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b - L'A' + L'a');
        if (a != b) return false;
    }
    return true;
}

// Walk InMemoryOrderModuleList for a case-insensitive base-name match.
// Returns the module's load address, or 0 on miss.
std::uintptr_t FindModuleByName(const wchar_t* moduleName) {
    PEB* peb = GetPEB();
    if (!peb || !peb->Ldr) return 0;

    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur && cur != head; cur = cur->Flink) {
        auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY_min*>(
            reinterpret_cast<std::uint8_t*>(cur) -
            offsetof(LDR_DATA_TABLE_ENTRY_min, InMemoryOrderLinks));

        if (BaseNameEqualsCI(entry->BaseDllName, moduleName)) {
            return reinterpret_cast<std::uintptr_t>(entry->DllBase);
        }
    }
    return 0;
}

// Locate the .text section. Returns false if PE headers are malformed or
// no executable section is found.
//
// Note: we match on section name ".text" specifically rather than "any
// section with EXECUTE flag" - some PEs have multiple executable sections
// (e.g. .textbss, .orpc) and code patterns we care about live in the
// canonical .text. If a build ever ships without a ".text" we'd need to
// revisit, but Roblox's MSVC-built binary always has one.
bool FindTextSection(std::uintptr_t moduleBase,
                     std::uintptr_t& outStart,
                     std::size_t&    outSize) {
    if (!moduleBase) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        // IMAGE_SECTION_HEADER.Name is up to 8 bytes, NOT null-terminated
        // when the name is exactly 8 chars. ".text" fits in 5+null so
        // memcmp on 6 bytes is correct.
        if (std::memcmp(sec->Name, ".text\0", 6) == 0) {
            outStart = moduleBase + sec->VirtualAddress;
            outSize  = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

} // namespace

// ---- public API ------------------------------------------------------------

CompiledPattern Compile(std::string_view pattern) {
    CompiledPattern cp{};
    cp.Valid = false;

    if (!TokenizePattern(pattern, cp.Bytes, cp.Mask,
                         CompiledPattern::MaxLen, cp.Len)) {
        return cp;
    }
    if (cp.Len == 0) return cp;

    // Find the anchor: first byte with mask=1. An all-wildcard pattern
    // is rejected - it would match every position and isn't useful for
    // any caller's purpose.
    bool found = false;
    for (std::size_t i = 0; i < cp.Len; i++) {
        if (cp.Mask[i]) {
            cp.Anchor       = cp.Bytes[i];
            cp.AnchorOffset = i;
            found = true;
            break;
        }
    }
    if (!found) return cp;

    cp.Valid = true;
    return cp;
}

std::uintptr_t Find(std::string_view pattern,
                    std::uintptr_t base, std::size_t size) {
    const CompiledPattern cp = Compile(pattern);

    std::uintptr_t result = 0;
    Scan(cp, base, size, [&](std::uintptr_t addr) {
        result = addr;
        return false;          // stop on first hit
    });
    return result;
}

std::uintptr_t FindInModule(std::string_view pattern,
                            const wchar_t* moduleName) {
    const std::uintptr_t modBase = FindModuleByName(moduleName);
    if (!modBase) return 0;

    std::uintptr_t textStart = 0;
    std::size_t    textSize  = 0;
    if (!FindTextSection(modBase, textStart, textSize)) return 0;

    return Find(pattern, textStart, textSize);
}

} // namespace ENI::Hyperion::SigScan
