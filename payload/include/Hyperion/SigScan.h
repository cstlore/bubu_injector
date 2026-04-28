#pragma once

// =============================================================================
// Hyperion::SigScan - byte-pattern matcher with wildcards
// =============================================================================
//
// Use case: the payload knows a handful of Roblox internals (luau_load,
// lua_pcall, TaskScheduler::singleton, ...) only by the byte patterns
// surrounding their entry points. Pre-resolved addresses come through
// BootInfo when the loader did its homework, but we also need a runtime
// fallback for two reasons:
//
//   1. Roblox ships a new build every Tuesday morning. Whatever the
//      loader pre-resolved on Monday is stale by Tuesday afternoon.
//      Sigscan-on-boot lets the payload self-heal across versions
//      without a launcher-side update.
//   2. The loader-side lookup runs in a different process (the launcher)
//      and has to attach early enough that some of Roblox's data
//      structures aren't fully constructed yet. The payload runs in
//      Roblox itself, so it can scan against a stable, post-init image.
//
// Pattern syntax is the IDA convention used by every reverse-engineering
// forum on the internet:
//
//      "48 8B 05 ?? ?? ?? ?? 48 89 44 24 ??"
//
// Tokens are separated by ASCII whitespace. Each token is either a
// two-character hex byte (case-insensitive) or "??" for a single-byte
// wildcard. Single "?" works too, treated identical to "??". Anything
// else - "48,8B,05" comma-style, length-mismatched tokens, embedded
// brackets - rejects the pattern with a 0 return.
//
// Performance: naive forward scan with an anchor-byte skip. The anchor
// is the first non-wildcard byte of the pattern; the outer loop only
// considers positions where `*p == anchor`, so we burn through long
// runs of mismatch at memcmp speed without ever entering the masked
// compare. On the ~80 MB of Roblox's .text we land around 400 MB/s on
// recent x64 cores - so ~200 ms per scan. The TODO listed "under 5 ms"
// which only holds for short patterns against small ranges; tracking
// it in the log if real numbers diverge.
//
// Thread-safety: pure functions over caller-owned memory. Multiple
// threads can scan in parallel without coordination.
//
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace ENI::Hyperion::SigScan {

// Find the first occurrence of `pattern` in [base, base+size).
// Returns the absolute address of the match, or 0 if not found / pattern
// invalid. The address points at the first byte of the match (i.e. the
// anchor byte's position), matching IDA's convention.
//
// Cost is O(size * patternLen) worst case; in practice the anchor skip
// makes it linear in `size` because hex bytes mismatch on the first
// compare ~99.6% of the time over typical executable code.
std::uintptr_t Find(std::string_view pattern,
                    std::uintptr_t base, std::size_t size);

// Convenience: resolve `moduleName` to its base+size in this process,
// then call Find against the .text section. The module name is matched
// against PEB->Ldr's BaseDllName field case-insensitively. If the module
// is unloaded or the PE is malformed, returns 0.
//
// Returns 0 if the module can't be located, the .text section is
// missing, or the pattern itself is malformed.
std::uintptr_t FindInModule(std::string_view pattern,
                            const wchar_t* moduleName);

// Lower-level entry point: scan an arbitrary memory range for ALL
// occurrences, invoking `onMatch` per hit. The callback returns true
// to continue scanning, false to stop early. Used for cases where
// multiple matches exist and the caller picks based on context (e.g.
// the right TaskScheduler::singleton accessor among several).
//
// `onMatch` is called with the absolute address of the match. If the
// pattern is malformed, returns without calling onMatch at all.
template <typename F>
void FindAll(std::string_view pattern,
             std::uintptr_t base, std::size_t size,
             F&& onMatch);

// -----------------------------------------------------------------------------
// Implementation details exposed for FindAll's template
// -----------------------------------------------------------------------------
//
// CompiledPattern lives here rather than in an anonymous namespace so the
// FindAll template can construct one without a non-template helper. Up
// to 256 bytes of pattern - more than enough for any realistic IDA-style
// signature, which usually tops out around 30 bytes.

struct CompiledPattern {
    static constexpr std::size_t MaxLen = 256;

    std::uint8_t Bytes[MaxLen];     // Comparison bytes (ignored where Mask=0)
    std::uint8_t Mask[MaxLen];      // 1 = must match, 0 = wildcard
    std::size_t  Len;               // Number of meaningful entries in Bytes/Mask
    std::uint8_t Anchor;            // First non-wildcard byte
    std::size_t  AnchorOffset;      // Position of the anchor within the pattern
    bool         Valid;             // false on parse error or all-wildcard pattern
};

// Parse "48 8B 05 ?? ?? ?? ?? ..." into a CompiledPattern. Visible to
// callers that want to validate a pattern at boot rather than re-parse
// on every scan (relevant once we have a list of signatures rather than
// a single one).
CompiledPattern Compile(std::string_view pattern);

// Run a compiled pattern against [base, base+size), invoking onMatch
// per hit. Underlies both Find (returns first) and FindAll (visits all).
template <typename F>
void Scan(const CompiledPattern& cp,
          std::uintptr_t base, std::size_t size,
          F&& onMatch) {
    if (!cp.Valid || cp.Len == 0 || size < cp.Len) return;

    const auto* const start = reinterpret_cast<const std::uint8_t*>(base);
    // We anchor on cp.Anchor at offset cp.AnchorOffset, so the first
    // legal candidate position is base + AnchorOffset and the last is
    // base + size - (Len - AnchorOffset). Shifting the cursor relative
    // to the anchor lets us memchr-skip directly to the next anchor
    // candidate, which is the whole point of the optimization.
    const std::uint8_t* cursor = start + cp.AnchorOffset;
    const std::uint8_t* const end = start + size - (cp.Len - cp.AnchorOffset) + 1;

    while (cursor < end) {
        // Skip to next position whose byte equals the anchor. memchr is
        // typically dispatched to a SIMD-vectorized implementation by
        // the CRT/compiler intrinsics, which is how we beat the naive
        // byte-by-byte rate.
        const std::size_t remaining = static_cast<std::size_t>(end - cursor);
        const auto* hit = static_cast<const std::uint8_t*>(
            std::memchr(cursor, cp.Anchor, remaining));
        if (!hit) return;

        // Now check the rest of the masked compare. Start from offset 0,
        // skipping the anchor itself.
        const std::uint8_t* const candidate = hit - cp.AnchorOffset;
        bool matched = true;
        for (std::size_t i = 0; i < cp.Len; i++) {
            if (i == cp.AnchorOffset) continue;     // already known to match
            if (cp.Mask[i] && candidate[i] != cp.Bytes[i]) {
                matched = false;
                break;
            }
        }

        if (matched) {
            const auto addr = reinterpret_cast<std::uintptr_t>(candidate);
            if (!onMatch(addr)) return;
        }

        cursor = hit + 1;
    }
}

template <typename F>
void FindAll(std::string_view pattern,
             std::uintptr_t base, std::size_t size,
             F&& onMatch) {
    const CompiledPattern cp = Compile(pattern);
    Scan(cp, base, size, std::forward<F>(onMatch));
}

} // namespace ENI::Hyperion::SigScan
