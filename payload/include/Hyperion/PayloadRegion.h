#pragma once

// =============================================================================
// Hyperion::PayloadRegion - "lie about these pages" registry
// =============================================================================
//
// Hyperion's runtime scans walk the address space via NtQueryVirtualMemory
// to enumerate every committed region, building a list it can then verify
// against trusted modules. Our manual-mapped payload is NOT a trusted
// module - it has no LDR entry, no signature, no on-disk file backing -
// so when Hyperion's walker finds it, the executor's life expectancy is
// measured in seconds.
//
// Solution: register every memory range we own here. Our
// NtQueryVirtualMemory hook checks any incoming BaseAddress against this
// list and lies if it falls inside one of our ranges, returning a
// MEM_FREE result that tells the walker "nothing's here, skip on."
//
// We don't need a fancy data structure - a fixed array of <16 ranges
// covers our payload image, hook trampoline pages, and the log buffer.
// =============================================================================

#include <cstddef>
#include <cstdint>

namespace ENI::Hyperion::PayloadRegion {

constexpr std::size_t kMaxRanges = 16;

struct Range {
    std::uintptr_t Base = 0;
    std::size_t    Size = 0;
    const char*    Tag = nullptr;
};

// Add a range. Tag is for diagnostics (logged on registration, returned
// in lookup). Returns true if the range fit; false if the table is full
// or the range is degenerate.
bool Add(std::uintptr_t base, std::size_t size, const char* tag);

// Test whether `address` lies inside any registered range. Returns the
// matching range or nullptr.
const Range* Find(std::uintptr_t address);

// Number of registered ranges. For diagnostics.
std::size_t Count();

// Iterate. Returns nullptr at end. (Simple index-based access works
// because we never remove ranges in v1.)
const Range* At(std::size_t index);

} // namespace ENI::Hyperion::PayloadRegion
