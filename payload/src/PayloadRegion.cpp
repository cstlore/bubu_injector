// =============================================================================
// PayloadRegion.cpp
// =============================================================================

#include "Hyperion/PayloadRegion.h"
#include "Hyperion/Log.h"

namespace ENI::Hyperion::PayloadRegion {

namespace {
Range g_Ranges[kMaxRanges];
std::size_t g_Count = 0;
} // namespace

bool Add(std::uintptr_t base, std::size_t size, const char* tag) {
    if (!base || !size) return false;
    if (g_Count >= kMaxRanges) {
        Log::Line("[region] table full; dropping %s", tag ? tag : "?");
        return false;
    }
    Range& r = g_Ranges[g_Count++];
    r.Base = base;
    r.Size = size;
    r.Tag  = tag;
    Log::Line("[region] +[%p .. %p) (%llu bytes) tag=%s",
              reinterpret_cast<void*>(base),
              reinterpret_cast<void*>(base + size),
              static_cast<unsigned long long>(size),
              tag ? tag : "?");
    return true;
}

const Range* Find(std::uintptr_t address) {
    for (std::size_t i = 0; i < g_Count; i++) {
        const auto& r = g_Ranges[i];
        if (address >= r.Base && address < r.Base + r.Size) return &r;
    }
    return nullptr;
}

std::size_t Count() {
    return g_Count;
}

const Range* At(std::size_t index) {
    return index < g_Count ? &g_Ranges[index] : nullptr;
}

} // namespace ENI::Hyperion::PayloadRegion
