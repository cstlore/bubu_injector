// =============================================================================
// Hyperion::Signatures - resolver implementation
// =============================================================================
//
// The interesting bit is ResolveAll. Everything else is lookup sugar.
//
// Resolution strategy per entry:
//   1. Call SigScan::FindInModule with the entry's pattern against its
//      target module (RobloxPlayerBeta.dll for every current entry).
//   2. If we get a nonzero address, stash it in Global() and log "resolved".
//   3. If we get zero, leave the slot as 0 and log "not resolved". This
//      is the expected path for every entry today because every entry is
//      a placeholder.
//
// We log the PLACEHOLDER tag explicitly so nobody reading hyperion.log
// mistakes "luau_load: not resolved" for a bug. The miss is by design.
//
// Thread-safety: ResolveAll runs once, from the boot thread, before any
// consumer thread exists. Callers of Get() / Has() after that point see
// a stable snapshot.
// =============================================================================

#include "Hyperion/Signatures.h"
#include "Hyperion/SigScan.h"
#include "Hyperion/Log.h"

#include <cstdint>

namespace ENI::Hyperion::Signatures {

namespace {

Resolved g_Resolved{};

const char* const kKindNames[static_cast<std::size_t>(Kind::Count)] = {
    "luau_load",
    "lua_pcall",
    "lua_resume",
    "lua_newthread",
    "getidentity",
    "setidentity",
    "TaskScheduler::singleton",
    "TaskScheduler::step",
    "ScriptContext::getDataModel",
    "global ScriptContext",
    "ScriptContext::runningScripts",
    "Roblox::PrintMessage",
};

} // namespace

Resolved& Global() {
    return g_Resolved;
}

const char* NameOf(Kind k) {
    const auto idx = static_cast<std::size_t>(k);
    if (idx >= static_cast<std::size_t>(Kind::Count)) return "<invalid>";
    return kKindNames[idx];
}

std::uint32_t ResolveAll() {
    std::uint32_t resolved = 0;
    std::uint32_t missed   = 0;
    std::uint32_t fakeHits = 0;  // Placeholder entries that accidentally matched something

    Log::Line("[sig] ResolveAll: scanning %u entries", static_cast<unsigned>(kEntryCount));

    for (std::size_t i = 0; i < kEntryCount; ++i) {
        const Entry& e = kEntries[i];
        const auto idx = static_cast<std::size_t>(e.Id);

        const std::uintptr_t hit =
            SigScan::FindInModule(e.Sig.Text, e.Module);

        const char* tag = e.Placeholder ? "PLACEHOLDER" : "REAL";

        if (hit) {
            g_Resolved.Address[idx] = hit;
            if (e.Placeholder) {
                // A placeholder should NOT match. If it did, either the
                // pattern was too loose or we got phenomenally unlucky.
                // Log loudly - treating this as a real resolution would
                // route downstream code into garbage.
                ++fakeHits;
                g_Resolved.Address[idx] = 0;  // reject the false positive
                Log::Line("[sig] %-32s [%s] fake-hit @ 0x%llX -- rejected",
                          e.Name, tag, static_cast<unsigned long long>(hit));
            } else {
                ++resolved;
                Log::Line("[sig] %-32s [%s] resolved @ 0x%llX",
                          e.Name, tag, static_cast<unsigned long long>(hit));
            }
        } else {
            ++missed;
            Log::Line("[sig] %-32s [%s] not resolved  (%s)",
                      e.Name, tag, e.Note ? e.Note : "");
        }
    }

    Log::Line("[sig] ResolveAll done: %u resolved, %u missed, %u rejected-placeholder-hits",
              resolved, missed, fakeHits);
    return resolved;
}

} // namespace ENI::Hyperion::Signatures
