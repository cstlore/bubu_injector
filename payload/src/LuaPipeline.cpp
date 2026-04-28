// =============================================================================
// Executor::LuaPipeline - script execution orchestrator
// =============================================================================
//
// The guts of what will eventually be "take a UTF-8 Luau string and run it
// inside Roblox." Today it's the scaffolding for that and nothing more -
// the real execution path is gated behind signatures that don't resolve,
// so Execute short-circuits into a log line.
//
// Keeping the shape honest matters because downstream surfaces (UI, pipe,
// script hub) get wired against this API now. When signatures land, only
// this file needs surgery - nothing above it changes.
// =============================================================================

#include "Executor/LuaPipeline.h"
#include "Hyperion/Signatures.h"
#include "Hyperion/TaskScheduler.h"
#include "Hyperion/Log.h"

#include <cstdint>
#include <cstring>
#include <string>

namespace ENI::Executor {

namespace {

// Keep a tiny preview for log lines without leaking full script content.
// 80 chars is enough to tell scripts apart in diagnostics.
std::string Preview(std::string_view s, std::size_t maxLen = 80) {
    std::string out;
    out.reserve(maxLen + 4);
    for (std::size_t i = 0; i < s.size() && i < maxLen; ++i) {
        char c = s[i];
        if (c == '\n' || c == '\r' || c == '\t') c = ' ';
        if (static_cast<unsigned char>(c) < 0x20 ||
            static_cast<unsigned char>(c) == 0x7F) {
            c = '?';
        }
        out.push_back(c);
    }
    if (s.size() > maxLen) out += "...";
    return out;
}

// The real implementation will live here once sigs exist. For now the
// function returns without touching Lua state - all it does is log what
// WOULD have happened and what's missing.
void RunOnRobloxThread(std::string source) {
    using namespace Hyperion::Signatures;

    // If we got dispatched, TaskScheduler drained us on a Roblox thread.
    // In placeholder mode this never fires because the pump isn't armed.
    if (!Has(Kind::LuauLoad) || !Has(Kind::LuaPCall)) {
        Hyperion::Log::Line("[lua] drained but sigs missing, cannot execute: %s",
                            Preview(source).c_str());
        return;
    }

    // Below here is the real execution path. Left as a TODO until
    // luau_load and lua_pcall resolve to real addresses.
    //
    //   using LuauLoadFn = int(*)(lua_State* L, const char* name,
    //                             const char* data, size_t size, int env);
    //   using LuaPCallFn = int(*)(lua_State* L, int nargs, int nresults, int errfunc);
    //   auto luau_load = reinterpret_cast<LuauLoadFn>(Get(Kind::LuauLoad));
    //   auto lua_pcall = reinterpret_cast<LuaPCallFn>(Get(Kind::LuaPCall));
    //
    //   lua_State* L = ResolveLuaState();  // walks ScriptContext -> state
    //   if (luau_load(L, "=ENI", source.data(), source.size(), 0) != 0) {
    //       Hyperion::Log::Line("[lua] luau_load failed: %s", lua_tostring(L, -1));
    //       lua_pop(L, 1);
    //       return;
    //   }
    //   if (lua_pcall(L, 0, 0, 0) != 0) {
    //       Hyperion::Log::Line("[lua] pcall error: %s", lua_tostring(L, -1));
    //       lua_pop(L, 1);
    //   }

    Hyperion::Log::Line("[lua] placeholder execution path hit -- real "
                        "execute not implemented yet, source preview: %s",
                        Preview(source).c_str());
}

} // namespace

bool Execute(std::string_view source) {
    if (source.empty()) {
        Hyperion::Log::Line("[lua] Execute called with empty source, rejecting");
        return false;
    }

    Hyperion::Log::Line("[lua] Execute queued (%zu bytes): %s",
                        source.size(), Preview(source).c_str());

    using namespace Hyperion::Signatures;
    const bool haveSigs = Has(Kind::LuauLoad) && Has(Kind::LuaPCall);
    const bool pumpArmed = Hyperion::TaskScheduler::IsArmed();

    if (!haveSigs) {
        Hyperion::Log::Line("[lua] pipeline not wired (missing: %s%s%s), dropping",
                            Has(Kind::LuauLoad) ? "" : "luau_load ",
                            Has(Kind::LuaPCall) ? "" : "lua_pcall ",
                            "");
        return false;
    }

    // Copy the source into an owned string so the closure can outlive the
    // caller's string_view.
    std::string owned(source);

    const bool accepted = Hyperion::TaskScheduler::Enqueue(
        [src = std::move(owned)]() mutable {
            RunOnRobloxThread(std::move(src));
        });

    if (!accepted) {
        Hyperion::Log::Line("[lua] Enqueue rejected (queue full or pump closed)");
        return false;
    }

    if (!pumpArmed) {
        // Legitimate state: sigs present but TaskScheduler detour hasn't
        // fired yet. The job will run on the first fire. Log for visibility.
        Hyperion::Log::Line("[lua] queued; pump not yet armed, job will run on first step");
    }
    return true;
}

int GetIdentity() {
    using namespace Hyperion::Signatures;
    if (!Has(Kind::GetIdentity)) {
        Hyperion::Log::Line("[lua] GetIdentity: sig missing, returning 0");
        return 0;
    }
    // Real implementation: walk to lua_State userdata and read the
    // identity offset. Gated on sig resolution.
    Hyperion::Log::Line("[lua] GetIdentity: sig present but reader not implemented");
    return 0;
}

bool SetIdentity(int level) {
    using namespace Hyperion::Signatures;
    if (!Has(Kind::SetIdentity)) {
        Hyperion::Log::Line("[lua] SetIdentity(%d): sig missing, no-op", level);
        return false;
    }
    Hyperion::Log::Line("[lua] SetIdentity(%d): sig present but writer not implemented",
                        level);
    return false;
}

bool IsReady() {
    using namespace Hyperion::Signatures;
    return Has(Kind::LuauLoad)
        && Has(Kind::LuaPCall)
        && Hyperion::TaskScheduler::IsArmed();
}

const char* StatusString() {
    using namespace Hyperion::Signatures;
    if (!Has(Kind::LuauLoad) || !Has(Kind::LuaPCall)) {
        return "missing-sigs";
    }
    if (!Hyperion::TaskScheduler::IsArmed()) {
        return "pump-not-armed";
    }
    return "ready";
}

} // namespace ENI::Executor
