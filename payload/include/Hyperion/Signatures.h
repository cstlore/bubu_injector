#pragma once

// =============================================================================
// Hyperion::Signatures - placeholder byte patterns for Roblox internals
// =============================================================================
//
// WHAT THIS FILE IS TODAY
//
// Every pattern below is a PLACEHOLDER. They are the illustrative shapes of
// real signatures, not real signatures. At runtime, SigScan::FindInModule
// will walk RobloxPlayerBeta.dll's executable sections looking for them;
// zero of them will resolve because they don't correspond to anything in
// the current Roblox build. That's the intended behavior for the scaffolding
// phase - the resolver logs "not resolved" for each one and the rest of the
// payload degrades gracefully.
//
// WHY PLACEHOLDERS AND NOT REAL PATTERNS
//
// RobloxPlayerBeta.dll ships with every function protected by Byfron. The
// DLL has no .text section - all 13.66 MB of executable code lives inside
// a section named .byfron, where most bytes are zero-filled and the runtime
// unpacks real code on demand. Static analysis of the file on disk cannot
// see luau_load, lua_pcall, TaskScheduler, or any other engine internal.
// Signatures derived against the file-level .byfron bytes would match
// nothing at runtime because the runtime bytes are different.
//
// The correct derivation path is a memory dump of a running Roblox process
// AFTER Byfron has unpacked its pages, followed by signature extraction
// from the dump. That work is tracked separately; this file gets filled in
// once real signatures exist.
//
// HOW TO REPLACE A PLACEHOLDER WITH A REAL SIGNATURE
//
// 1. Dump .byfron from a running Roblox process (see tools/dump_byfron/).
// 2. Load the dump into Ghidra/IDA.
// 3. Locate the target function by its string references or behavioral
//    fingerprint (e.g. luau_load is identified by the bytecode version
//    byte check early in its body).
// 4. Capture 20-32 bytes of the function prologue, wildcarding RIP-relative
//    displacements and immediates that move across builds.
// 5. Replace the placeholder string below. Remove the `kPlaceholder` tag
//    from the Entry definition so the resolver logs it as REAL on boot.
// 6. Rebuild, inject, tail hyperion.log. Look for
//    [sig] luau_load: resolved @ 0x...
//
// ENTRY REGISTRATION
//
// Each Entry binds a human-readable Name to a Pattern and a slot in the
// resolved-address table. The resolver iterates the table, sigscans each,
// stores the hit in g_Resolved, and logs the outcome. All fields of
// g_Resolved default to 0. Downstream code (LuaPipeline, TaskScheduler)
// checks Has(Kind) before dereferencing.
//
// =============================================================================

#include <cstdint>
#include <cstddef>

namespace ENI::Hyperion::Signatures {

// Which Roblox internal this signature resolves.
enum class Kind : std::uint32_t {
    LuauLoad = 0,          // luau_load - bytecode -> lua_State
    LuaPCall,              // lua_pcall - protected call entry
    LuaResume,             // lua_resume - coroutine resumption
    LuaNewThread,          // lua_newthread - creates a coroutine
    GetIdentity,           // getidentity - reads identity from lua_State userdata
    SetIdentity,           // setidentity - writes identity
    TaskSchedulerSingleton,// TaskScheduler::singleton accessor
    TaskSchedulerStep,     // TaskScheduler::step - per-frame dispatch we hook
    DataModelGetter,       // ScriptContext::getDataModel
    ScriptContextGetter,   // RBX global ScriptContext accessor
    RunningScriptsHead,    // ScriptContext linked-list head pointer
    PrintMessage,          // PrintMessage - StandardOut emitter we intercept

    Count                  // Keep last - sentinel for array sizing.
};

// Fixed-length signature storage so the header carries no allocations.
// Max pattern length is 128 bytes. Real IDA signatures top out around 30.
struct Pattern {
    const char* Text;      // IDA-style "48 8B 05 ?? ?? ?? ?? ..."
};

struct Entry {
    Kind         Id;
    const char*  Name;         // Short identifier for logs
    Pattern      Sig;          // Pattern to scan for
    const wchar_t* Module;     // Module to search, usually RobloxPlayerBeta.dll
    bool         Placeholder;  // true = known-fake, will not resolve
    const char*  Note;         // Human notes shown in the log line
};

// -----------------------------------------------------------------------------
// The table. When we have real signatures, replace the placeholder fields
// and set Placeholder=false. Until then these are structurally-correct but
// semantically-empty - they parse, they sigscan, they return 0 at runtime.
// -----------------------------------------------------------------------------

constexpr Entry kEntries[] = {
    {
        Kind::LuauLoad,
        "luau_load",
        // Placeholder: shape of a typical MSVC non-leaf prologue.
        { "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 41 56 41 57 48 83 EC ??" },
        L"RobloxPlayerBeta.dll",
        true,
        "bytecode loader. Identify by version-byte check near prologue."
    },
    {
        Kind::LuaPCall,
        "lua_pcall",
        { "48 89 5C 24 ?? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ??" },
        L"RobloxPlayerBeta.dll",
        true,
        "protected call entry. Identify by stack setup + pcall error path."
    },
    {
        Kind::LuaResume,
        "lua_resume",
        { "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 49 8B F8 48 8B F2" },
        L"RobloxPlayerBeta.dll",
        true,
        "coroutine resume. Similar prologue to pcall but with co param."
    },
    {
        Kind::LuaNewThread,
        "lua_newthread",
        { "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9 E8 ?? ?? ?? ??" },
        L"RobloxPlayerBeta.dll",
        true,
        "coroutine creation. Needed for async script execution."
    },
    {
        Kind::GetIdentity,
        "getidentity",
        { "48 8B 81 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 40 ?? C3" },
        L"RobloxPlayerBeta.dll",
        true,
        "reads identity field from lua_State userdata. Short function."
    },
    {
        Kind::SetIdentity,
        "setidentity",
        { "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 41 8B F8 48 8B F2" },
        L"RobloxPlayerBeta.dll",
        true,
        "writes identity. Level 7 needed for most exploit primitives."
    },
    {
        Kind::TaskSchedulerSingleton,
        "TaskScheduler::singleton",
        { "48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? E8 ?? ?? ?? ??" },
        L"RobloxPlayerBeta.dll",
        true,
        "returns TaskScheduler instance. RIP-relative load of cached ptr."
    },
    {
        Kind::TaskSchedulerStep,
        "TaskScheduler::step",
        { "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B D9 48 8B 49 ??" },
        L"RobloxPlayerBeta.dll",
        true,
        "per-frame dispatch. This is the hook target for running our work."
    },
    {
        Kind::DataModelGetter,
        "ScriptContext::getDataModel",
        { "48 8B 81 ?? ?? ?? ?? 48 85 C0 74 ?? 48 C1 E8 03 C3" },
        L"RobloxPlayerBeta.dll",
        true,
        "walks ScriptContext -> DataModel. Encoded pointer, shift by 3."
    },
    {
        Kind::ScriptContextGetter,
        "global ScriptContext",
        { "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 80 ?? ?? ?? ??" },
        L"RobloxPlayerBeta.dll",
        true,
        "global accessor for the ScriptContext. Entry to the Lua world."
    },
    {
        Kind::RunningScriptsHead,
        "ScriptContext::runningScripts",
        { "48 8D 81 ?? ?? ?? ?? 48 3B C8 74 ?? 48 8B 01" },
        L"RobloxPlayerBeta.dll",
        true,
        "intrusive list head of active scripts. Offset into ScriptContext."
    },
    {
        Kind::PrintMessage,
        "Roblox::PrintMessage",
        { "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 81 EC ?? ?? ?? ?? 8B F9" },
        L"RobloxPlayerBeta.dll",
        true,
        "emits to StandardOut. We hook this to mirror our log into F9 console."
    },
};

constexpr std::size_t kEntryCount = sizeof(kEntries) / sizeof(kEntries[0]);
static_assert(kEntryCount == static_cast<std::size_t>(Kind::Count),
              "kEntries must cover every Kind");

// Resolution results, populated by ResolveAll. Indexed by Kind. Any slot
// not resolved stays at 0, and Has(Kind) returns false for it.
//
// Not a struct of named fields because callers iterate by Kind and because
// adding a new Kind should not require editing two places.
struct Resolved {
    std::uintptr_t Address[static_cast<std::size_t>(Kind::Count)] = {};
};

// Process-wide resolution table. Populated once at boot. Read from anywhere
// after that. No synchronization: writes happen before any reader thread
// starts (we spin up pipeline threads only after ResolveAll completes).
Resolved& Global();

// Scan every entry in kEntries against its target module. Store hits in
// Global(). Log each outcome. Returns the number of entries that resolved.
std::uint32_t ResolveAll();

// Lookup helpers.
inline std::uintptr_t Get(Kind k) {
    return Global().Address[static_cast<std::size_t>(k)];
}

inline bool Has(Kind k) {
    return Get(k) != 0;
}

// Convenience for callers that want to emit a "we would do X but sig missing"
// log line without reimplementing the name lookup.
const char* NameOf(Kind k);

} // namespace ENI::Hyperion::Signatures
