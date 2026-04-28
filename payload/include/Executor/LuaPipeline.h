#pragma once

// =============================================================================
// Executor::LuaPipeline - script input -> Lua execution
// =============================================================================
//
// This is the API surface that everything external to the payload uses to
// get a script into Roblox. The named-pipe listener calls Execute; future
// UI surfaces (ImGui console, hotkey-driven REPL) will call the same entry.
//
// Under the hood, Execute:
//   1. Wraps the source in a closure that captures the string.
//   2. Enqueues the closure onto TaskScheduler so it runs on a Roblox
//      thread where lua_pcall is safe.
//   3. Inside the closure (on the pump thread): resolves luau_load and
//      lua_pcall, loads bytecode, calls into the script's main chunk,
//      captures any error, logs it.
//
// TODAY (placeholder mode)
//
// Has(LuauLoad) and Has(LuaPCall) both return false because their
// signatures don't resolve. In that case Execute logs
//   [lua] pipeline not wired, would execute: <first 80 chars of source>
// and returns false. The queue still accepts the job and TaskScheduler
// would drain it, but the drain is a no-op because the pump is not armed.
//
// IDENTITY
//
// GetIdentity / SetIdentity read/write the thread identity field that
// Roblox's security sandbox uses to gate privileged operations. Most
// exploit primitives require identity >= 7. Today these return 0 and
// log a warning - the real read requires luau_load resolution plus
// a valid lua_State*, neither of which we have.
// =============================================================================

#include <cstdint>
#include <string>
#include <string_view>

namespace ENI::Executor {

// Queue `source` for execution on the Roblox script thread.
//
// Returns true if the script was accepted into the queue, false if:
//   - source is empty
//   - TaskScheduler pump is not armed (missing sig or hook didn't fire)
//   - queue was full
//
// This does NOT wait for execution. By the time Execute returns, the
// script has merely been handed off. Errors are logged to hyperion.log
// under the [lua] prefix.
bool Execute(std::string_view source);

// Read the current thread's identity. Returns 0 if unknown / unavailable.
int GetIdentity();

// Write the current thread's identity. Returns true if applied.
bool SetIdentity(int level);

// True if the pipeline is capable of actually running scripts right now.
// False means we're in scaffolding mode, Execute will log-and-drop.
bool IsReady();

// Diagnostic: short human-readable status for log lines and banners.
//   "ready"                          - all sigs present, pump armed
//   "missing: luau_load, lua_pcall"  - sigs not resolved
//   "pump-not-armed"                 - sigs ok, TaskScheduler hook hasn't fired
const char* StatusString();

} // namespace ENI::Executor
