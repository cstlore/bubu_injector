#pragma once

// =============================================================================
// Hyperion::TaskScheduler - Roblox-thread work pump
// =============================================================================
//
// Lua state operations (lua_pcall, lua_resume, stack manipulation) are not
// thread-safe. Calling into them from our boot thread or any other
// non-Roblox thread is a use-after-free waiting to happen - another Roblox
// thread is free to GC or mutate the state under us.
//
// The fix is a pump that runs our work on whatever thread Roblox has
// designated for script execution. Roblox does this via TaskScheduler:
// it dispatches jobs per frame, one of which is the script VM job. If we
// hook the dispatch function and pop our own queued closures before
// chaining to the original, our closures run on the correct thread with
// the correct stack.
//
// LIFECYCLE
//
// 1. ResolveAll runs at boot. If TaskSchedulerStep sig is missing (which
//    it always is today) Install() logs "skipped" and returns. No hook,
//    no pump - the queue stays closed and Enqueue returns false.
// 2. If the sig ever resolves, Install() MinHook-detours TaskScheduler::step.
//    The first time the detour fires, we know we're on a Roblox thread:
//    we lazily spawn the InputPipe worker (which can safely call into
//    Enqueue from its own thread) and drain any queued items.
// 3. Enqueue is called by LuaPipeline::Execute from arbitrary threads.
//    It pushes onto a ring buffer guarded by a critsec. If the queue is
//    full, the push is dropped and logged - we prefer losing one script
//    over stalling the script input channel.
//
// TODAY (placeholder mode)
//
// Install returns false because the sig doesn't resolve. Enqueue still
// works as a data structure but nothing drains the queue. LuaPipeline
// calls through us and logs "[taskscheduler] pump not armed" so the
// script author knows why their work didn't run.
//
// =============================================================================

#include <cstddef>
#include <cstdint>
#include <functional>

namespace ENI::Hyperion::TaskScheduler {

// A unit of deferred work. Captured closures are fine - we std::move them
// into a fixed slot on enqueue, invoke on the pump thread, destroy on
// completion.
using Job = std::function<void()>;

// Install the MinHook detour on TaskScheduler::step. Safe to call whether
// or not the sig resolved - if it didn't, returns false and logs skipped.
// Must be called exactly once from ENIBootEntry after Signatures::ResolveAll.
bool Install();

// Remove the detour and drop any pending work. Idempotent.
void Uninstall();

// Push a job onto the pump queue. Returns true if accepted, false if:
//   - Install has not succeeded (most common today)
//   - The queue is full
//   - Job is empty
// Thread-safe. Legal to call before Install - the job will be held until
// the first drain (but with no pump, the first drain never happens).
bool Enqueue(Job job);

// Diagnostic. Returns the number of jobs still queued. Primarily for
// log lines on shutdown to flag dropped work.
std::size_t PendingCount();

// True once the detour has fired at least once and we have confidence
// that subsequent drains will happen on a Roblox-owned thread.
bool IsArmed();

} // namespace ENI::Hyperion::TaskScheduler
