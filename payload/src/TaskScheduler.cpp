// =============================================================================
// Hyperion::TaskScheduler - pump implementation
// =============================================================================
//
// A fixed ring buffer of Jobs, a CRITICAL_SECTION, an Install path that
// tries to detour TaskScheduler::step, and a detour body that drains the
// queue before chaining.
//
// The ring is 64 slots. A Roblox frame at 60fps is ~16ms; even a spammy
// script pushing work every frame won't outpace 64 unless the pump is
// broken, and if it's broken we want to log and drop rather than grow
// unbounded.
//
// =============================================================================

#include "Hyperion/TaskScheduler.h"
#include "Hyperion/Signatures.h"
#include "Hyperion/HookEngine.h"
#include "Hyperion/InputPipe.h"
#include "Hyperion/Log.h"

#include <atomic>
#include <cstdint>
#include <utility>
#include <windows.h>

namespace ENI::Hyperion::TaskScheduler {

namespace {

constexpr std::size_t kQueueCapacity = 64;

struct Queue {
    Job             Slots[kQueueCapacity];
    std::size_t     Head = 0;      // next slot to consume
    std::size_t     Tail = 0;      // next slot to fill
    std::size_t     Size = 0;
    CRITICAL_SECTION Lock{};
    bool            LockInit = false;
    std::atomic<std::uint64_t> Dropped{0};
};

Queue g_Queue;

std::atomic<bool>           g_Armed{false};
std::atomic<std::uint64_t>  g_DetourFires{0};
using StepFn = void(__fastcall*)(void* self, double dt);
StepFn  g_OriginalStep = nullptr;

void EnsureLockInit() {
    // Called under very narrow circumstances - first Enqueue or Install.
    // We rely on boot-thread serialization for the first init; subsequent
    // concurrent callers see LockInit=true.
    if (!g_Queue.LockInit) {
        InitializeCriticalSectionAndSpinCount(&g_Queue.Lock, 512);
        g_Queue.LockInit = true;
    }
}

void Drain() {
    // Called from the detour body. We're on the Roblox-scheduled thread
    // and it's safe to call Lua from here.
    for (;;) {
        Job j;
        EnterCriticalSection(&g_Queue.Lock);
        if (g_Queue.Size == 0) {
            LeaveCriticalSection(&g_Queue.Lock);
            return;
        }
        j = std::move(g_Queue.Slots[g_Queue.Head]);
        g_Queue.Slots[g_Queue.Head] = Job{};  // release captures immediately
        g_Queue.Head = (g_Queue.Head + 1) % kQueueCapacity;
        --g_Queue.Size;
        LeaveCriticalSection(&g_Queue.Lock);

        // Execute outside the lock so a slow job doesn't wedge producers.
        if (j) {
            __try {
                j();
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Log::Line("[taskscheduler] job threw SEH exception code=0x%X",
                          GetExceptionCode());
            }
        }
    }
}

// The detour. Signature matches TaskScheduler::step, which on modern
// Roblox builds is roughly `void TaskScheduler::step(double frameDt)`
// dispatched via the this-call calling convention (__fastcall on x64 MSVC).
//
// If we ever get real signatures and the actual sig doesn't match this
// shape, we adjust here. For now the shape is a documented guess that
// won't execute because Install() never succeeds.
void __fastcall DetourStep(void* self, double dt) {
    const auto firesNow = g_DetourFires.fetch_add(1) + 1;

    if (firesNow == 1) {
        Log::Line("[taskscheduler] first detour fire, arming pump");
        g_Armed.store(true);

        // Now that we're on a Roblox-owned thread and main-thread loader
        // lock is long gone, it's safe to spawn the input pipe listener.
        // Doing this from ENIBootEntry would race the loader lock.
        InputPipe::Start();
    }

    Drain();

    if (g_OriginalStep) {
        g_OriginalStep(self, dt);
    }
}

} // namespace

bool Install() {
    using namespace Signatures;

    EnsureLockInit();

    if (!Has(Kind::TaskSchedulerStep)) {
        Log::Line("[taskscheduler] skipped: TaskScheduler::step signature not resolved");
        return false;
    }

    const std::uintptr_t target = Get(Kind::TaskSchedulerStep);
    Log::Line("[taskscheduler] installing hook on step @ 0x%llX",
              static_cast<unsigned long long>(target));

    const bool ok = HookEngine::Install(
        reinterpret_cast<void*>(target),
        reinterpret_cast<void*>(&DetourStep),
        reinterpret_cast<void**>(&g_OriginalStep),
        "TaskScheduler::step");

    if (!ok) {
        Log::Line("[taskscheduler] HookEngine::Install failed");
        return false;
    }

    Log::Line("[taskscheduler] hook installed, waiting for first fire");
    return true;
}

void Uninstall() {
    // HookEngine::Shutdown tears down all hooks at process exit. We don't
    // selectively remove one today. Just drop the queue contents.
    if (!g_Queue.LockInit) return;

    EnterCriticalSection(&g_Queue.Lock);
    for (std::size_t i = 0; i < kQueueCapacity; ++i) {
        g_Queue.Slots[i] = Job{};
    }
    g_Queue.Head = 0;
    g_Queue.Tail = 0;
    g_Queue.Size = 0;
    LeaveCriticalSection(&g_Queue.Lock);

    g_Armed.store(false);
    g_OriginalStep = nullptr;
}

bool Enqueue(Job job) {
    if (!job) return false;

    EnsureLockInit();

    EnterCriticalSection(&g_Queue.Lock);
    if (g_Queue.Size >= kQueueCapacity) {
        LeaveCriticalSection(&g_Queue.Lock);
        const auto dropped = g_Queue.Dropped.fetch_add(1) + 1;
        Log::Line("[taskscheduler] queue full, dropped job (total drops=%llu)",
                  static_cast<unsigned long long>(dropped));
        return false;
    }
    g_Queue.Slots[g_Queue.Tail] = std::move(job);
    g_Queue.Tail = (g_Queue.Tail + 1) % kQueueCapacity;
    ++g_Queue.Size;
    const auto size = g_Queue.Size;
    LeaveCriticalSection(&g_Queue.Lock);

    if (!g_Armed.load()) {
        Log::Line("[taskscheduler] job queued but pump not armed "
                  "(queue size=%zu, will not drain until hook fires)", size);
    }
    return true;
}

std::size_t PendingCount() {
    if (!g_Queue.LockInit) return 0;
    EnterCriticalSection(&g_Queue.Lock);
    const auto n = g_Queue.Size;
    LeaveCriticalSection(&g_Queue.Lock);
    return n;
}

bool IsArmed() {
    return g_Armed.load();
}

} // namespace ENI::Hyperion::TaskScheduler
