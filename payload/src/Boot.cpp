// =============================================================================
// Boot.cpp - the ENIBootEntry export, top-level orchestrator
// =============================================================================
//
// What runs here, in order:
//   1. Validate BootInfo magic / version / size.
//   2. Open the log file (BootInfo->LogsDir + "\\hyperion.log").
//   3. Discover our own image extent (base + size) using __ImageBase
//      and VirtualQuery on ourselves.
//   4. Call Sentry::Arm.
//   5. Return 0 on success.
//
// We don't spawn any background threads from here. The boot thread that
// the loader created is the one running this function; when we return,
// it exits, GetExitCodeThread reads our return value, and the shim
// resumes Roblox.
//
// If we ever want a long-lived render/UI thread, it should be created
// AFTER ResumeThread (in a hook detour, e.g. when the first DirectX
// device is created). Spawning a thread inside the suspended Roblox
// process before Hyperion exists is technically possible but wakes up
// the loader-lock dragons - safer to wait.
// =============================================================================

#include "Hyperion/Boot.h"
#include "Hyperion/Sentry.h"
#include "Hyperion/Signatures.h"
#include "Hyperion/TaskScheduler.h"
#include "Hyperion/Log.h"
#include "Executor/LuaPipeline.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <windows.h>

#include "BootInfo.h"

// Linker-provided base of our DLL.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace {

constexpr std::uint32_t kStatusOk                 = 0;
constexpr std::uint32_t kStatusInvalidBootInfo    = 1;
constexpr std::uint32_t kStatusVersionMismatch    = 2;
constexpr std::uint32_t kStatusArmingFailed       = 3;

// Discover where our payload lives in memory and how big it is. We can't
// trust IMAGE_NT_HEADERS::SizeOfImage because the loader may have erased
// the headers (BootFlags::HeadersErased). VirtualQuery on __ImageBase
// gives us the AllocationBase and we can VirtualQuery forward to find
// the end of the contiguous reservation.
void DiscoverSelfExtent(std::uintptr_t& outBase, std::size_t& outSize) {
    outBase = reinterpret_cast<std::uintptr_t>(&__ImageBase);
    outSize = 0;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(&__ImageBase, &mbi, sizeof(mbi))) return;

    const auto allocBase = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
    if (!allocBase) return;
    outBase = allocBase;

    // Walk forward through pages that share the same AllocationBase.
    std::uintptr_t cursor = allocBase;
    while (true) {
        if (!VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi))) break;
        if (reinterpret_cast<std::uintptr_t>(mbi.AllocationBase) != allocBase) break;
        cursor = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }
    outSize = cursor - allocBase;
}

// Register our .pdata exception directory with the OS so SEH unwinding
// works through our manually-mapped frames. Without this, any access
// violation inside our payload (or one Hyperion deliberately faults
// into us) terminates Roblox because Windows' unwinder can't find a
// RUNTIME_FUNCTION entry covering the faulting RIP.
//
// The PE headers are still intact at this point - PostBootCleanup runs
// AFTER ENIBootEntry returns, so we can read DataDirectory[EXCEPTION]
// directly. We hand RtlAddFunctionTable the .pdata array and our image
// base; it walks the entries lazily on actual unwind.
//
// Returns true if the table was registered, false if no .pdata exists
// (rare but possible for tiny DLLs with no SEH/C++) or if the API call
// failed. Failure is non-fatal - the payload still runs, it's just one
// fault away from a hard crash.
bool RegisterExceptionDirectory() {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(&__ImageBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        ENI::Hyperion::Log::Line("[pdata] DOS magic mismatch, skipping registration");
        return false;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        reinterpret_cast<std::uint8_t*>(&__ImageBase) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        ENI::Hyperion::Log::Line("[pdata] NT signature mismatch, skipping registration");
        return false;
    }

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size) {
        ENI::Hyperion::Log::Line("[pdata] no .pdata in image (DataDirectory empty)");
        return false;
    }

    auto* table = reinterpret_cast<RUNTIME_FUNCTION*>(
        reinterpret_cast<std::uint8_t*>(&__ImageBase) + dir.VirtualAddress);
    const DWORD count = dir.Size / sizeof(RUNTIME_FUNCTION);

    const auto base = reinterpret_cast<DWORD64>(&__ImageBase);
    if (!RtlAddFunctionTable(table, count, base)) {
        ENI::Hyperion::Log::Line("[pdata] RtlAddFunctionTable failed (count=%u base=%p)",
                            count, reinterpret_cast<void*>(base));
        return false;
    }

    ENI::Hyperion::Log::Line("[pdata] registered %u RUNTIME_FUNCTION entries @ %p",
                        count, static_cast<void*>(table));
    return true;
}

// Compose LogsDir + "\\hyperion.log" into a fixed buffer.
void ComposeLogPath(const wchar_t* logsDir, wchar_t* out, std::size_t outCap) {
    if (!logsDir || !*logsDir || !out || outCap < 32) {
        if (out && outCap) out[0] = L'\0';
        return;
    }
    const std::size_t n = std::wcslen(logsDir);
    if (n + 16 >= outCap) {
        out[0] = L'\0';
        return;
    }
    std::wmemcpy(out, logsDir, n);
    out[n] = L'\0';
    // Ensure trailing backslash before appending filename.
    if (out[n ? n - 1 : 0] != L'\\' && out[n ? n - 1 : 0] != L'/') {
        out[n] = L'\\';
        out[n + 1] = L'\0';
    }
    const wchar_t* leaf = L"hyperion.log";
    std::size_t cur = std::wcslen(out);
    std::wmemcpy(out + cur, leaf, std::wcslen(leaf) + 1);
}

// Static so we own its storage for the lifetime of the process.
ENI::Boot::BootInfo g_BootInfo{};

} // namespace

extern "C" __declspec(dllexport) std::uint32_t ENIBootEntry(const ENI::Boot::BootInfo* info) {
    using namespace ENI;

    // -- 1. Validate ----------------------------------------------------
    if (!info) return kStatusInvalidBootInfo;
    if (info->Magic != Boot::Magic) return kStatusInvalidBootInfo;
    if (info->Version != Boot::ProtocolVersion) return kStatusVersionMismatch;
    if (info->StructSize != sizeof(Boot::BootInfo)) return kStatusVersionMismatch;

    // Stash for later access by other subsystems.
    std::memcpy(&g_BootInfo, info, sizeof(g_BootInfo));

    // -- 2. Logging -----------------------------------------------------
    wchar_t logPath[ENI::Boot::MaxPathChars] = {};
    ComposeLogPath(g_BootInfo.LogsDir, logPath,
                   sizeof(logPath) / sizeof(logPath[0]));
    Hyperion::Log::Open(logPath);
    Hyperion::Log::Line("[boot] ENIBootEntry called, BootInfo @ %p flags=0x%X",
                       static_cast<const void*>(info), g_BootInfo.Flags);
    Hyperion::Log::Line("[boot] Process pid=%u image=%p size=%llu",
                       g_BootInfo.Process.Pid,
                       reinterpret_cast<void*>(g_BootInfo.Process.BaseAddress),
                       static_cast<unsigned long long>(g_BootInfo.Process.ImageSize));

    // -- 3. Discover our own extent ------------------------------------
    std::uintptr_t selfBase = 0;
    std::size_t    selfSize = 0;
    DiscoverSelfExtent(selfBase, selfSize);
    Hyperion::Log::Line("[boot] payload self @ %p size=0x%llX",
                       reinterpret_cast<void*>(selfBase),
                       static_cast<unsigned long long>(selfSize));

    // -- 3.5 Register .pdata so SEH unwinds through our frames ---------
    // Must run before Sentry::Arm because the moment we install detours,
    // any fault inside our code (or one Hyperion deliberately probes us
    // with) needs RUNTIME_FUNCTION coverage or Roblox dies. PostBootCleanup
    // hasn't fired yet, so PE headers are still readable.
    RegisterExceptionDirectory();

    // BootInfo's own range comes from SelfAddress/SelfSize that the
    // mapper filled in. If they're zero (older mapper), fall back to
    // sizeof(BootInfo).
    std::uintptr_t bootInfoBase = g_BootInfo.SelfAddress
        ? g_BootInfo.SelfAddress
        : reinterpret_cast<std::uintptr_t>(info);
    std::size_t    bootInfoSize = g_BootInfo.SelfSize
        ? static_cast<std::size_t>(g_BootInfo.SelfSize)
        : sizeof(ENI::Boot::BootInfo);

    // -- 4. Arm Sentry --------------------------------------------------
    auto result = Hyperion::Sentry::Arm(selfBase, selfSize, bootInfoBase, bootInfoSize);

    if (!result.NtdllFound || !result.MinHookReady) {
        ENI::Hyperion::Log::Line("[boot] arming failed: ntdll=%d mh=%d",
                           result.NtdllFound ? 1 : 0,
                           result.MinHookReady ? 1 : 0);
        return kStatusArmingFailed;
    }

    Hyperion::Log::Line("[boot] OK: stubs=%u hooks=%u regions=%u ldr=%d",
                       result.StubsCached, result.HooksInstalled,
                       result.RegionsRegistered,
                       result.DllNotifyHooked ? 1 : 0);

    // -- 5. Resolve Roblox signatures ----------------------------------
    // In scaffolding mode every entry is a placeholder and resolves to 0.
    // The log line per entry documents the miss; downstream code degrades
    // gracefully via Signatures::Has() checks.
    const std::uint32_t sigsResolved = Hyperion::Signatures::ResolveAll();
    Hyperion::Log::Line("[boot] signatures: %u resolved", sigsResolved);

    // -- 6. Install TaskScheduler hook ---------------------------------
    // No-ops if TaskScheduler::step signature didn't resolve. When it
    // does, the hook arms the Lua execution pump and spawns the input
    // pipe listener on first fire.
    const bool taskSchedulerHooked = Hyperion::TaskScheduler::Install();
    Hyperion::Log::Line("[boot] task scheduler: %s",
                       taskSchedulerHooked ? "hooked" : "skipped");

    // -- 7. Pipeline status banner -------------------------------------
    Hyperion::Log::Line("[boot] pipeline status: %s",
                       Executor::StatusString());
    Hyperion::Log::Line("[boot] ENIBootEntry returning, main thread will resume");

    // We deliberately leave the log handle open for the lifetime of the
    // process; subsequent hook callbacks log into it.
    return kStatusOk;
}

// =============================================================================
// DllMain - intentionally minimal
// =============================================================================
//
// The mapper invokes ENIBootEntry directly via shellcode, so DllMain
// only fires for TLS callbacks (we have none) or if someone LoadLibrary's
// us (they shouldn't). We keep a minimal stub for completeness.

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(GetModuleHandleW(nullptr));
    }
    return TRUE;
}
