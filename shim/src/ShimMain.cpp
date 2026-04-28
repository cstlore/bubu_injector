// =============================================================================
// ShimMain.cpp - the launcher-process shim DLL
// =============================================================================
//
// This DLL is manual-mapped into RobloxPlayerLauncher.exe by ENILauncher.
// It does the following on entry:
//
//   1. Validates the ShimEnvelope (magic / version / size).
//   2. Reads the payload DLL from disk into memory once, so the on-disk
//      file can be deleted immediately after the launcher starts (helps
//      reduce on-disk evidence even though the bytes still live in memory).
//   3. Hooks CreateProcessW.
//   4. Returns success.
//
// When the launcher subsequently calls CreateProcessW for any process,
// our detour examines the application name. If it's RobloxPlayerBeta.exe:
//   a. Add CREATE_SUSPENDED to dwCreationFlags.
//   b. Call the real CreateProcessW via the trampoline.
//   c. With the suspended Roblox process handle in hand, run the
//      ManualMapper (linked into the shim) on it.
//   d. ResumeThread the Roblox main thread.
//   e. Optionally uninstall our hook and unload ourselves from the launcher.
//
// For any other process spawn (Roblox sometimes shells out to helpers)
// the detour just calls the trampoline unchanged.
//
// =============================================================================

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>
#include <windows.h>

#include "BootInfo.h"
#include "PayloadCrypt.h"
#include "ShimContract.h"
#include "ShimStatus.h"
#include "InlineHook.h"

// We link the loader's ManualMapper directly into the shim. Keeps the
// shim self-contained: one DLL, no IPC, no shared state with the
// ENILauncher process.
#include "ManualMapper.h"

namespace ENI::Shim {

// -----------------------------------------------------------------------------
// Shim-wide state
// -----------------------------------------------------------------------------
//
// All globals live inside an anonymous namespace so they don't pollute
// the linker's symbol table once the shim is mapped. (Manual mapping
// preserves these as ordinary BSS - they exist, just nameless from the
// outside.)

namespace {

struct ShimState {
    bool Initialized = false;
    std::uint32_t Flags = 0;
    std::wstring PayloadPath;
    std::wstring LogPath;
    std::vector<std::uint8_t> PayloadBytes;
    Boot::BootInfo PendingBootInfo{};        // Carries through to ManualMapper

    // Mirror of ShimEnvelope's ExecutorBoot fields, in the actual struct
    // form ManualMapper expects.
    Injector::MapOptions MapOpts;

    InlineHook CreateProcessW_Hook;
    std::mutex Lock;

    // Set true once we've handed off to Roblox successfully. Subsequent
    // CreateProcessW calls (the launcher might spawn helpers) pass through
    // unchanged. Atomic because the detour can be called from any thread
    // the launcher uses for spawning.
    std::atomic<bool> RobloxInjected{false};
};

ShimState* g_State = nullptr;

// Append a line to the log file if Verbose is set. Best-effort - we
// don't propagate errors. We open/close per write to avoid holding the
// file handle, since the launcher might run for a while between hook
// install and the actual Roblox spawn.
void Log(const wchar_t* fmt, ...) {
    if (!g_State || !(g_State->Flags & ShimFlags::Verbose)) return;
    if (g_State->LogPath.empty()) return;

    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);

    // Open append, write, close. Inefficient under load but fine for
    // the once-per-event cadence we have.
    HANDLE h = CreateFileW(g_State->LogPath.c_str(),
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    char ascii[1024];
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, ascii, sizeof(ascii), nullptr, nullptr);
    if (len > 0) {
        DWORD written = 0;
        WriteFile(h, ascii, static_cast<DWORD>(len - 1), &written, nullptr);
        WriteFile(h, "\n", 1, &written, nullptr);
    }
    CloseHandle(h);
}

// Lower-case ASCII compare for path matching. We don't pull in CRT's
// _wcsicmp because it might be one of the functions we end up hooking
// later for stealth.
bool PathEndsWithCaseInsensitive(const wchar_t* full, const wchar_t* suffix) {
    if (!full || !suffix) return false;
    const std::size_t fullLen = std::wcslen(full);
    const std::size_t suffLen = std::wcslen(suffix);
    if (suffLen > fullLen) return false;

    const wchar_t* tail = full + (fullLen - suffLen);
    for (std::size_t i = 0; i < suffLen; i++) {
        wchar_t a = tail[i];
        wchar_t b = suffix[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b - L'A' + L'a');
        if (a != b) return false;
    }
    return true;
}

// Quick check: is this CreateProcessW call asking to spawn Roblox?
//
// CreateProcessW receives the target either via lpApplicationName (full
// path) or lpCommandLine (parsed; first token is the executable). We
// check both. The match is "ends with RobloxPlayerBeta.exe" (case-insensitive)
// rather than exact-match because the launcher passes a full absolute path
// that varies per-install.
bool IsRobloxSpawn(LPCWSTR appName, LPCWSTR cmdLine) {
    constexpr const wchar_t* kRobloxExe = L"RobloxPlayerBeta.exe";
    if (appName && PathEndsWithCaseInsensitive(appName, kRobloxExe)) return true;
    if (!cmdLine) return false;

    // Parse cmdLine's first token. Rules per Win32:
    //   * If it starts with ", read until the matching ".
    //   * Otherwise read until the first whitespace.
    // We don't need full CommandLineToArgvW correctness - just the first
    // token's tail.
    std::wstring first;
    const wchar_t* p = cmdLine;
    while (*p == L' ' || *p == L'\t') p++;

    if (*p == L'"') {
        p++;
        while (*p && *p != L'"') first.push_back(*p++);
    } else {
        while (*p && *p != L' ' && *p != L'\t') first.push_back(*p++);
    }
    return PathEndsWithCaseInsensitive(first.c_str(), kRobloxExe);
}

} // anonymous namespace

// -----------------------------------------------------------------------------
// CreateProcessW detour
// -----------------------------------------------------------------------------
//
// This function MUST match the exact signature of the real CreateProcessW.
// Any divergence (missing __stdcall, wrong return type, missing arg) and
// the launcher's call into us trashes the stack and crashes.

using PFN_CreateProcessW = BOOL(WINAPI*)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static BOOL WINAPI CreateProcessW_Detour(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    auto trampoline = reinterpret_cast<PFN_CreateProcessW>(g_State->CreateProcessW_Hook.Trampoline);

    const bool isRoblox = !g_State->RobloxInjected.load(std::memory_order_acquire) &&
                          IsRobloxSpawn(lpApplicationName, lpCommandLine);

    if (!isRoblox) {
        // Pass through unchanged.
        return trampoline(
            lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
    }

    Log(L"[shim] Roblox spawn detected. App=%ls Cmd=%ls",
        lpApplicationName ? lpApplicationName : L"<null>",
        lpCommandLine ? lpCommandLine : L"<null>");

    if (g_State->Flags & ShimFlags::DryRun) {
        Log(L"[shim] DryRun set - passing through without injecting");
        g_State->RobloxInjected.store(true, std::memory_order_release);
        return trampoline(
            lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
            lpStartupInfo, lpProcessInformation);
    }

    // Add CREATE_SUSPENDED. The launcher won't notice - it just calls
    // ResumeThread on lpProcessInformation->hThread eventually, which we
    // also intercept (or do ourselves immediately after injecting).
    const DWORD adjustedFlags = dwCreationFlags | CREATE_SUSPENDED;

    PROCESS_INFORMATION pi{};
    LPPROCESS_INFORMATION outPi = lpProcessInformation ? lpProcessInformation : &pi;

    const BOOL spawned = trampoline(
        lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, adjustedFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, outPi);

    if (!spawned) {
        Log(L"[shim] Real CreateProcessW failed: %lu", GetLastError());
        return FALSE;
    }

    Log(L"[shim] Roblox spawned suspended. PID=%lu TID=%lu",
        outPi->dwProcessId, outPi->dwThreadId);

    // -- Inject the payload via ManualMapper. ----------------------
    //
    // We have outPi->hProcess as a handle with PROCESS_ALL_ACCESS (since
    // we created the process ourselves). Roblox's main thread is paused
    // at the very first instruction in ntdll - Hyperion is NOT loaded.
    // This is our window.
    //
    // After the mapper completes, the payload's BootEntry has run and
    // installed its hooks. The mapper waits for BootEntry to return
    // (PROCESS_ATTACH semantics) before we resume the main thread, so
    // by the time Roblox actually starts executing user code, we're
    // already there.

    Injector::ManualMapper mapper(outPi->hProcess, g_State->MapOpts);
    auto result = mapper.Map(g_State->PayloadBytes);

    if (result.Status != Injector::MapStatus::Ok) {
        Log(L"[shim] ManualMapper failed: %S (payload return code: 0x%X)",
            Injector::MapStatusToString(result.Status), result.PayloadReturnCode);

        // Decision point: do we let Roblox launch un-injected, or kill it?
        // Killing it gives the user a clearer signal that something went
        // wrong (Roblox just doesn't start) rather than a confusing
        // half-working state. Kill.
        TerminateProcess(outPi->hProcess, 1);
        SetLastError(ERROR_INTERNAL_ERROR);
        return FALSE;
    }

    Log(L"[shim] Mapped at 0x%llX. Resuming Roblox main thread.",
        static_cast<unsigned long long>(result.RemoteImageBase));

    // Mark before resuming so the next CreateProcessW call (which the
    // launcher might fire for helpers) doesn't try to inject again.
    g_State->RobloxInjected.store(true, std::memory_order_release);

    // Resume Roblox. It now starts executing with our payload mapped.
    // Hyperion will load shortly after - the payload should already have
    // hooks ready to neutralize whatever Hyperion does at init.
    ResumeThread(outPi->hThread);

    // If the caller didn't supply a PROCESS_INFORMATION, close handles.
    if (!lpProcessInformation) {
        CloseHandle(outPi->hThread);
        CloseHandle(outPi->hProcess);
    }

    // Optional self-uninstall - reduces our footprint in the launcher
    // process once we're done.
    if (!(g_State->Flags & ShimFlags::StayResident)) {
        // Note: we don't unload the DLL itself (that would be
        // FreeLibraryAndExitThread, which is awkward from inside a hook).
        // We just remove the hook so subsequent calls go to the original.
        UninstallInlineHook(g_State->CreateProcessW_Hook);
        Log(L"[shim] Hook uninstalled. Shim now dormant.");
    }

    return TRUE;
}

// -----------------------------------------------------------------------------
// Envelope validation
// -----------------------------------------------------------------------------

static Status ValidateEnvelope(const ShimEnvelope* env) {
    if (!env) return Status::InvalidEnvelope;
    if (env->Magic != Magic) return Status::InvalidEnvelope;
    if (env->Version != ProtocolVersion) return Status::InvalidEnvelope;
    if (env->StructSize != sizeof(ShimEnvelope)) return Status::InvalidEnvelope;
    return Status::Ok;
}

// -----------------------------------------------------------------------------
// Entry point - called by the loader's manual-mapper boot stub
// -----------------------------------------------------------------------------

extern "C" __declspec(dllexport) std::uint32_t ENIShimEntry(const ShimEnvelope* env) {
    if (auto s = ValidateEnvelope(env); s != Status::Ok) {
        return static_cast<std::uint32_t>(s);
    }

    // Create state. We use a static so manual mapping doesn't need to
    // worry about CRT init order - the storage exists in BSS regardless.
    static ShimState state{};
    g_State = &state;

    state.Flags = env->Flags;
    state.PayloadPath = env->PayloadPath;
    state.LogPath = env->LogFile;

    Log(L"[shim] ENIShimEntry called. PayloadPath=%ls", state.PayloadPath.c_str());

    // Read the encrypted payload blob ONCE, now, then decrypt it in
    // memory. After this point the on-disk file is optional - the
    // launcher EXE could delete it and the shim still has the plaintext
    // ready for ManualMapper.
    //
    // payload.bin format (see shared/PayloadCrypt.h):
    //   magic(4) || nonce(12) || ciphertext(rest)
    //
    // Decrypt failures land us back at PayloadNotFound rather than a
    // dedicated DecryptFailed status because the user-facing recovery
    // is identical: re-build, re-deploy. Adding a separate status code
    // for "the file existed but was the wrong shape" buys nothing the
    // log line doesn't already convey.
    {
        std::vector<std::uint8_t> blob;
        {
            std::ifstream f(state.PayloadPath, std::ios::binary | std::ios::ate);
            if (!f) return static_cast<std::uint32_t>(Status::PayloadNotFound);
            const std::streamsize size = f.tellg();
            if (size <= static_cast<std::streamsize>(Crypt::HeaderBytes)) {
                Log(L"[shim] payload.bin too small (%lld bytes) - missing header?",
                    static_cast<long long>(size));
                return static_cast<std::uint32_t>(Status::PayloadNotFound);
            }
            f.seekg(0);
            blob.resize(static_cast<std::size_t>(size));
            f.read(reinterpret_cast<char*>(blob.data()), size);
            if (!f) return static_cast<std::uint32_t>(Status::PayloadNotFound);
        }

        const std::size_t plaintextCap = blob.size() - Crypt::HeaderBytes;
        state.PayloadBytes.assign(plaintextCap, 0);
        std::size_t plaintextSize = 0;
        if (!Crypt::TryDecryptPayload(blob.data(), blob.size(),
                                      state.PayloadBytes.data(), plaintextCap,
                                      &plaintextSize)) {
            Log(L"[shim] payload decrypt failed (bad magic or short read)");
            return static_cast<std::uint32_t>(Status::PayloadNotFound);
        }
        state.PayloadBytes.resize(plaintextSize);

        // Wipe the encrypted blob from our local stack-spill / heap. Best
        // effort - the OS keeps freed pages around until reuse, but this
        // at least kills the obvious "scan the shim's heap for ciphertext"
        // path that an analyst might try.
        std::memset(blob.data(), 0, blob.size());
    }
    Log(L"[shim] Payload decrypted, %llu plaintext bytes",
        static_cast<unsigned long long>(state.PayloadBytes.size()));

    // Translate the flat ShimEnvelope into the C++ MapOptions struct that
    // ManualMapper expects. This copy is cheap and keeps the C++ API
    // ergonomic for callers other than the shim.
    state.MapOpts.EraseHeaders    = env->EraseHeaders   != 0;
    state.MapOpts.UnlinkFromPeb   = env->UnlinkFromPeb  != 0;
    state.MapOpts.UseRemoteThread = env->UseRemoteThread != 0;
    state.MapOpts.BootTimeoutMs   = env->BootTimeoutMs;
    state.MapOpts.Flags           = env->BootFlags;
    state.MapOpts.ConfigDir       = env->ConfigDir;
    state.MapOpts.ScriptsDir      = env->ScriptsDir;
    state.MapOpts.LogsDir         = env->LogsDir;
    if (env->Flags & ShimFlags::HasPreResolved) {
        state.MapOpts.Addresses = env->Addresses;
    }

    // -- Install the CreateProcessW hook -------------------------------
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return static_cast<std::uint32_t>(Status::KernelHandleFailed);

    void* createProcW = reinterpret_cast<void*>(GetProcAddress(k32, "CreateProcessW"));
    if (!createProcW) return static_cast<std::uint32_t>(Status::GetProcAddressFailed);

    if (!InstallInlineHook(createProcW,
                           reinterpret_cast<void*>(&CreateProcessW_Detour),
                           state.CreateProcessW_Hook)) {
        Log(L"[shim] InstallInlineHook(CreateProcessW) failed");
        return static_cast<std::uint32_t>(Status::ProtectFailed);
    }

    Log(L"[shim] CreateProcessW hooked. Ready for Roblox spawn.");

    state.Initialized = true;
    return static_cast<std::uint32_t>(Status::Ok);
}

} // namespace ENI::Shim

// -----------------------------------------------------------------------------
// DllMain - intentionally minimal
// -----------------------------------------------------------------------------
//
// The shim is manual-mapped, so DllMain only runs if the mapper invokes a
// TLS callback or the user dynamically loads us via LoadLibrary. We do
// nothing here - all real work happens in ENIShimEntry which the mapper's
// boot stub calls directly.

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(GetModuleHandleW(nullptr));
    }
    return TRUE;
}
