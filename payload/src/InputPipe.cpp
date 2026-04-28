// =============================================================================
// Hyperion::InputPipe - listener thread implementation
// =============================================================================
//
// Creates the pipe, accepts one connection at a time, reads length-prefixed
// UTF-8 frames, hands each to Executor::Execute. All errors log and the
// worker recovers by disconnecting and re-accepting.
//
// SECURITY
//
// The pipe is created with a default security descriptor (the one Windows
// hands back when we pass nullptr to the SECURITY_ATTRIBUTES param). That
// allows the owning user and SYSTEM to connect, and nobody else. If we
// ever care about restricting to same-process or adding signed-writer
// checks, we'd build an explicit SD here. Not needed for scaffolding.
//
// SHUTDOWN
//
// Stop() sets g_StopFlag and calls CancelSynchronousIo on the listener
// thread, then waits for the thread to exit with a 2s timeout. If the
// thread is stuck in a hostile syscall (shouldn't happen, but Hyperion
// does weird things) we skip the Close on the pipe handle and let process
// exit clean it up.
// =============================================================================

#include "Hyperion/InputPipe.h"
#include "Hyperion/Log.h"
#include "Executor/LuaPipeline.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <windows.h>

namespace ENI::Hyperion::InputPipe {

namespace {

std::atomic<bool>          g_Running{false};
std::atomic<bool>          g_StopRequested{false};
std::atomic<std::uint64_t> g_FramesAccepted{0};
std::atomic<std::uint64_t> g_FramesRejected{0};

HANDLE g_WorkerThread = nullptr;
HANDLE g_CurrentPipe  = INVALID_HANDLE_VALUE;

// Read exactly `count` bytes or fail. Handles partial reads (ReadFile on
// a pipe can and will return fewer bytes than asked even in blocking mode).
bool ReadExact(HANDLE pipe, void* buf, std::uint32_t count) {
    auto* p = static_cast<std::uint8_t*>(buf);
    std::uint32_t got = 0;
    while (got < count) {
        DWORD chunk = 0;
        if (!ReadFile(pipe, p + got, count - got, &chunk, nullptr)) {
            return false;
        }
        if (chunk == 0) return false;  // EOF
        got += chunk;
    }
    return true;
}

void HandleOneConnection(HANDLE pipe) {
    for (;;) {
        if (g_StopRequested.load()) return;

        std::uint32_t len = 0;
        if (!ReadExact(pipe, &len, sizeof(len))) {
            Log::Line("[pipe] client disconnected or read error (len-prefix)");
            return;
        }

        if (len == 0) {
            Log::Line("[pipe] rejecting zero-length frame");
            g_FramesRejected.fetch_add(1);
            continue;
        }
        if (len > kMaxFrameSize) {
            Log::Line("[pipe] rejecting oversized frame: %u bytes (max=%u)",
                      len, kMaxFrameSize);
            g_FramesRejected.fetch_add(1);
            return;  // malformed stream - resync by disconnecting
        }

        std::string body;
        body.resize(len);
        if (!ReadExact(pipe, body.data(), len)) {
            Log::Line("[pipe] read error during body (expected %u bytes)", len);
            return;
        }

        g_FramesAccepted.fetch_add(1);
        Log::Line("[pipe] accepted frame: %u bytes", len);

        // Hand off. Executor::Execute logs its own outcome.
        Executor::Execute(std::string_view(body));
    }
}

DWORD WINAPI WorkerMain(LPVOID) {
    Log::Line("[pipe] listener worker started");

    while (!g_StopRequested.load()) {
        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,                       // single instance
            0,                       // no outbound buffer
            65536,                   // 64K inbound buffer
            0,                       // default timeout
            nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            const auto err = GetLastError();
            Log::Line("[pipe] CreateNamedPipeW failed: error=%lu", err);
            Sleep(1000);
            continue;
        }

        g_CurrentPipe = pipe;
        Log::Line("[pipe] created %ls, waiting for client", kPipeName);

        const BOOL connected = ConnectNamedPipe(pipe, nullptr)
            ? TRUE
            : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (g_StopRequested.load()) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            g_CurrentPipe = INVALID_HANDLE_VALUE;
            break;
        }

        if (connected) {
            Log::Line("[pipe] client connected");
            HandleOneConnection(pipe);
            DisconnectNamedPipe(pipe);
        } else {
            Log::Line("[pipe] ConnectNamedPipe failed: error=%lu", GetLastError());
        }

        CloseHandle(pipe);
        g_CurrentPipe = INVALID_HANDLE_VALUE;
    }

    Log::Line("[pipe] listener worker exiting");
    g_Running.store(false);
    return 0;
}

} // namespace

bool Start() {
    bool expected = false;
    if (!g_Running.compare_exchange_strong(expected, true)) {
        Log::Line("[pipe] Start: already running");
        return false;
    }

    g_StopRequested.store(false);
    g_WorkerThread = CreateThread(nullptr, 0, &WorkerMain, nullptr, 0, nullptr);
    if (!g_WorkerThread) {
        Log::Line("[pipe] Start: CreateThread failed error=%lu", GetLastError());
        g_Running.store(false);
        return false;
    }
    Log::Line("[pipe] Start: worker thread=%p", static_cast<void*>(g_WorkerThread));
    return true;
}

void Stop() {
    if (!g_Running.load()) return;
    g_StopRequested.store(true);

    // If the worker is blocked in ConnectNamedPipe, poke it by opening
    // and immediately closing a client on the pipe. This unblocks the
    // server-side accept.
    const HANDLE wake = CreateFileW(kPipeName, GENERIC_WRITE, 0, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
    if (wake != INVALID_HANDLE_VALUE) {
        CloseHandle(wake);
    }

    if (g_WorkerThread) {
        const DWORD waitResult = WaitForSingleObject(g_WorkerThread, 2000);
        if (waitResult != WAIT_OBJECT_0) {
            Log::Line("[pipe] Stop: worker did not exit in 2s, leaking handle");
        }
        CloseHandle(g_WorkerThread);
        g_WorkerThread = nullptr;
    }
}

bool IsRunning()                 { return g_Running.load(); }
std::uint64_t FramesAccepted()   { return g_FramesAccepted.load(); }
std::uint64_t FramesRejected()   { return g_FramesRejected.load(); }

} // namespace ENI::Hyperion::InputPipe
