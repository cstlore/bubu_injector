#pragma once

// =============================================================================
// Hyperion::InputPipe - named-pipe script input channel
// =============================================================================
//
// External callers (a UI loader, a CLI, a REPL running in another process)
// push Luau source into the payload over a named pipe. We read until the
// pipe disconnects, parse length-prefixed frames out of the stream, and
// hand each frame to Executor::Execute.
//
// WIRE FORMAT
//
// Little-endian 4-byte length, then that many bytes of UTF-8 source.
// No other framing, no magic, no checksum. The consumer (Execute) will
// tolerate malformed Luau by logging a compiler error - we don't need
// framing-layer validation for "your script won't parse."
//
//   [LEN:u32_le][BODY:u8 * LEN]
//
// Max LEN is 1 MiB. Anything larger is rejected and the pipe reset.
//
// PIPE NAME
//
//   \\.\pipe\ENI_input
//
// Single instance. Concurrent writers serialize at the pipe layer.
// Security descriptor allows local user + SYSTEM; no remote access.
//
// LIFECYCLE
//
// Start() spawns a worker thread that creates the pipe and accepts
// connections in a loop. One connection at a time. If the pipe read
// errors, the worker logs and retries.
//
// MUST NOT be called from ENIBootEntry - creating a thread inside the
// suspended Roblox process with the main thread still frozen pokes the
// loader-lock dragons. Instead, Start() is called from the first
// TaskScheduler detour fire (once we know we're past Byfron and on a
// Roblox-owned thread).
//
// Stop() signals the worker and waits for it to exit. Called from
// Uninstall paths - today nothing calls it because we never shut down
// cleanly, but it's wired so a future graceful-unload path works.
// =============================================================================

#include <cstddef>
#include <cstdint>

namespace ENI::Hyperion::InputPipe {

// Pipe name, hardcoded. Exposed for tests / external tools.
constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\ENI_input";

// Max single-script size. 1 MiB handles every realistic exploit script
// (the big ones are ~200KB fully inlined); larger submissions probably
// indicate a bug or abuse and get rejected at the framing layer.
constexpr std::uint32_t kMaxFrameSize = 1u * 1024u * 1024u;

// Spawn the listener thread. Idempotent; second call logs and returns.
// Returns true if the thread was created.
bool Start();

// Signal the listener to stop, disconnect the pipe, join the thread.
// Idempotent.
void Stop();

// Diagnostic.
bool IsRunning();
std::uint64_t FramesAccepted();
std::uint64_t FramesRejected();

} // namespace ENI::Hyperion::InputPipe
