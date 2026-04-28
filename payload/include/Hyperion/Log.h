#pragma once

// =============================================================================
// Hyperion::Log - file-only payload logger
// =============================================================================
//
// We absolutely cannot AllocConsole inside RobloxPlayerBeta.exe - that pops
// a console window the user (and any screen-recording moderator tooling)
// can see. Instead, everything goes to a flat-file log under
// BootInfo->LogsDir\hyperion.log.
//
// The log handle is opened once during boot and cached. Writes are
// best-effort; we'd rather drop a line than block the boot path waiting
// on a slow disk. Each line gets a millisecond-precision timestamp.
//
// Thread-safety: a single CRITICAL_SECTION guards the file handle. The
// boot path is single-threaded so contention is zero on the hot path.
// Once Roblox is running, hooks may call Log from arbitrary threads -
// the lock keeps lines from interleaving mid-byte.
//
// Buffering: we use FILE_FLAG_WRITE_THROUGH so a crash mid-line still
// leaves the bytes on disk. Costs ~100us per write, fine for our cadence.
// =============================================================================

#include <cstdarg>
#include <cstdint>
#include <windows.h>

namespace ENI::Hyperion::Log {

// Open the log file. Path is widechar. Best-effort - if open fails,
// subsequent Line() calls are silent no-ops.
void Open(const wchar_t* path);

// Close. Idempotent.
void Close();

// Append one line. printf-style (ASCII format string for simplicity -
// most of what we log is hex / numbers / ASCII module names).
// %wZ is supported as a special case for UNICODE_STRING* args (we
// roll our own since the CRT's %wZ is unreliable cross-runtime).
void Line(const char* fmt, ...);

// Same but with explicit va_list. Used by macros below.
void LineV(const char* fmt, std::va_list ap);

} // namespace ENI::Hyperion::Log
