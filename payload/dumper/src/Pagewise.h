#pragma once

// =============================================================================
// Pagewise.h - SEH-guarded single-page memcpy
// =============================================================================
//
// One job: copy at most 4096 bytes from `src` to `dst`, returning false
// rather than terminating the process if the source page faults. The
// dumper iterates over Roblox's address space committing-page by
// committing-page, and even after VirtualQuery says MEM_COMMIT we can
// still hit a PAGE_GUARD trip-wire or a dynamically-revoked PAGE_NOACCESS
// (Hyperion likes to flip protections on regions it considers sensitive).
// We catch the AV / guard-page exception, zero-fill the destination
// upstream, and keep walking.
//
// MSVC rule: a function containing __try cannot have any C++ object with
// a destructor in its lexical scope. Pagewise.cpp's body keeps to POD
// locals + a `volatile bool` only. Same constraint TaskScheduler.cpp's
// InvokeJobSEH already navigates - this is just the read-only twin.
// =============================================================================

#include <cstddef>

namespace ENI::Dumper {

// Returns true on a clean copy, false if the read raised an SEH
// exception. `len` must be <= 4096 (the caller clamps).
bool ReadPageSEH(void* dst, const void* src, std::size_t len);

} // namespace ENI::Dumper
