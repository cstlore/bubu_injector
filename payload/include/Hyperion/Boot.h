#pragma once

// =============================================================================
// Hyperion::Boot - the ENIBootEntry export
// =============================================================================
//
// The ManualMapper invokes this single export via a tiny shellcode stub
// that passes a BootInfo* in rcx. We validate it, stand up logging, and
// hand off to Sentry::Arm. Returning 0 tells the loader we're good and
// the shim will resume Roblox's main thread.
//
// Anything we do here runs INSIDE RobloxPlayerBeta.exe with its main
// thread suspended. Hyperion has not loaded. Do as much as possible in
// this window because once the main thread resumes, our hook surface
// has to fight for relevance.
// =============================================================================

#include <cstdint>

#include "BootInfo.h"

extern "C" __declspec(dllexport) std::uint32_t ENIBootEntry(const ENI::Boot::BootInfo* info);
