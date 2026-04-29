#pragma once

// =============================================================================
// KernelRead.h - Cross-process VA reads via the BYOVD driver's IOCTL
// =============================================================================
//
// One primitive: read N bytes from another process's virtual address
// space, given that process's PID and a target VA. Backed by the
// driver loaded via DriverLoader.h.
//
// Kernel side does:
//   PsLookupProcessByProcessId(pid, &eproc);
//   KeStackAttachProcess(eproc, &state);
//   __try { memcpy(usermode_dst, target_va, size); }
//   __except (EXCEPTION_EXECUTE_HANDLER) { ... }
//   KeUnstackDetachProcess(&state);
//   ObDereferenceObject(eproc);
//
// User side does: build the IOCTL input struct, DeviceIoControl, check
// status. PPL filters OpenProcess from ring-3, but ring-0 doesn't go
// through OpenProcess - PsLookupProcessByProcessId returns the EPROCESS
// regardless of protection.
// =============================================================================

#include "DriverLoader.h"

#include <cstddef>
#include <cstdint>

namespace ENI::Byovd {

// Read `size` bytes from `pid`'s virtual address `srcVa` into `dst`.
// Returns the number of bytes actually read on success (always == size
// for a clean read; less if the read straddled an unreadable page and
// the driver bailed mid-copy). Returns 0 on hard failure with
// GetLastError() set.
//
// Why this returns size_t and not bool: paging rules in the target
// process are unpredictable. Some pages will be PAGE_NOACCESS at the
// moment we read, others COMMIT but unbacked, others guarded by
// hardware breakpoints. We chunk reads at 4 KB and let partial returns
// surface back to the caller's page-walk logic, exactly like the
// in-process Pagewise.cpp dumper does.
std::size_t KernelReadProcessMemory(const DriverHandle& drv,
                                    DWORD pid,
                                    std::uintptr_t srcVa,
                                    void* dst,
                                    std::size_t size);

} // namespace ENI::Byovd
