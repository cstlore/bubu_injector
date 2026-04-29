// =============================================================================
// KernelRead.cpp - DeviceIoControl wrapper for cross-process VA reads
// =============================================================================
//
// Talks to bin\EniDrv.sys (built from driver/src/EniDrv.c). One IOCTL,
// IOCTL_ENI_READ_VM. Sends an ENI_READ_VM_REQUEST struct describing
// {pid, src_va, size, dst_user_va}; the driver does
// PsLookupProcessByProcessId + KeStackAttachProcess + bounce-buffered
// memcpy + write-back to our user-mode buffer.
//
// Design notes:
//   - Page-sized chunking mirrors the in-process Pagewise.cpp dumper.
//     If a single page is unreadable (PAGE_NOACCESS, guarded), we
//     surface the partial read up to the caller's page-walk loop and
//     it skips that page rather than aborting the whole region.
//   - We do NOT need OpenProcess on the target. PPL filters that;
//     we don't go through it. The driver uses PsLookupProcessByProcessId
//     which is purely a kernel-internal lookup unaffected by PPL.
// =============================================================================

#include "../include/KernelRead.h"
#include "../../driver/include/EniDrvShared.h"

#include <windows.h>
#include <winioctl.h>

namespace ENI::Byovd {

namespace {

// Cap each IOCTL at one page. The driver enforces a 256 MB hard limit
// of its own, but page-sized chunks let us bail granularly when one
// page in the middle of a region is PAGE_NOACCESS.
constexpr std::size_t CHUNK = 0x1000;

} // namespace

std::size_t KernelReadProcessMemory(const DriverHandle& drv,
                                    DWORD pid,
                                    std::uintptr_t srcVa,
                                    void* dst,
                                    std::size_t size) {
    if (drv.device == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }
    if (size == 0) return 0;

    auto* dstBytes = static_cast<unsigned char*>(dst);
    std::size_t total = 0;

    while (total < size) {
        const std::size_t want =
            (size - total < CHUNK) ? (size - total) : CHUNK;

        ENI_READ_VM_REQUEST req{};
        req.Pid       = pid;
        req.SrcVa     = static_cast<unsigned long long>(srcVa + total);
        req.DstUserVa = reinterpret_cast<unsigned long long>(dstBytes + total);
        req.Size      = static_cast<unsigned long long>(want);
        req.BytesRead = 0;

        DWORD bytesReturned = 0;
        // METHOD_BUFFERED on the input side: I/O manager copies our
        // ENI_READ_VM_REQUEST into the IRP's SystemBuffer for the
        // driver, and copies back any modifications (i.e. BytesRead)
        // when we set Information in the IRP completion.
        BOOL ok = DeviceIoControl(
            drv.device,
            IOCTL_ENI_READ_VM,
            &req, sizeof(req),         // input: the request struct
            &req, sizeof(req),         // output: same struct - I/O mgr
                                       // copies SystemBuffer back here
            &bytesReturned,
            nullptr);

        if (!ok) {
            // Hard IOCTL failure (e.g. invalid PID, driver returned
            // STATUS_ACCESS_VIOLATION because the source page faulted).
            // Surface what we got so far and let the caller decide
            // whether to skip-and-continue or bail.
            break;
        }
        if (req.BytesRead == 0) break;

        total += req.BytesRead;
        if (req.BytesRead < want) {
            // Partial: driver hit an unreadable page partway. Stop
            // here and let the caller's page-walk loop retry the next
            // page on its own.
            break;
        }
    }

    return total;
}

} // namespace ENI::Byovd
