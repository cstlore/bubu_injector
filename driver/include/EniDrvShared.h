// =============================================================================
// EniDrvShared.h - IOCTL contract between ENIDrv (kernel) and user-mode
// =============================================================================
//
// Both byovd/ user-mode and driver/ kernel-mode #include this. Single
// source of truth for the device name + IOCTL value + request/response
// struct shape. Anything that diverges between the two sides becomes
// silent corruption, so we keep this header tiny and the boundary
// explicit.
//
// Wire format intentionally minimal: a request struct with PID + target
// VA + length + caller's user-mode buffer pointer. The driver does the
// usual probe-and-copy dance against that buffer, so we don't need to
// pre-allocate kernel memory sized to the read.
//
// METHOD_BUFFERED for the input struct (small, fixed-size), but the
// output is the user-mode buffer the caller passes via the struct's
// DstUserVa field. We deliberately don't use the IRP's output buffer
// for that - METHOD_BUFFERED would force the I/O manager to allocate
// kernel-side scratch the same size as the read, which is wasteful for
// multi-megabyte dumps. METHOD_NEITHER on the output side, hand-rolled
// probe.
// =============================================================================

#pragma once

// L"\\Device\\..." in kernel becomes \\.\... in user-mode.
#define ENIDRV_NT_DEVICE_NAME       L"\\Device\\EniDrv"
#define ENIDRV_DOS_DEVICE_NAME      L"\\DosDevices\\EniDrv"
#define ENIDRV_USER_DEVICE_PATH     L"\\\\.\\EniDrv"

// CTL_CODE expansion done by hand so this header has no dependency on
// <winioctl.h> from user-mode or <wdm.h> from kernel-mode beyond the
// two #defines below.
//
//   FILE_DEVICE_UNKNOWN = 0x22, custom range 0x800+
//   METHOD_BUFFERED     = 0    (input only - we tolerate buffered input)
//   FILE_ANY_ACCESS     = 0
//
// IOCTL = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
//       = (0x22 << 16) | 0 | (0x800 << 2) | 0
//       = 0x222000
#define IOCTL_ENI_READ_VM           0x00222000

// Sent to the driver as the IRP's input buffer. The driver validates
// every field before doing anything with it.
typedef struct _ENI_READ_VM_REQUEST {
    unsigned long      Pid;            // target process ID
    unsigned long long SrcVa;           // VA in target's address space
    unsigned long long DstUserVa;       // VA in OUR (caller's) address space
    unsigned long long Size;            // bytes to read
    unsigned long long BytesRead;       // out: filled by driver before completion
} ENI_READ_VM_REQUEST;
