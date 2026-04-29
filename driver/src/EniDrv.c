// =============================================================================
// EniDrv.c - minimal kernel-mode driver for cross-process VA reads
// =============================================================================
//
// One device, one IOCTL, one job: take {pid, src_va, size, dst_user_va},
// stack-attach to the target process, copy size bytes from src_va to
// dst_user_va under SEH, detach, return bytes-read.
//
// PPL is a user-mode protection: the kernel callback on PspProcessOpen
// filters access masks requested through OpenProcess. PsLookupProcess-
// ByProcessId is the kernel's *internal* lookup - it doesn't go through
// the access-check pipeline. Once we're stack-attached, the target's
// VA space is mapped into our thread's CR3 and ordinary memcpy reads
// it. Hyperion's user-mode protection has no purchase here.
//
// What this driver explicitly does NOT do:
//   - No SSDT hooking, no callback registration, no detours.
//   - No write primitive. Read-only by construction.
//   - No "stealth" tricks. The driver shows up in PsLoadedModuleList
//     under whatever service name the user-mode loader picked. The
//     mitigation against detection is the *time window*, not stealth.
//
// MSVC kernel-mode rules we obey:
//   - C, not C++. /kernel mode forbids most CRT, exceptions, virtual
//     destructors. Plain C is the path of least resistance for ~150
//     lines of glue.
//   - All globals in NonPagedPool. We have one (the device pointer).
//   - IOCTL handler runs at PASSIVE_LEVEL. Safe to call PsLookup*,
//     KeStackAttachProcess, ProbeForWrite. Not safe to call any of
//     them from DPC/dispatch.
// =============================================================================

// ntifs.h is the superset of ntddk.h that exports KeStackAttachProcess,
// KeUnstackDetachProcess, PsLookupProcessByProcessId for WDM drivers.
// ntddk.h alone leaves them undeclared.
#include <ntifs.h>
#include <ntddk.h>

#include "../include/EniDrvShared.h"

// -----------------------------------------------------------------------------
// Forward declarations
// -----------------------------------------------------------------------------

DRIVER_INITIALIZE     DriverEntry;
DRIVER_UNLOAD         EniDrvUnload;
DRIVER_DISPATCH       EniDrvCreateClose;
DRIVER_DISPATCH       EniDrvDeviceControl;

// -----------------------------------------------------------------------------
// Globals (live for the driver's lifetime)
// -----------------------------------------------------------------------------

static PDEVICE_OBJECT g_DeviceObject = NULL;

// -----------------------------------------------------------------------------
// Default trivial dispatch: succeed Create/Close so the user-mode
// CreateFileW handshake completes.
// -----------------------------------------------------------------------------

NTSTATUS
EniDrvCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------------------
// Cross-process read primitive. Bounce-buffer model.
// -----------------------------------------------------------------------------
//
// Critical correctness point: KeStackAttachProcess swaps the calling
// thread's CR3 to the target process's. While attached, only the
// TARGET's user VAs are valid. The CALLER's user VA (where we want to
// deliver the output) lives in a DIFFERENT address space and is not
// reachable while attached. So we can't memcpy directly target -> caller;
// the caller's VA would either resolve to garbage or fault.
//
// Bounce buffer = NonPagedPool kernel allocation, valid in BOTH address
// spaces because kernel VAs are global. Sequence:
//
//   1. ExAllocatePool2(NonPaged, size)               // scratch
//   2. PsLookupProcessByProcessId(pid, &target)      // AddRef target
//   3. KeStackAttachProcess(target, &apc)            // swap CR3
//   4. __try { RtlCopyMemory(scratch, src_va, size)} // target->kernel
//      __except { record exception code }
//   5. KeUnstackDetachProcess(&apc)                  // back to caller CR3
//   6. __try { ProbeForWrite(dst_user_va, size, 1);
//             RtlCopyMemory(dst_user_va, scratch, size) }
//      __except { fail }
//   7. ExFreePoolWithTag(scratch)
//   8. ObDereferenceObject(target)
//
// Any SEH trip in step 4 (PAGE_NOACCESS, guard page, unmapped page)
// surfaces as a non-success NTSTATUS without doing any user-space
// write, so the caller learns about the failure cleanly.
// -----------------------------------------------------------------------------

static NTSTATUS
EniDrvDoReadVmReal(
    _Inout_ ENI_READ_VM_REQUEST* request)
{
    NTSTATUS    status     = STATUS_UNSUCCESSFUL;
    PEPROCESS   targetProc = NULL;
    KAPC_STATE  apcState;
    PVOID       scratch    = NULL;
    SIZE_T      size;

    request->BytesRead = 0;

    if (request->Size == 0 || request->Size > (256ULL * 1024ULL * 1024ULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    size = (SIZE_T)request->Size;

    // Allocate scratch in NonPagedPool. We're at PASSIVE_LEVEL but we
    // don't want this paged out across the attach/detach window.
    scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'vREn');
    if (!scratch) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->Pid,
        &targetProc);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(scratch, 'vREn');
        return status;
    }

    KeStackAttachProcess(targetProc, &apcState);

    __try {
        // memcpy from target VA into our kernel-pool scratch. SEH
        // catches PAGE_NOACCESS / PAGE_GUARD / unmapped pages.
        RtlCopyMemory(scratch,
                      (PVOID)(ULONG_PTR)request->SrcVa,
                      size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    if (NT_SUCCESS(status)) {
        // Now back in the caller's CR3. Copy scratch -> caller's user
        // buffer with the standard probe.
        __try {
            ProbeForWrite(
                (PVOID)(ULONG_PTR)request->DstUserVa,
                size,
                1);
            RtlCopyMemory(
                (PVOID)(ULONG_PTR)request->DstUserVa,
                scratch,
                size);
            request->BytesRead = size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            request->BytesRead = 0;
        }
    }

    ExFreePoolWithTag(scratch, 'vREn');
    ObDereferenceObject(targetProc);
    return status;
}

// -----------------------------------------------------------------------------
// IRP_MJ_DEVICE_CONTROL dispatch
// -----------------------------------------------------------------------------

NTSTATUS
EniDrvDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp)
{
    NTSTATUS              status        = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION    stack         = IoGetCurrentIrpStackLocation(Irp);
    ULONG                 ioctl         = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG                 inLen         = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID                 inBuf         = Irp->AssociatedIrp.SystemBuffer;
    ULONG_PTR             info          = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (ioctl) {
        case IOCTL_ENI_READ_VM:
        {
            if (inLen < sizeof(ENI_READ_VM_REQUEST) || inBuf == NULL) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            ENI_READ_VM_REQUEST* req = (ENI_READ_VM_REQUEST*)inBuf;
            status = EniDrvDoReadVmReal(req);
            // The output buffer is the caller's DstUserVa, which we
            // wrote to directly under ProbeForWrite. We DO want to
            // surface request->BytesRead back through the IRP's input
            // buffer so the user-mode caller can read it post-IOCTL;
            // since input is METHOD_BUFFERED, the I/O manager will
            // copy the SystemBuffer back to the user's input pointer
            // on completion as long as we set Information.
            info = sizeof(ENI_READ_VM_REQUEST);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// -----------------------------------------------------------------------------
// Lifecycle
// -----------------------------------------------------------------------------

VOID
EniDrvUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING dosName;
    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&dosName, ENIDRV_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosName);

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS       status;
    UNICODE_STRING ntName;
    UNICODE_STRING dosName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&ntName,  ENIDRV_NT_DEVICE_NAME);
    RtlInitUnicodeString(&dosName, ENIDRV_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &ntName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&dosName, &ntName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = EniDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = EniDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EniDrvDeviceControl;
    DriverObject->DriverUnload                          = EniDrvUnload;

    // No DO_BUFFERED_IO / DO_DIRECT_IO needed here. The IOCTL method
    // bits (METHOD_BUFFERED in IOCTL_ENI_READ_VM) tell the I/O manager
    // exactly how to marshal the per-request buffers; the device-level
    // flags only affect IRP_MJ_READ / IRP_MJ_WRITE, which we don't
    // implement.

    return STATUS_SUCCESS;
}
