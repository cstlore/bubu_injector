#pragma once

// =============================================================================
// DriverLoader.h - SCM-based load/unload for a third-party signed driver
// =============================================================================
//
// PPL prevents user-mode injection. Test-signing is detectable via
// NtQuerySystemInformation(SystemCodeIntegrityInformation), and Hyperion
// almost certainly checks for it. The remaining path: load a driver
// somebody else signed, abuse its IOCTL surface to read protected memory.
//
// Concretely: we copy the signed .sys to a temp path, register it as a
// kernel-mode service via SCM, start it, hand back a HANDLE to the
// driver's device object. On teardown we close the handle, stop the
// service, delete the registration, scrub the .sys from disk.
//
// The whole driver-resident window is on the order of seconds. Hyperion
// would have to enumerate kernel modules (NtQuerySystemInformation /
// SystemModuleInformation) inside that window AND match on the driver
// name to detect us. We additionally rename the .sys at copy time so
// any name-based blocklist lookups miss.
// =============================================================================

#include <windows.h>
#include <string>

namespace ENI::Byovd {

struct DriverHandle {
    HANDLE         device      = INVALID_HANDLE_VALUE;
    SC_HANDLE      service     = nullptr;
    SC_HANDLE      scm         = nullptr;
    std::wstring   serviceName;     // e.g. "EniDriverLoader_<rand>"
    std::wstring   tempSysPath;     // path we copied to, to scrub on close
    bool           weStarted   = false;  // false if it was already running
};

// Bring up a vulnerable signed driver. `sourceSysPath` is the on-disk
// signed driver we ship alongside this tool. `deviceName` is the
// \Device\Foo string the driver registers (varies per driver). Returns
// a populated DriverHandle on success; .device == INVALID_HANDLE_VALUE
// on failure with GetLastError() set.
//
// Side effects on success:
//   - A copy of the .sys at %TEMP%\<random>.sys
//   - A service registration under HKLM\System\...\Services\<random>
//   - A running kernel-mode service binding the driver into PsLoadedModuleList
//   - A device handle held by us
DriverHandle LoadDriver(const std::wstring& sourceSysPath,
                        const std::wstring& deviceName);

// Reverse of LoadDriver. Closes the device, stops the service, deletes
// the service registration, scrubs the .sys copy. Idempotent - safe to
// call on a partially-initialized handle.
void UnloadDriver(DriverHandle& h);

} // namespace ENI::Byovd
