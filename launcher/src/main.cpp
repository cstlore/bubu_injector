// =============================================================================
// ENILauncher - main.cpp
// =============================================================================
//
// User-facing entry point. The whole experience boils down to:
//
//   1. User runs ENILauncher.exe.
//   2. We find RobloxPlayerLauncher.exe (registry first, then well-known paths).
//   3. We CreateProcess on it with CREATE_SUSPENDED.
//   4. We manual-map ENILauncherShim.dll into the suspended launcher.
//   5. We hand the shim a ShimEnvelope describing where the payload lives,
//      what %APPDATA% paths to use, and which boot flags to pass through.
//   6. We resume the launcher's main thread.
//   7. The launcher does its normal "fetch ticket / spawn Roblox" dance.
//      When it calls CreateProcessW for RobloxPlayerBeta.exe, our shim's
//      detour runs - it suspends the spawn, manual-maps the payload, and
//      resumes Roblox with our code already in place.
//   8. Our launcher process exits as soon as step 6 completes. It does NOT
//      stick around - the shim handles the rest from inside the launcher.
//
// CLI:
//   ENILauncher.exe                                use sensible defaults
//   ENILauncher.exe --payload C:\path\to\dll       override payload path
//   ENILauncher.exe --launcher C:\path\to\rbx.exe  explicit launcher path
//   ENILauncher.exe --shim C:\path\to\shim.dll     explicit shim path
//   ENILauncher.exe --verbose                      enable shim logging
//   ENILauncher.exe --log C:\path\log.txt          override log file
//   ENILauncher.exe --dry-run                      install the hook, do not inject
//   ENILauncher.exe --stay-resident                shim doesn't self-uninstall
//   ENILauncher.exe --help
//
// We don't have a GUI yet. Headless EXE + tray-app shell will come later.
// =============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>
#include <shlobj.h>

#include "ShimMapper.h"
#include "../../shared/BootInfo.h"
#include "../../shared/ShimContract.h"

namespace {

// -- Utilities ------------------------------------------------------------

// Resolve %APPDATA%\ENI; create if missing. Returns empty on failure.
std::wstring AppDataEniDir() {
    wchar_t appdata[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
        return {};
    }
    std::wstring dir = appdata;
    dir += L"\\ENI";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

bool FileExists(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

std::vector<std::uint8_t> ReadAllBytes(const std::wstring& path) {
    std::vector<std::uint8_t> out;
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return out;
    const std::streamsize size = f.tellg();
    if (size <= 0) return out;
    f.seekg(0);
    out.resize(static_cast<std::size_t>(size));
    if (!f.read(reinterpret_cast<char*>(out.data()), size)) out.clear();
    return out;
}

// Path of the running ENILauncher.exe's directory.
std::wstring ExecutableDir() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0) return {};
    std::wstring path = buf;
    auto pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"" : path.substr(0, pos);
}

// -- Roblox launcher discovery -------------------------------------------
//
// Strategies, in order:
//   1. Registry: HKCU\Software\Roblox\RobloxStudioBrowser\roblox-player or
//      HKCR\roblox-player\shell\open\command (MUI: "C:\...\RobloxPlayerLauncher.exe" "%1").
//   2. Well-known install dirs: %LOCALAPPDATA%\Roblox\Versions\<latest>\
//      RobloxPlayerLauncher.exe.
//
// We bias toward registry because the well-known path lookup requires us to
// pick the "latest" version directory, which is brittle - the launcher
// updates Roblox versions itself, but it remains addressable through the
// registered protocol handler that *just works*.

std::wstring FindFromProtocolHandler() {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"roblox-player\\shell\\open\\command",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return {};
    }

    wchar_t buf[2048] = {};
    DWORD type = 0;
    DWORD size = sizeof(buf);
    if (RegQueryValueExW(hKey, nullptr, nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf), &size) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(hKey);
        return {};
    }
    RegCloseKey(hKey);

    // The value looks like:  "C:\Users\...\RobloxPlayerLauncher.exe" "%1"
    // Extract the first quoted token.
    std::wstring s = buf;
    if (s.empty()) return {};
    if (s.front() == L'"') {
        const auto end = s.find(L'"', 1);
        if (end == std::wstring::npos) return {};
        return s.substr(1, end - 1);
    }
    // Unquoted - take up to first whitespace.
    const auto space = s.find_first_of(L" \t");
    return s.substr(0, space);
}

std::wstring FindFromVersionsDir() {
    wchar_t local[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local))) {
        return {};
    }
    std::wstring versions = local;
    versions += L"\\Roblox\\Versions";

    WIN32_FIND_DATAW fd{};
    HANDLE find = FindFirstFileW((versions + L"\\version-*").c_str(), &fd);
    if (find == INVALID_HANDLE_VALUE) return {};

    // Pick whichever version dir contains RobloxPlayerLauncher.exe. There
    // are usually two (one per channel) - first one wins, and they're
    // interchangeable for our purposes since both are signed by Roblox.
    std::wstring chosen;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        std::wstring candidate = versions + L"\\" + fd.cFileName + L"\\RobloxPlayerLauncher.exe";
        if (FileExists(candidate)) {
            chosen = candidate;
            break;
        }
    } while (FindNextFileW(find, &fd));
    FindClose(find);
    return chosen;
}

std::wstring FindRobloxPlayerLauncher() {
    auto p = FindFromProtocolHandler();
    if (FileExists(p)) return p;

    p = FindFromVersionsDir();
    if (FileExists(p)) return p;

    return {};
}

// -- CLI -----------------------------------------------------------------

struct CliArgs {
    std::wstring LauncherPath;
    std::wstring ShimPath;
    std::wstring PayloadPath;
    std::wstring LogFile;
    std::wstring ConfigDir;
    std::wstring ScriptsDir;
    std::wstring LogsDir;
    bool Verbose = false;
    bool DryRun = false;
    bool StayResident = false;
    bool ShowHelp = false;
};

void PrintHelp() {
    std::wcout <<
        L"ENILauncher - launcher-hijack injector for Roblox\n"
        L"\n"
        L"Usage: ENILauncher.exe [options]\n"
        L"\n"
        L"Options:\n"
        L"  --launcher <path>   Path to RobloxPlayerLauncher.exe (auto-detected by default)\n"
        L"  --shim <path>       Path to ENILauncherShim.dll (default: alongside this EXE)\n"
        L"  --payload <path>    Path to payload DLL (default: alongside this EXE as payload.bin)\n"
        L"  --log <path>        Log file path (default: %APPDATA%\\ENI\\launcher.log)\n"
        L"  --verbose           Enable verbose logging in both launcher and shim\n"
        L"  --dry-run           Install hook but skip payload injection (test the chain)\n"
        L"  --stay-resident     Don't self-uninstall the shim after first inject\n"
        L"  --help              Show this help\n";
}

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs out;
    for (int i = 1; i < argc; i++) {
        const std::wstring_view a = argv[i];
        auto next = [&]() -> std::wstring {
            if (i + 1 >= argc) {
                std::wcerr << L"Missing value for " << a << L"\n";
                out.ShowHelp = true;
                return {};
            }
            return argv[++i];
        };

        if (a == L"--help" || a == L"-h")               out.ShowHelp = true;
        else if (a == L"--launcher")                    out.LauncherPath = next();
        else if (a == L"--shim")                        out.ShimPath = next();
        else if (a == L"--payload")                     out.PayloadPath = next();
        else if (a == L"--log")                         out.LogFile = next();
        else if (a == L"--verbose" || a == L"-v")       out.Verbose = true;
        else if (a == L"--dry-run")                     out.DryRun = true;
        else if (a == L"--stay-resident")               out.StayResident = true;
        else {
            std::wcerr << L"Unknown argument: " << a << L"\n";
            out.ShowHelp = true;
        }
    }
    return out;
}

// -- Envelope construction -----------------------------------------------

void CopyToFixedPath(wchar_t (&dst)[ENI::Shim::MaxPathChars], const std::wstring& src) {
    const std::size_t n = std::min<std::size_t>(src.size(), ENI::Shim::MaxPathChars - 1);
    std::wmemcpy(dst, src.data(), n);
    dst[n] = L'\0';
}

ENI::Shim::ShimEnvelope BuildEnvelope(const CliArgs& cli,
                                      const std::wstring& payload,
                                      const std::wstring& log,
                                      const std::wstring& configDir,
                                      const std::wstring& scriptsDir,
                                      const std::wstring& logsDir)
{
    // Only pull in the Shim namespace - Boot has its own Magic / ProtocolVersion
    // that would shadow Shim's and produce ambiguous-symbol errors. We name the
    // few Boot symbols we need explicitly below.
    using namespace ENI::Shim;

    ShimEnvelope env{};
    env.Magic = Magic;
    env.Version = ProtocolVersion;
    env.StructSize = sizeof(ShimEnvelope);

    env.Flags = ShimFlags::None;
    if (cli.Verbose)        env.Flags |= ShimFlags::Verbose;
    if (cli.DryRun)         env.Flags |= ShimFlags::DryRun;
    if (cli.StayResident)   env.Flags |= ShimFlags::StayResident;

    CopyToFixedPath(env.PayloadPath, payload);
    CopyToFixedPath(env.LogFile,     log);
    CopyToFixedPath(env.ConfigDir,   configDir);
    CopyToFixedPath(env.ScriptsDir,  scriptsDir);
    CopyToFixedPath(env.LogsDir,     logsDir);

    // Boot flags forwarded into the payload's BootInfo. PreHyperion is
    // accurate by definition - we run before Roblox loads any Hyperion DLL.
    env.BootFlags = ENI::Boot::BootFlags::PreHyperion;
    if (cli.Verbose) env.BootFlags |= ENI::Boot::BootFlags::DebugLoader;

    env.BootTimeoutMs   = 30000;
    env.EraseHeaders    = 1;
    env.UnlinkFromPeb   = 1;
    env.UseRemoteThread = 1;
    env.Reserved0       = 0;

    // Pre-resolved Roblox addresses: we don't have them yet. Hyperion-aware
    // version detection is a separate work item. Until we add that, the
    // payload's own scanner does the resolution post-load.
    env.Addresses = ENI::Boot::ResolvedAddresses{};

    return env;
}

// -- Main pipeline -------------------------------------------------------

int LauncherMain(const CliArgs& cli) {
    const std::wstring exeDir = ExecutableDir();
    const std::wstring eniDir = AppDataEniDir();

    // -- Resolve paths ---------------------------------------------------
    std::wstring launcherPath = cli.LauncherPath;
    if (launcherPath.empty()) launcherPath = FindRobloxPlayerLauncher();
    if (!FileExists(launcherPath)) {
        std::wcerr << L"[launcher] Could not find RobloxPlayerLauncher.exe."
                      L" Pass --launcher <path>.\n";
        return 2;
    }

    std::wstring shimPath = cli.ShimPath;
    if (shimPath.empty()) shimPath = exeDir + L"\\ENILauncherShim.dll";
    if (!FileExists(shimPath)) {
        std::wcerr << L"[launcher] Shim DLL not found at: " << shimPath << L"\n";
        return 3;
    }

    std::wstring payloadPath = cli.PayloadPath;
    if (payloadPath.empty()) payloadPath = exeDir + L"\\payload.bin";
    if (!FileExists(payloadPath)) {
        std::wcerr << L"[launcher] Payload DLL not found at: " << payloadPath << L"\n";
        return 4;
    }

    std::wstring logPath = cli.LogFile;
    if (logPath.empty() && cli.Verbose && !eniDir.empty()) {
        logPath = eniDir + L"\\launcher.log";
    }

    const std::wstring configDir  = cli.ConfigDir.empty()  ? eniDir + L"\\config"  : cli.ConfigDir;
    const std::wstring scriptsDir = cli.ScriptsDir.empty() ? eniDir + L"\\scripts" : cli.ScriptsDir;
    const std::wstring logsDir    = cli.LogsDir.empty()    ? eniDir + L"\\logs"    : cli.LogsDir;
    CreateDirectoryW(configDir.c_str(),  nullptr);
    CreateDirectoryW(scriptsDir.c_str(), nullptr);
    CreateDirectoryW(logsDir.c_str(),    nullptr);

    if (cli.Verbose) {
        std::wcout << L"[launcher] launcher = " << launcherPath << L"\n";
        std::wcout << L"[launcher] shim     = " << shimPath << L"\n";
        std::wcout << L"[launcher] payload  = " << payloadPath << L"\n";
        std::wcout << L"[launcher] log      = " << logPath << L"\n";
    }

    // -- Read shim bytes -------------------------------------------------
    auto shimBytes = ReadAllBytes(shimPath);
    if (shimBytes.empty()) {
        std::wcerr << L"[launcher] Failed to read shim DLL.\n";
        return 5;
    }

    // -- Build the ShimEnvelope ------------------------------------------
    const auto envelope = BuildEnvelope(cli, payloadPath, logPath,
                                        configDir, scriptsDir, logsDir);

    // -- Spawn RobloxPlayerLauncher.exe suspended ------------------------
    //
    // We pass through any extra command-line args from our own caller so
    // that `roblox-player://` deep links still flow correctly when the
    // user invokes us via the protocol handler (a future change). For
    // the headless CLI build, no extra args - the user does the auth via
    // the launcher's normal flow.

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    // CreateProcessW wants a writable command line buffer.
    std::wstring cmdLine = L"\"" + launcherPath + L"\"";
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    if (!CreateProcessW(
            launcherPath.c_str(),
            cmdBuf.data(),
            nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            nullptr, nullptr,
            &si, &pi)) {
        std::wcerr << L"[launcher] CreateProcessW failed: " << GetLastError() << L"\n";
        return 6;
    }

    if (cli.Verbose) {
        std::wcout << L"[launcher] Spawned launcher PID " << pi.dwProcessId
                   << L" suspended.\n";
    }

    // -- Manual-map the shim into the suspended launcher -----------------
    auto result = ENI::Launcher::MapShimAndInvoke(
        pi.hProcess, std::span<const std::uint8_t>(shimBytes), envelope);

    if (result.Status != ENI::Launcher::ShimMapStatus::Ok) {
        std::wcerr << L"[launcher] Shim mapping failed: "
                   << ENI::Launcher::ShimMapStatusToString(result.Status)
                   << L" (shim returned 0x"
                   << std::hex << result.ShimReturnCode << std::dec << L")\n";

        // Kill the suspended launcher rather than leaving it dangling. The
        // user got a clear failure; cleaner that it doesn't run un-injected.
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 7;
    }

    if (cli.Verbose) {
        std::wcout << L"[launcher] Shim installed at 0x"
                   << std::hex << result.RemoteImageBase << std::dec
                   << L". Resuming launcher main thread.\n";
    }

    // -- Resume the launcher --------------------------------------------
    //
    // From here on the launcher does its own thing. Our shim, now living
    // inside it, will intercept the eventual CreateProcessW call for
    // RobloxPlayerBeta.exe and inject the payload there.
    if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
        std::wcerr << L"[launcher] ResumeThread failed: " << GetLastError() << L"\n";
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 8;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (cli.Verbose) {
        std::wcout << L"[launcher] Done. Launcher running with shim resident.\n";
    }
    return 0;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    auto cli = ParseArgs(argc, argv);
    if (cli.ShowHelp) {
        PrintHelp();
        return 0;
    }
    return LauncherMain(cli);
}
