// =============================================================================
// ENILoader - main.cpp
// =============================================================================
//
// The injector EXE. For point 1 of the production rebuild, this is intentionally
// minimal: command-line driven, attaches to a running RobloxPlayerBeta.exe,
// reads payload.bin from disk next to the exe, and runs the manual mapper.
//
// Future passes will replace:
//   * "find existing process" with "spawn process suspended and inject pre-Hyperion"
//   * "read payload.bin from disk" with "decrypt embedded resource"
//   * the bare-metal printf logging with structured logs that don't ship "ENI" strings
//   * the CLI with an actual loader UI (or kept headless if we go full automatic)
//
// CLI:
//   ENILoader.exe                       attach to running Roblox, payload.bin
//   ENILoader.exe --payload custom.dll  use a different payload path
//   ENILoader.exe --pid 12345           target a specific PID
//   ENILoader.exe --verbose             print phase timings
//   ENILoader.exe --keep-headers        don't erase PE headers post-map (debug)
// =============================================================================

#include <cstddef>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

#include "ManualMapper.h"
#include "../../shared/BootInfo.h"
#include "../../shared/PayloadCrypt.h"

namespace {

struct CliArgs {
    std::wstring PayloadPath = L"payload.bin";
    DWORD ExplicitPid = 0;
    bool Verbose = false;
    bool KeepHeaders = false;
    bool ShowHelp = false;
};

void PrintHelp() {
    std::cout <<
        "ENILoader - manual-mapping injector\n"
        "\n"
        "Usage: ENILoader.exe [options]\n"
        "\n"
        "Options:\n"
        "  --payload <path>     Payload DLL path (default: payload.bin)\n"
        "  --pid <number>       Inject into a specific PID instead of searching\n"
        "  --verbose            Print phase timings on success\n"
        "  --keep-headers       Don't erase PE headers after mapping (for debugging)\n"
        "  --help               Show this help\n";
}

CliArgs ParseArgs(int argc, wchar_t** argv) {
    CliArgs out;
    for (int i = 1; i < argc; i++) {
        const std::wstring_view a = argv[i];
        if (a == L"--help" || a == L"-h") {
            out.ShowHelp = true;
        } else if (a == L"--payload" && i + 1 < argc) {
            out.PayloadPath = argv[++i];
        } else if (a == L"--pid" && i + 1 < argc) {
            out.ExplicitPid = std::wcstoul(argv[++i], nullptr, 10);
        } else if (a == L"--verbose" || a == L"-v") {
            out.Verbose = true;
        } else if (a == L"--keep-headers") {
            out.KeepHeaders = true;
        } else {
            std::wcerr << L"Unknown argument: " << a << L"\n";
            out.ShowHelp = true;
        }
    }
    return out;
}

DWORD FindRobloxPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, L"RobloxPlayerBeta.exe") == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(snap);
    return pid;
}

std::vector<std::uint8_t> ReadAllBytes(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    const std::streamsize size = file.tellg();
    if (size <= 0) return {};
    file.seekg(0);

    std::vector<std::uint8_t> buf(static_cast<std::size_t>(size));
    file.read(reinterpret_cast<char*>(buf.data()), size);
    if (!file) return {};
    return buf;
}

std::wstring GetAppDataEniDir() {
    wchar_t* base = nullptr;
    std::size_t len = 0;
    if (_wdupenv_s(&base, &len, L"APPDATA") != 0 || !base) {
        return L"";
    }
    std::wstring out = base;
    free(base);
    out += L"\\ENI";
    CreateDirectoryW(out.c_str(), nullptr); // ignore failure (may exist)
    return out;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    const CliArgs args = ParseArgs(argc, argv);
    if (args.ShowHelp) {
        PrintHelp();
        return 0;
    }

    // Resolve target PID.
    DWORD pid = args.ExplicitPid ? args.ExplicitPid : FindRobloxPid();
    if (!pid) {
        std::cerr << "Roblox not running (and no --pid given). Launch Roblox and try again.\n";
        return 1;
    }
    std::wcout << L"[+] Target PID: " << pid << L"\n";

    // Open with the minimum rights the mapper needs.
    HANDLE process = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!process) {
        std::cerr << "OpenProcess failed: " << GetLastError() << "\n";
        return 2;
    }

    // Load payload. Two paths because we accept both:
    //
    //   * payload.bin (encrypted blob produced by tools/encrypt_payload.py)
    //     - the production build artifact, magic-prefixed and ChaCha20'd
    //   * a raw DLL path (--payload custom.dll) - for one-off dev work
    //     where you want to inject something that wasn't run through the
    //     build's encryption step
    //
    // We sniff the magic prefix to decide which one we got. Decryption
    // failure on a magic-bearing file is fatal (mismatched key); a file
    // with no magic falls through to "treat as plaintext PE" which the
    // mapper will validate or reject on its own.
    auto raw = ReadAllBytes(args.PayloadPath);
    if (raw.empty()) {
        std::wcerr << L"Failed to read payload: " << args.PayloadPath << L"\n";
        CloseHandle(process);
        return 3;
    }

    std::vector<std::uint8_t> payload;
    if (raw.size() >= ENI::Crypt::HeaderBytes) {
        std::uint32_t magic = 0;
        std::memcpy(&magic, raw.data(), sizeof(magic));
        if (magic == ENI::Crypt::PayloadMagic) {
            const std::size_t cap = raw.size() - ENI::Crypt::HeaderBytes;
            payload.assign(cap, 0);
            std::size_t outSize = 0;
            if (!ENI::Crypt::TryDecryptPayload(raw.data(), raw.size(),
                                               payload.data(), cap, &outSize)) {
                std::wcerr << L"Payload decryption failed - mismatched key?\n";
                CloseHandle(process);
                return 3;
            }
            payload.resize(outSize);
            std::wcout << L"[+] Payload decrypted: "
                       << raw.size() << L" -> " << payload.size() << L" bytes\n";
        }
    }
    if (payload.empty()) {
        // Either the file lacked the magic header (raw DLL path) or it
        // was too small to even contain a header. Hand it to the mapper
        // verbatim and let PE validation decide if it's usable.
        payload = std::move(raw);
        std::wcout << L"[+] Payload size: " << payload.size()
                   << L" bytes (treating as plaintext)\n";
    }

    // Build mapper options.
    ENI::Injector::MapOptions opts{};
    opts.EraseHeaders = !args.KeepHeaders;
    opts.UnlinkFromPeb = true;
    opts.UseRemoteThread = true;
    opts.BootTimeoutMs = 30000;

    const std::wstring eniRoot = GetAppDataEniDir();
    if (!eniRoot.empty()) {
        opts.ConfigDir  = eniRoot + L"\\config";
        opts.ScriptsDir = eniRoot + L"\\scripts";
        opts.LogsDir    = eniRoot + L"\\logs";
        for (const auto& d : { opts.ConfigDir, opts.ScriptsDir, opts.LogsDir }) {
            CreateDirectoryW(d.c_str(), nullptr);
        }
    }

    // TODO: signature pass - resolve LuaState, luau_load, etc., fill
    // opts.Addresses. For now we leave them all zero; the payload is
    // expected to handle null addresses by falling back to its own
    // pattern scan (slower, but works).

    // Map.
    ENI::Injector::ManualMapper mapper(process, opts);
    auto result = mapper.Map(payload);

    if (result.Status != ENI::Injector::MapStatus::Ok) {
        std::cerr << "[-] Map failed: "
                  << ENI::Injector::MapStatusToString(result.Status) << "\n";
        if (result.PayloadReturnCode) {
            std::cerr << "    Payload return code: 0x"
                      << std::hex << result.PayloadReturnCode << std::dec << "\n";
        }
        CloseHandle(process);
        return 4;
    }

    std::cout << "[+] Mapped at 0x" << std::hex << result.RemoteImageBase
              << " (size " << std::dec << result.RemoteImageSize << ")\n";
    std::cout << "[+] BootInfo at 0x" << std::hex << result.RemoteBootInfo << std::dec << "\n";
    std::cout << "[+] BootEntry at 0x" << std::hex << result.RemoteEntryPoint << std::dec << "\n";

    if (args.Verbose) {
        const char* names[] = {
            "Validate", "Allocate", "CopySections", "Relocations",
            "Imports",  "TLS",      "Protections",  "BootEntry",
        };
        std::cout << "[+] Phase timings:\n";
        for (int i = 0; i < 8; i++) {
            std::cout << "    " << names[i] << ": " << result.TimingsUs[i] << " us\n";
        }
    }

    CloseHandle(process);
    return 0;
}
