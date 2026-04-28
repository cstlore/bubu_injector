# ENI

A manual-mapping injection chain for Roblox, written in modern C++ against
MSVC 14.50 / `/std:c++latest`. The project is structured as a series of
small, decoupled components that each do one thing and hand off through a
documented binary contract.

The headline trick is that the in-process payload arms a Hyperion-aware
defensive layer (`Sentry`) before any script-execution code runs, so by the
time Roblox's anti-tamper code starts probing memory, our pages already
look like normal RW/RX scenery owned by some unrelated module.

## Components

```
rblx_injector/
├── launcher/      ENILauncher.exe       starts RobloxPlayerLauncher.exe
│                                        and manual-maps the shim into it
├── shim/          ENILauncherShim.dll   lives inside the launcher process,
│                                        hooks CreateProcessW, manual-maps
│                                        the payload into the suspended
│                                        Roblox child before ResumeThread
├── payload/       ENIPayload.dll        in-process payload. Exports
│                                        ENIBootEntry. Arms Sentry, hooks
│                                        Nt* surface, registers .pdata,
│                                        scrubs PEB/DR0-7, lies about its
│                                        own pages on VirtualQuery
├── injector/      ENILoader.exe         standalone manual-mapping loader.
│                                        Useful for attaching to an
│                                        already-running RobloxPlayerBeta
│                                        without going through the launcher
├── shared/        BootInfo.h            wire format passed from mapper
│                                        to payload (magic 0x42494E45)
│                  ShimContract.h        wire format launcher → shim
│                                        (magic 0x53494E45)
├── deps/          MinHook, ImGui, Luau headers, nlohmann/json
├── src/           legacy RobloxExecutor (EXCLUDE_FROM_ALL — being retired
│                  as features port onto the Sentry-armed payload)
└── bin/           output directory for every target
```

The four shipping targets — `ENILauncher.exe`, `ENILauncherShim.dll`,
`ENIPayload.dll`, `ENILoader.exe` — are the new chain. `RobloxExecutor`
is kept in-tree only so its features (Lua executor, ImGui menu, ESP,
script hub) can be ported over to the new payload one piece at a time.
It does not build by default.

## Boot sequence

```
ENILauncher.exe
   └─ CreateProcess RobloxPlayerLauncher.exe (suspended)
   └─ manual-map ENILauncherShim.dll into the launcher
   └─ ENIShimEntry runs
       └─ MinHook on CreateProcessW
       └─ ResumeThread
           ↓ (launcher launches the player)
   CreateProcessW(RobloxPlayerBeta.exe, CREATE_SUSPENDED) hits our hook
       └─ manual-map ENIPayload.dll into the suspended Roblox process
       └─ build BootInfo, drop a boot stub at known RVA
       └─ CreateRemoteThread → boot stub → ENIBootEntry(BootInfo*)
           ├─ validate magic / version / size
           ├─ open hyperion.log under BootInfo->LogsDir
           ├─ DiscoverSelfExtent (VirtualQuery on __ImageBase)
           ├─ RegisterExceptionDirectory  ← .pdata for SEH unwind
           └─ Sentry::Arm(selfBase, selfSize, bootInfoBase, bootInfoSize)
               ├─ snapshot original Nt* stubs
               ├─ install MinHook detours on
               │    NtQueryVirtualMemory, NtProtectVirtualMemory,
               │    NtQueryInformationProcess, NtSetInformationProcess,
               │    NtSetInformationThread, NtClose
               ├─ register payload + BootInfo regions in PayloadRegions
               ├─ scrub PEB->BeingDebugged, PEB->NtGlobalFlag
               ├─ clear DR0–DR7 on the boot thread
               └─ LdrRegisterDllNotification (forward visibility into
                  modules that load after we do)
       └─ ENIBootEntry returns 0
   ResumeThread on the Roblox boot thread
       ↓
   Hyperion initializes, walks memory, asks the kernel about pages and
   threads. Every probe that crosses our cloak comes back clean.
```

## Sentry — what it actually defends against

Hyperion does several things during its init pass that would otherwise
identify us:

- `NtQueryVirtualMemory` on a payload page — would show our private
  commit and the not-image-backed allocation. Sentry's detour returns
  the full registered region size against an `AllocationBase` matching a
  legitimate-looking image, so the page looks contiguous with neighbors.
- `NtProtectVirtualMemory` over a payload page — would let Hyperion
  remove RX, denying execution. Sentry's detour filters payload-region
  writes, returns `STATUS_SUCCESS` without applying, and back-fills
  `OldProtect` so save-restore patterns don't notice.
- `NtSetInformationProcess` with class `0x28`
  (`ProcessInstrumentationCallback`) — Hyperion's modern tamper-detection
  install. Sentry's detour swallows it. Same goes for the older anti-debug
  classes `0x07` (`ProcessDebugPort`), `0x1E` (`ProcessDebugObjectHandle`),
  `0x1F` (`ProcessDebugFlags`).
- `NtSetInformationThread` with `ThreadHideFromDebugger` — passed through
  but logged (some legitimate code uses it; suppressing breaks more than
  it fixes).
- `NtClose` against caller-owned probe handles — Sentry returns success
  without the kernel ever seeing the close, defeating the
  invalid-handle-as-debugger-detector trick.
- `.pdata` registration via `RtlAddFunctionTable` — without this, any
  fault inside our manually-mapped code (or a deliberate probe by
  Hyperion) terminates Roblox because the unwinder can't find a
  `RUNTIME_FUNCTION` covering the faulting RIP.

## Building

### Toolchain

- CMake 3.20 or newer
- Visual Studio 2022 / MSVC 14.50 (`/std:c++latest`)
- Windows 10 SDK
- Ninja (the VS-bundled one at
  `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe`
  works; if MSYS2 is on `PATH`, strip it before invoking CMake or its
  toolchain detection will pick up the wrong `cmd.exe` shim and fail
  link with `LNK1104` on UNC paths)

### Configure + build

From a fresh checkout:

```bash
git clone <repo> rblx_injector
cd rblx_injector

# clone the deps inline
git clone https://github.com/TsudaKageyu/minhook.git deps/MinHook
git clone https://github.com/ocornut/imgui.git          deps/ImGui
git clone https://github.com/Roblox/luau.git            deps/lua
git clone https://github.com/nlohmann/json.git          deps/json

# configure
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl

# build the four shipping targets (the legacy RobloxExecutor is
# EXCLUDE_FROM_ALL, so this skips it cleanly)
cmake --build build
```

Outputs land in `bin/`:

| File                   | Role                              |
|------------------------|-----------------------------------|
| `ENILauncher.exe`      | start of the production chain     |
| `ENILauncherShim.dll`  | manual-mapped into the launcher   |
| `ENIPayload.dll`       | manual-mapped into Roblox itself  |
| `ENILoader.exe`        | standalone attach-to-running tool |

The legacy executor still has a target — invoke it explicitly if you
need to build it:

```bash
cmake --build build --target RobloxExecutor
```

It does not build cleanly under the current toolchain; expect missing
includes for `ImU32`, `std::mutex`, `MH_HANDLE`, `imgui_impl_dx11.h`.
That bitrot is intentional — the target is being retired feature by
feature.

## Running

### Production chain (launcher)

```
.\bin\ENILauncher.exe
```

The launcher takes care of starting the player, mapping the shim, and
the shim takes care of mapping the payload. No flags required for the
default flow.

### Direct attach (standalone loader)

For attaching to an already-running `RobloxPlayerBeta.exe`:

```
.\bin\ENILoader.exe                      # auto-detect Roblox PID, payload.bin
.\bin\ENILoader.exe --pid 12345          # specific PID
.\bin\ENILoader.exe --payload custom.dll # different payload
.\bin\ENILoader.exe --verbose            # print phase timings
.\bin\ENILoader.exe --keep-headers       # keep PE headers (debug)
```

The standalone loader expects the payload bytes at `bin/payload.bin`.
Copy `bin/ENIPayload.dll` over `bin/payload.bin` (or symlink it) before
invoking. In the launcher chain this isn't needed — the shim consumes
the payload from disk relative to its own location.

## Verifying a build

```bash
# confirm the payload exports the expected entry point
dumpbin //exports bin/ENIPayload.dll | grep ENIBootEntry
# →   1    0 0000XXXX ENIBootEntry = @ILT+290(ENIBootEntry)

# sanity-check it has a .pdata directory (required for RtlAddFunctionTable)
dumpbin //headers bin/ENIPayload.dll | grep -A1 EXCEPTION
```

## Logs

The payload writes to `%APPDATA%\ENI\logs\hyperion.log`, opened on first
boot and held open for the lifetime of the host process. Each line is
millisecond-stamped. `FILE_FLAG_WRITE_THROUGH` is on, so a crash mid-line
leaves the bytes on disk. Tail it during dev:

```powershell
Get-Content "$env:APPDATA\ENI\logs\hyperion.log" -Wait -Tail 50
```

Boot-path logs prefix with `[boot]`, Sentry detour decisions with
`[sentry]`, `.pdata` registration with `[pdata]`, NtApi resolver with
`[ntapi]`.

## Wire formats

Two binary contracts cross component boundaries. Both are versioned with
a magic number and an explicit `StructSize`; mismatches abort cleanly
rather than corrupting state.

- **`shared/BootInfo.h`** — mapper → payload. Magic `0x42494E45`
  (`"ENIB"`). Carries process IDs, image base/size, resolved address
  table (`Boot::ResolvedAddresses`), boot flags, and the three working
  paths (`ConfigDir`, `ScriptsDir`, `LogsDir`).
- **`shared/ShimContract.h`** — launcher → shim. Magic `0x53494E45`
  (`"ENIS"`). Carries the path the shim should read the payload from
  and any flags the launcher wants to pass through.

## Status

The injection chain compiles, links, and reaches `ENIBootEntry`. Sentry
arms cleanly against the documented Hyperion surface. What's not yet in
place — see `CLAUDE.md` for the active task list — includes payload
encryption-at-rest, runtime signature derivation against a live x64
Roblox build, the TaskScheduler hook for running on a Roblox-owned
thread, and the Lua-state acquisition pipeline that lets us actually
execute scripts.

## License

Private project. Educational and research purposes.
