# TODO

Tracked work for the ENI injection chain, in dependency order. Tier names
match the production-readiness audit: Tier 1 is everything that has to be
in place before the chain can survive a real Hyperion-armed Roblox boot,
Tier 2 is the script-execution pipeline that turns "we're inside" into
"we can do something", Tier 3 is hardening, Tier 4 is feature surface
ported from the legacy executor.

## In flight

_(empty — #16 sigscan engine, #10 payload encryption, #17 BootInfo
wiring all landed, along with three Tier 3 mapper TODOs: forwarded
exports, TLS callback ABI, failure-path cleanup.)_

## Tier 1 — survive the boot

These are the items that decide whether the payload's first ten seconds
inside Roblox are clean.

### Roblox signature derivation — #18, DEFERRED
Status: pending. Deferred: needs a live x64 Roblox build to derive
against, which can't run on this Parallels-on-Apple-Silicon dev VM.
What: hand-pick byte signatures for the Roblox internals we need —
`luau_load`, `lua_pcall`, `lua_resume`, `getidentity`, `setidentity`,
`TaskScheduler::singleton`, `RBX::ScriptContext::getDataModel`, the
`ScriptContext::getRunningScripts` linked-list head. Bake them into a
header (`payload/include/Hyperion/Signatures.h`) so the payload can
sigscan for them on boot.
Workflow: when there's hardware to derive against, dump the addresses
out of a fresh Roblox client with a debugger, screenshot the surrounding
bytes, encode the wildcards by hand. Update with each Roblox release
(weekly cadence — automate later via a CI job that diffs a fresh Roblox
download against the last known good signatures and flags drift).

### TaskScheduler hook — #20, blocked by #18
Status: pending. Blocked: needs the `TaskScheduler::singleton` signature
from #18.
What: hook into Roblox's TaskScheduler so the payload can post work onto
a Roblox-owned thread. Required because Lua VM operations are not
thread-safe — calling into `lua_pcall` from our boot thread (or any
non-Roblox thread) is a use-after-free waiting to happen. We need a
pump that says "next time the scheduler runs jobs, run mine".
Where: `payload/src/Hyperion/TaskScheduler.cpp`. MinHook detour on a
TaskScheduler dispatch function; when the detour fires, pop our own
queued work first, then chain to the original.
Open question: which dispatch function? Historically people hook
`step()` or the per-frame `update()`. Confirm against a live build
under #18.

### Lua state acquisition + script execution — #14, blocked by #20
Status: pending. Blocked: needs TaskScheduler.
What: walk from the global `DataModel` to a `ScriptContext`, get the
current `lua_State*` (Roblox encodes it through a couple of indirections
to make it harder to grab cold), then `luau_load` + `lua_pcall` user
script bytecode. Set identity to 7 (level required for most exploits)
via the identity field in the Lua state's userdata.
Where: `payload/src/Executor/LuaPipeline.cpp`. API surface that the
script-input channel (#22) calls into:
```cpp
namespace ENI::Executor {
    bool Execute(std::string_view source);   // queues onto TaskScheduler
    int  GetIdentity();
    void SetIdentity(int level);
}
```

### External script-input channel — #22, blocked by #14
Status: pending. Blocked: needs Lua execution to wire to.
What: named pipe at `\\.\pipe\ENI_input` so an external UI / loader can
push script source into the running payload. Single producer, single
consumer, line-delimited UTF-8 with a 4-byte length prefix.
Where: `payload/src/Hyperion/InputPipe.cpp`. Spawned as a worker thread
from the first TaskScheduler hook fire (not from `ENIBootEntry` — see
the warning in `Boot.cpp` about loader-lock dragons).

## Tier 3 — hardening (not yet ticketed)

These aren't in the task list yet because Tier 1 has to land first.
Capturing them here so they don't fall out of context.

- **PEB module-list unlinking from inside the payload.** Mapper does it
  at `MapOptions::UnlinkFromPeb`, but Hyperion's `LdrEnumerateLoadedModules`
  callback can re-walk the list at any time. Sentry currently registers
  a `LdrRegisterDllNotification` to see new loads — also needs to scrub
  any list entry that references our base.
- **Hardware breakpoint persistence.** We clear DR0–DR7 once at boot.
  Hyperion (or its host process) can re-set them. Either re-clear on a
  timer or detour `NtSetContextThread` to filter writes targeting our
  threads.
- **Pre-image-base randomization.** `MapOptions::RandomizeBase` is off.
  Once everything else is stable, flip it on and verify the relocation
  pass handles the higher base ranges Hyperion is more likely to ignore.
- **Thread hijack instead of `CreateRemoteThread`.** `MapOptions::UseRemoteThread`
  is true. The hijack path is sketched in `ManualMapper.h` but not
  implemented. Lower priority — `CreateRemoteThread` works fine and the
  shim's process is one we created suspended anyway, so attribution is
  already weird from Hyperion's perspective.

## Tier 4 — feature surface (legacy port)

The legacy `RobloxExecutor` target carries Lua executor, ImGui menu,
DirectX 11 overlay, ESP, script hub, and config persistence. None of
that compiles under the current toolchain (`Config.h` ImU32, `ScriptEngine.h`
`std::mutex`, `HookManager.h` `MH_HANDLE`, `ImGuiRenderer.h`
`imgui_impl_dx11.h`). Each piece needs to be ported onto the new payload
once Tier 1 + Tier 2 are stable:

- ImGui DX11 overlay — needs the DX11 device hook to land first
- Lua REPL UI — depends on #14 (Lua execution)
- Script hub — drop-in once #22 is wired
- ESP renderer — needs the overlay
- Config persistence — `nlohmann/json` is already linked, low effort
- Hotkey system (F1, Ctrl+S/O/Enter) — needs the overlay

These are deliberately not in the task list yet — they're feature work,
not infra, and feature work without Tier 1 ships a beautiful executor
that gets killed by Hyperion in 800 ms.

## Toolchain reminders

Captured here so they don't get lost:

- **MSYS2 on `PATH` poisons CMake's compiler detection.** Strip with
  `PATH=$(echo "$PATH" | tr ':' '\n' | grep -vi msys64 | tr '\n' ':')`
  before invoking `cmake`. Symptom: link fails with `LNK1104` against
  UNC paths because CMake picks a `cmd.exe` shim from MSYS that can't
  resolve `\\Mac\Home\...`.
- **Use the VS-bundled Ninja.** Path:
  `C:/Program Files/Microsoft Visual Studio/18/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe`.
  System ninja from MSYS works on absolute drive paths but fails on UNC.
- **MSVC 14.50 strict header transitivity.** `<cstdint>` no longer
  brings in `std::size_t`; `<cstring>` no longer brings in `std::wcslen`.
  Add `<cstddef>` and `<cwchar>` explicitly. We've already done this for
  the 12 files that needed it; new files will need the same treatment.
- **`/std:c++latest` ambiguous `using namespace`.** Both `ENI::Shim` and
  `ENI::Boot` define `Magic` and `ProtocolVersion`. Don't pull both in
  via `using namespace`; qualify one of them inline.

## Done (recent)

- #16 — Sigscan engine. IDA-style `"48 8B 05 ?? ?? ?? ?? ..."` pattern
  matcher in `ENI::Hyperion::SigScan`. Anchor-byte memchr skip in the
  hot loop (hits SIMD via the CRT's vectorized memchr, ~400 MB/s on
  recent x64). `Find()` returns first hit; `FindAll()` template walks
  every match for callers that disambiguate by context; `FindInModule()`
  hand-walks PEB->Ldr (same pattern as NtApi.cpp's FindNtdllBase) and
  scans the `.text` section only. All-wildcard patterns reject at compile
  time. CompiledPattern caps at 256 bytes - real IDA sigs top out
  around 30.
- #10 — Payload encryption at rest. ChaCha20 (RFC 7539) with per-build
  key generated by `tools/encrypt_payload.py` into `shared/PayloadKey.h`.
  Format: `magic(4) || nonce(12) || ciphertext`. Wired into the shim's
  pre-mapper read step and the standalone `ENILoader` (which sniffs the
  magic and falls through to plaintext for raw `--payload custom.dll`).
- #17 — `BootInfo.Process.{BaseAddress, ImageSize, FileVersion}` wired.
  Resolved via `NtQueryInformationProcess(ProcessBasicInformation)` ->
  `PEB->ImageBaseAddress` (works on freshly suspended processes where
  `EnumProcessModules` returns nothing because `PEB->Ldr` isn't filled
  yet). `FileVersion` packed as `major<<48 | minor<<32 | build<<16 | rev`.
- Mapper TODOs cleared: forwarded export resolution (chases up to 8
  hops, splits on last `.`, supports api-ms-win-* and classic forms,
  bails on ordinal forwards); TLS callback ABI (now invokes via a
  shellcode trampoline that loads `rcx/rdx/r8` with `(hModule,
  DLL_PROCESS_ATTACH, NULL)`); failure-path cleanup (`RollbackPartialMapping`
  frees image / BootInfo / boot stub on any phase failure).
- #11 — Sentry: VirtualQuery region size cloak (returns full registered
  range size against the legitimate AllocationBase)
- #9  — Sentry: NtProtectVirtualMemory filter (returns STATUS_SUCCESS
  without applying, populates OldProtect for save-restore patterns)
- #13 — Sentry: ProcessInstrumentationCallback (0x28) added to swallow
  list in Detour_NtSetInformationProcess
- #23 — ManualMapper: register .pdata exception directory via
  RtlAddFunctionTable in ENIBootEntry between DiscoverSelfExtent and
  Sentry::Arm
