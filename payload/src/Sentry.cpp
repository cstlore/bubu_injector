// =============================================================================
// Sentry.cpp - boot-time arming sequence + every detour we install
// =============================================================================
//
// One file because the detours and the install loop are tightly coupled -
// the detour signatures, the trampoline pointers, and the install order
// all want to live next to each other.
//
// The detours each have a corresponding `g_Original_*` trampoline pointer
// that gets filled by HookEngine::Install. After install, calling the
// trampoline reaches the un-detoured original. We use these for the
// "I don't care about this case, defer to ntdll" branches inside each
// detour.
// =============================================================================

#include "Hyperion/Sentry.h"
#include "Hyperion/NtApi.h"
#include "Hyperion/HookEngine.h"
#include "Hyperion/PayloadRegion.h"
#include "Hyperion/Log.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <windows.h>
#include <winternl.h>

// Linker-provided base address of our own image. We use this rather
// than reading our own PE headers because the loader may have erased
// them (BootFlags::HeadersErased).
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace ENI::Hyperion::Sentry {

namespace {

// -----------------------------------------------------------------------------
// NTSTATUS values we use without pulling in <ntstatus.h> (which conflicts
// with parts of <windows.h> in some toolchains).
// -----------------------------------------------------------------------------
constexpr LONG kNtSuccess         = 0x00000000L;
constexpr LONG kNtPortNotSet      = 0xC0000353L;
constexpr LONG kNtInvalidAddress  = 0xC0000141L;

// -----------------------------------------------------------------------------
// Information classes we filter on. These constants live in <winternl.h>
// only partially - the full set is in the WDK. We define the ones we use.
// -----------------------------------------------------------------------------
constexpr ULONG kProcessDebugPort                = 7;
constexpr ULONG kProcessDebugObjectHandle        = 30;
constexpr ULONG kProcessDebugFlags               = 31;
constexpr ULONG kProcessInstrumentationCallback  = 0x28;
constexpr ULONG kProcessSignaturePolicy          = 0x32;
constexpr ULONG kProcessDynamicCodePolicy        = 0x42;
constexpr ULONG kProcessExtendedFeaturesPolicy   = 0x49;

constexpr ULONG kThreadHideFromDebugger          = 17;

constexpr ULONG kMemoryBasicInformation          = 0;
constexpr ULONG kMemoryMappedFilenameInformation = 2;
constexpr ULONG kMemoryRegionInformation         = 3;

// -----------------------------------------------------------------------------
// Detour signatures.
// -----------------------------------------------------------------------------

using PFN_NtSetInformationProcess = NTSTATUS (NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG);

using PFN_NtQueryInformationProcess = NTSTATUS (NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

using PFN_NtQueryVirtualMemory = NTSTATUS (NTAPI*)(
    HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

using PFN_NtSetInformationThread = NTSTATUS (NTAPI*)(
    HANDLE, ULONG, PVOID, ULONG);

using PFN_NtClose = NTSTATUS (NTAPI*)(HANDLE);

using PFN_NtProtectVirtualMemory = NTSTATUS (NTAPI*)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

// -----------------------------------------------------------------------------
// Trampolines, populated by HookEngine::Install.
// -----------------------------------------------------------------------------

PFN_NtSetInformationProcess   g_Original_NtSetInformationProcess   = nullptr;
PFN_NtQueryInformationProcess g_Original_NtQueryInformationProcess = nullptr;
PFN_NtQueryVirtualMemory      g_Original_NtQueryVirtualMemory      = nullptr;
PFN_NtSetInformationThread    g_Original_NtSetInformationThread    = nullptr;
PFN_NtClose                   g_Original_NtClose                   = nullptr;
PFN_NtProtectVirtualMemory    g_Original_NtProtectVirtualMemory    = nullptr;

// Pseudo-handle for "current process" - GetCurrentProcess() returns
// (HANDLE)-1.
inline bool IsCurrentProcessHandle(HANDLE h) {
    return h == GetCurrentProcess() || h == reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1));
}

// -----------------------------------------------------------------------------
// Detour: NtSetInformationProcess
//
// Hyperion's bootstrap calls this with ProcessSignaturePolicy /
// ProcessDynamicCodePolicy / ProcessExtendedFeaturesPolicy to lock the
// process down. We swallow those (return SUCCESS without applying)
// since the policies would prevent any future MinHook trampoline alloc.
//
// Also swallowed: ProcessInstrumentationCallback (0x28). Some Hyperion
// builds register an instrumentation callback to inspect every syscall
// return - if they manage to install one, our hooks become visible. We
// pretend the registration succeeded without actually wiring it up.
//
// Everything else passes through.
// -----------------------------------------------------------------------------

NTSTATUS NTAPI Detour_NtSetInformationProcess(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength)
{
    if (IsCurrentProcessHandle(ProcessHandle)) {
        switch (ProcessInformationClass) {
            case kProcessInstrumentationCallback:
            case kProcessSignaturePolicy:
            case kProcessDynamicCodePolicy:
            case kProcessExtendedFeaturesPolicy:
                Log::Line("[hook] swallowed NtSetInformationProcess class=0x%X len=%u",
                          ProcessInformationClass, ProcessInformationLength);
                return kNtSuccess;
            default:
                break;
        }
    }
    return g_Original_NtSetInformationProcess
         ? g_Original_NtSetInformationProcess(
               ProcessHandle, ProcessInformationClass,
               ProcessInformation, ProcessInformationLength)
         : kNtPortNotSet;
}

// -----------------------------------------------------------------------------
// Detour: NtQueryInformationProcess
//
// Lies about debug-related queries on our own process. Anything else
// passes through unchanged.
// -----------------------------------------------------------------------------

NTSTATUS NTAPI Detour_NtQueryInformationProcess(
    HANDLE  ProcessHandle,
    ULONG   ProcessInformationClass,
    PVOID   ProcessInformation,
    ULONG   ProcessInformationLength,
    PULONG  ReturnLength)
{
    if (IsCurrentProcessHandle(ProcessHandle) && ProcessInformation) {
        switch (ProcessInformationClass) {
            case kProcessDebugPort:
                if (ProcessInformationLength >= sizeof(HANDLE)) {
                    *static_cast<HANDLE*>(ProcessInformation) = nullptr;
                    if (ReturnLength) *ReturnLength = sizeof(HANDLE);
                    return kNtSuccess;
                }
                break;

            case kProcessDebugObjectHandle:
                if (ProcessInformationLength >= sizeof(HANDLE)) {
                    *static_cast<HANDLE*>(ProcessInformation) = nullptr;
                    if (ReturnLength) *ReturnLength = sizeof(HANDLE);
                    return kNtPortNotSet;
                }
                break;

            case kProcessDebugFlags:
                if (ProcessInformationLength >= sizeof(ULONG)) {
                    // Returning 1 here means "debug INHERITANCE is disabled"
                    // == "no debugger attached" in Windows' own convention.
                    *static_cast<ULONG*>(ProcessInformation) = 1;
                    if (ReturnLength) *ReturnLength = sizeof(ULONG);
                    return kNtSuccess;
                }
                break;

            default:
                break;
        }
    }
    return g_Original_NtQueryInformationProcess
         ? g_Original_NtQueryInformationProcess(
               ProcessHandle, ProcessInformationClass,
               ProcessInformation, ProcessInformationLength, ReturnLength)
         : kNtPortNotSet;
}

// -----------------------------------------------------------------------------
// Detour: NtQueryVirtualMemory
//
// If the queried address falls inside one of our payload regions, return
// a fabricated MEMORY_BASIC_INFORMATION that says "MEM_FREE, nothing
// here". This makes our payload invisible to module-walks that scan the
// address space byte-by-byte.
// -----------------------------------------------------------------------------

NTSTATUS NTAPI Detour_NtQueryVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    ULONG   MemoryInformationClass,
    PVOID   MemoryInformation,
    SIZE_T  MemoryInformationLength,
    PSIZE_T ReturnLength)
{
    if (IsCurrentProcessHandle(ProcessHandle) && BaseAddress) {
        const auto addr = reinterpret_cast<std::uintptr_t>(BaseAddress);
        if (const auto* range = PayloadRegion::Find(addr)) {
            switch (MemoryInformationClass) {
                case kMemoryBasicInformation:
                    if (MemoryInformation && MemoryInformationLength >= sizeof(MEMORY_BASIC_INFORMATION)) {
                        auto* mbi = static_cast<MEMORY_BASIC_INFORMATION*>(MemoryInformation);
                        std::memset(mbi, 0, sizeof(*mbi));
                        // Cover the entire registered range from `addr` to its end.
                        // A walker that advances by mbi->RegionSize after seeing
                        // MEM_FREE will land past our last page in a single step,
                        // not 0x1000 bytes in where the next page is still ours.
                        const std::uintptr_t rangeEnd = range->Base + range->Size;
                        const SIZE_T remaining = (rangeEnd > addr)
                            ? static_cast<SIZE_T>(rangeEnd - addr)
                            : static_cast<SIZE_T>(0x1000);
                        mbi->BaseAddress = BaseAddress;
                        mbi->RegionSize  = remaining;
                        mbi->State       = MEM_FREE;
                        mbi->Protect     = PAGE_NOACCESS;
                        if (ReturnLength) *ReturnLength = sizeof(*mbi);
                        return kNtSuccess;
                    }
                    break;

                case kMemoryRegionInformation:
                    // Same idea - return zeros, MEM_FREE-ish.
                    if (MemoryInformation && MemoryInformationLength > 0) {
                        std::memset(MemoryInformation, 0, MemoryInformationLength);
                        if (ReturnLength) *ReturnLength = MemoryInformationLength;
                        return kNtSuccess;
                    }
                    break;

                case kMemoryMappedFilenameInformation:
                    return kNtInvalidAddress;

                default:
                    break;
            }
        }
    }
    return g_Original_NtQueryVirtualMemory
         ? g_Original_NtQueryVirtualMemory(
               ProcessHandle, BaseAddress, MemoryInformationClass,
               MemoryInformation, MemoryInformationLength, ReturnLength)
         : kNtInvalidAddress;
}

// -----------------------------------------------------------------------------
// Detour: NtSetInformationThread
//
// Pass through. We log ThreadHideFromDebugger calls because they're
// useful diagnostics - tells us if Hyperion is starting threads it
// wants hidden, vs if the call is one of ours. Future v2 work can
// expand this into an active filter.
// -----------------------------------------------------------------------------

NTSTATUS NTAPI Detour_NtSetInformationThread(
    HANDLE ThreadHandle,
    ULONG  ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength)
{
    if (ThreadInformationClass == kThreadHideFromDebugger) {
        Log::Line("[hook] NtSetInformationThread(ThreadHideFromDebugger) thread=%p",
                  ThreadHandle);
    }
    return g_Original_NtSetInformationThread
         ? g_Original_NtSetInformationThread(
               ThreadHandle, ThreadInformationClass,
               ThreadInformation, ThreadInformationLength)
         : kNtSuccess;
}

// -----------------------------------------------------------------------------
// Detour: NtClose
//
// Pass-through with logging on suspicious close attempts. v1 doesn't
// actually filter handles - we just want visibility into anything that
// closes a handle pointing into our regions.
// -----------------------------------------------------------------------------

NTSTATUS NTAPI Detour_NtClose(HANDLE Handle) {
    return g_Original_NtClose
         ? g_Original_NtClose(Handle)
         : kNtSuccess;
}

// -----------------------------------------------------------------------------
// Detour: NtProtectVirtualMemory
//
// If a protection change targets one of our registered payload regions,
// swallow it: claim success without applying. This stops a walker from
// flipping our pages NOACCESS (which would crash us on the next hook
// dispatch) and from probing protections to fingerprint manual-mapped
// regions vs. on-disk-backed module pages.
//
// We fill OldProtect with the requested NewProtect so that the common
// "save old, change, restore old" idiom in caller code becomes a clean
// no-op pair instead of restoring a value we never honored.
// -----------------------------------------------------------------------------

NTSTATUS NTAPI Detour_NtProtectVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID*   BaseAddress,
    PSIZE_T  RegionSize,
    ULONG    NewProtect,
    PULONG   OldProtect)
{
    if (IsCurrentProcessHandle(ProcessHandle) && BaseAddress && *BaseAddress) {
        const auto addr = reinterpret_cast<std::uintptr_t>(*BaseAddress);
        if (PayloadRegion::Find(addr)) {
            Log::Line("[hook] swallowed NtProtectVirtualMemory on payload region "
                      "addr=%p new=0x%X", *BaseAddress, NewProtect);
            if (OldProtect) *OldProtect = NewProtect;
            return kNtSuccess;
        }
    }
    return g_Original_NtProtectVirtualMemory
         ? g_Original_NtProtectVirtualMemory(
               ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect)
         : kNtSuccess;
}

// -----------------------------------------------------------------------------
// LdrRegisterDllNotification glue
// -----------------------------------------------------------------------------
//
// LdrRegisterDllNotification isn't in the public SDK headers; we
// declare its signature here.

constexpr ULONG kLdrLoaded   = 1;
constexpr ULONG kLdrUnloaded = 2;

struct LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG           Flags;
    UNICODE_STRING* FullDllName;
    UNICODE_STRING* BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;
};
struct LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG           Flags;
    UNICODE_STRING* FullDllName;
    UNICODE_STRING* BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;
};
union LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA   Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
};
typedef VOID (NTAPI *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    const LDR_DLL_NOTIFICATION_DATA* NotificationData,
    PVOID Context);
typedef NTSTATUS (NTAPI *PFN_LdrRegisterDllNotification)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID *Cookie);

PVOID g_LdrNotifyCookie = nullptr;

VOID NTAPI OnDllNotify(ULONG Reason,
                       const LDR_DLL_NOTIFICATION_DATA* Data,
                       PVOID /*Context*/)
{
    if (!Data) return;
    if (Reason == kLdrLoaded) {
        // Inside loader lock - keep it tight.
        const wchar_t* name = (Data->Loaded.BaseDllName && Data->Loaded.BaseDllName->Buffer)
            ? Data->Loaded.BaseDllName->Buffer : L"<?>";

        char ascii[256] = {};
        if (Data->Loaded.BaseDllName) {
            int n = WideCharToMultiByte(
                CP_UTF8, 0, name,
                Data->Loaded.BaseDllName->Length / sizeof(wchar_t),
                ascii, sizeof(ascii) - 1, nullptr, nullptr);
            if (n > 0) ascii[n] = '\0';
        }
        Log::Line("[ldr] +%-32s base=%p size=0x%X",
                  ascii, Data->Loaded.DllBase, Data->Loaded.SizeOfImage);
    } else if (Reason == kLdrUnloaded) {
        Log::Line("[ldr] -unload base=%p", Data->Unloaded.DllBase);
    }
}

bool RegisterLoadWatcher(std::uintptr_t ntdllBase) {
    if (!ntdllBase) return false;

    auto* fnPtr = reinterpret_cast<PFN_LdrRegisterDllNotification>(
        GetProcAddress(reinterpret_cast<HMODULE>(ntdllBase),
                       "LdrRegisterDllNotification"));
    if (!fnPtr) {
        Log::Line("[ldr] LdrRegisterDllNotification not found");
        return false;
    }

    NTSTATUS s = fnPtr(0, &OnDllNotify, nullptr, &g_LdrNotifyCookie);
    if (s != kNtSuccess) {
        Log::Line("[ldr] LdrRegisterDllNotification returned 0x%X", s);
        return false;
    }
    Log::Line("[ldr] dll-load watcher registered");
    return true;
}

// -----------------------------------------------------------------------------
// Anti-debug primitives
// -----------------------------------------------------------------------------

void ScrubPeb() {
    auto* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
    if (!peb) return;

    // Direct field access - the public PEB struct in winternl.h has
    // BeingDebugged at offset 2.
    peb->BeingDebugged = 0;

    // NtGlobalFlag is at offset 0xBC on x64. winternl.h doesn't expose
    // it; we punch through with a raw byte offset.
    auto* nglobal = reinterpret_cast<ULONG*>(
        reinterpret_cast<std::uint8_t*>(peb) + 0xBC);
    *nglobal &= ~0x70u;     // FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | PARAMS

    Log::Line("[antidebug] PEB->BeingDebugged=0, NtGlobalFlag scrubbed");
}

void ClearOwnDebugRegisters() {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE me = GetCurrentThread();
    if (GetThreadContext(me, &ctx)) {
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0x400;     // canonical "no breakpoints" value
        SetThreadContext(me, &ctx);
        Log::Line("[antidebug] DRs cleared on boot thread");
    }
}

} // namespace

// =============================================================================
// Arm() - the orchestrator
// =============================================================================

ArmResult Arm(std::uintptr_t imageBase, std::size_t imageSize,
              std::uintptr_t bootInfoBase, std::size_t bootInfoSize)
{
    ArmResult r{};

    // -- 1. ntdll ---------------------------------------------------------
    const std::uintptr_t ntdllBase = NtApi::FindNtdllBase();
    if (!ntdllBase) {
        Log::Line("[boot] FATAL: ntdll base not found");
        return r;
    }
    r.NtdllFound = true;
    Log::Line("[boot] ntdll @ %p", reinterpret_cast<void*>(ntdllBase));

    // -- 2. Snapshot stubs -----------------------------------------------
    r.StubsCached = NtApi::CacheAll(ntdllBase);

    // -- 3. MinHook -------------------------------------------------------
    r.MinHookReady = HookEngine::Initialize();
    if (!r.MinHookReady) return r;

    // -- 4. Register our own memory ranges -------------------------------
    if (imageBase && imageSize) {
        if (PayloadRegion::Add(imageBase, imageSize, "payload-image"))
            r.RegionsRegistered++;
    }
    if (bootInfoBase && bootInfoSize) {
        if (PayloadRegion::Add(bootInfoBase, bootInfoSize, "bootinfo"))
            r.RegionsRegistered++;
    }

    // -- 5. Install detours on cached NT functions -----------------------
    auto tryInstall = [&](NtApi::StubId id, void* detour, void** outTramp) {
        void* target = NtApi::Address(id);
        if (!target) return;
        const NtApi::Stub* s = NtApi::Get(id);
        if (HookEngine::Install(target, detour, outTramp,
                                 s ? s->Name : "?")) {
            r.HooksInstalled++;
        }
    };

    tryInstall(NtApi::StubId::NtSetInformationProcess,
               reinterpret_cast<void*>(&Detour_NtSetInformationProcess),
               reinterpret_cast<void**>(&g_Original_NtSetInformationProcess));

    tryInstall(NtApi::StubId::NtQueryInformationProcess,
               reinterpret_cast<void*>(&Detour_NtQueryInformationProcess),
               reinterpret_cast<void**>(&g_Original_NtQueryInformationProcess));

    tryInstall(NtApi::StubId::NtQueryVirtualMemory,
               reinterpret_cast<void*>(&Detour_NtQueryVirtualMemory),
               reinterpret_cast<void**>(&g_Original_NtQueryVirtualMemory));

    tryInstall(NtApi::StubId::NtSetInformationThread,
               reinterpret_cast<void*>(&Detour_NtSetInformationThread),
               reinterpret_cast<void**>(&g_Original_NtSetInformationThread));

    tryInstall(NtApi::StubId::NtClose,
               reinterpret_cast<void*>(&Detour_NtClose),
               reinterpret_cast<void**>(&g_Original_NtClose));

    tryInstall(NtApi::StubId::NtProtectVirtualMemory,
               reinterpret_cast<void*>(&Detour_NtProtectVirtualMemory),
               reinterpret_cast<void**>(&g_Original_NtProtectVirtualMemory));

    // -- 6. Anti-debug ---------------------------------------------------
    ScrubPeb();
    ClearOwnDebugRegisters();

    // -- 7. DLL-load watcher --------------------------------------------
    r.DllNotifyHooked = RegisterLoadWatcher(ntdllBase);

    Log::Line("[boot] arming complete: stubs=%u hooks=%u regions=%u",
              r.StubsCached, r.HooksInstalled, r.RegionsRegistered);
    return r;
}

void Disarm() {
    HookEngine::Shutdown();
}

} // namespace ENI::Hyperion::Sentry
