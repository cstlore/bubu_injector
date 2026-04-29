// =============================================================================
// WebView2Forwarders.cpp - runtime thunks to WebView2Loader_orig.dll
// =============================================================================
//
// Why not PE forwarders (the /EXPORT:Foo=Other.Foo pragma form):
//
// We tried it. It builds, the export table looks correct in dumpbin, but
// Roblox calls LoadLibraryW("WebView2Loader.dll") and gets ERROR_MOD_NOT_FOUND.
// Reason: the PE forwarder string "WebView2Loader_orig.X" triggers the
// loader's NAME-based search for WebView2Loader_orig.dll AT THE MOMENT
// OF FORWARDER RESOLUTION. That search uses the standard order
// (calling-module-dir, System32, Windows, CWD, PATH). Roblox's install
// directory is NOT on that path for forwarder lookups, even though it
// IS on the search path for the initial LoadLibrary of our DLL.
// Verified empirically: LoadLibraryW("WebView2Loader.dll") from a process
// CWD'd into the install dir fails with err 126 unless the caller adds
// LOAD_WITH_ALTERED_SEARCH_PATH (which Roblox apparently does not).
//
// Manual thunking sidesteps the issue:
//
//   1. In DllMain we resolve our OWN module path via GetModuleFileNameW(hSelf).
//   2. We strip the basename, append "WebView2Loader_orig.dll", and call
//      LoadLibraryW with the ABSOLUTE path. No search-order ambiguity.
//   3. We GetProcAddress each of the five functions, cache them in
//      static function pointers.
//   4. Each export is a tiny C function that tail-calls through the
//      cached pointer. The MSVC optimizer turns this into a single
//      `jmp [rip+disp]` - one indirection, zero stack frame, ABI-clean.
//
// Cost: a one-time LoadLibraryW + 5x GetProcAddress in DllMain (a few
// dozen microseconds). Per-call overhead afterward: one indirect jump,
// indistinguishable from what the PE forwarder would have produced.
//
// IMPORTANT: DllMain runs under the loader lock. LoadLibraryW from
// within DllMain is technically dangerous (re-enters the loader). It's
// safe HERE because:
//   (a) The target DLL has only system-DLL imports (KERNEL32, ADVAPI32,
//       ole32) which are already loaded - no recursion into LoadLibraryW
//       paths beyond the trivial "is this DLL in InMemoryOrderModuleList
//       already, yes return its handle".
//   (b) We do not free anything we load. Any module the loader pulls in
//       transitively stays for the process lifetime, so we never trip
//       a DLL_PROCESS_DETACH chain that could deadlock.
//
// =============================================================================

#include <windows.h>

namespace {

using PFN_CompareBrowserVersions =
    HRESULT (STDMETHODCALLTYPE*)(LPCWSTR, LPCWSTR, int*);

using PFN_CreateCoreWebView2Environment =
    HRESULT (STDMETHODCALLTYPE*)(void* /*ICoreWebView2CreatedHandler*/);

using PFN_CreateCoreWebView2EnvironmentWithOptions =
    HRESULT (STDMETHODCALLTYPE*)(LPCWSTR, LPCWSTR, void*, void*);

using PFN_GetAvailableCoreWebView2BrowserVersionString =
    HRESULT (STDMETHODCALLTYPE*)(LPCWSTR, LPWSTR*);

using PFN_GetAvailableCoreWebView2BrowserVersionStringWithOptions =
    HRESULT (STDMETHODCALLTYPE*)(LPCWSTR, void*, LPWSTR*);

// One pointer per real export. Initialized in DllMain via GetProcAddress.
// Atomic write of a pointer-size value on x64 is intrinsically tear-free,
// so we don't need fences here - by the time Roblox can call any of the
// thunks, DllMain has long since returned.
PFN_CompareBrowserVersions g_pCompareBrowserVersions = nullptr;
PFN_CreateCoreWebView2Environment g_pCreateCoreWebView2Environment = nullptr;
PFN_CreateCoreWebView2EnvironmentWithOptions g_pCreateCoreWebView2EnvironmentWithOptions = nullptr;
PFN_GetAvailableCoreWebView2BrowserVersionString g_pGetAvailableCoreWebView2BrowserVersionString = nullptr;
PFN_GetAvailableCoreWebView2BrowserVersionStringWithOptions g_pGetAvailableCoreWebView2BrowserVersionStringWithOptions = nullptr;

// Standard sentinel for "this implementation is missing". Surfaces as
// HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND) in callers that translate it.
constexpr HRESULT kHResultMissing = static_cast<HRESULT>(0x8007007F);

} // namespace

// -----------------------------------------------------------------------------
// Public entry point invoked by ProxyEntry.cpp's DllMain. We can't put the
// LoadLibrary inside this TU's own DllMain because there are now two TUs
// with potential DllMain attach hooks - having only ProxyEntry.cpp own
// the DllMain keeps initialization order obvious. ProxyEntry.cpp calls
// us directly during DLL_PROCESS_ATTACH, BEFORE it spawns the dump worker.
// -----------------------------------------------------------------------------

extern "C" void ENI_ResolveWebView2Forwarders(HMODULE hSelf) {
    wchar_t selfPath[MAX_PATH];
    DWORD len = GetModuleFileNameW(hSelf, selfPath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return; // Caller will see null pointers and thunks return kHResultMissing.
    }

    // Trim back to the directory by walking off the basename.
    while (len > 0 && selfPath[len - 1] != L'\\' && selfPath[len - 1] != L'/') {
        --len;
    }
    selfPath[len] = L'\0';

    // Append the renamed-original filename. We have MAX_PATH (260) chars
    // total; the install dir is ~80 chars. No overflow risk in practice,
    // but bound the wcscat anyway.
    static const wchar_t kOrigName[] = L"WebView2Loader_orig.dll";
    constexpr size_t kOrigLen = (sizeof(kOrigName) / sizeof(wchar_t)) - 1;
    if (len + kOrigLen + 1 >= MAX_PATH) {
        return;
    }
    for (size_t i = 0; i <= kOrigLen; ++i) {
        selfPath[len + i] = kOrigName[i];
    }

    HMODULE hOrig = LoadLibraryW(selfPath);
    if (!hOrig) {
        return;
    }

    g_pCompareBrowserVersions = reinterpret_cast<PFN_CompareBrowserVersions>(
        GetProcAddress(hOrig, "CompareBrowserVersions"));
    g_pCreateCoreWebView2Environment = reinterpret_cast<PFN_CreateCoreWebView2Environment>(
        GetProcAddress(hOrig, "CreateCoreWebView2Environment"));
    g_pCreateCoreWebView2EnvironmentWithOptions =
        reinterpret_cast<PFN_CreateCoreWebView2EnvironmentWithOptions>(
            GetProcAddress(hOrig, "CreateCoreWebView2EnvironmentWithOptions"));
    g_pGetAvailableCoreWebView2BrowserVersionString =
        reinterpret_cast<PFN_GetAvailableCoreWebView2BrowserVersionString>(
            GetProcAddress(hOrig, "GetAvailableCoreWebView2BrowserVersionString"));
    g_pGetAvailableCoreWebView2BrowserVersionStringWithOptions =
        reinterpret_cast<PFN_GetAvailableCoreWebView2BrowserVersionStringWithOptions>(
            GetProcAddress(hOrig, "GetAvailableCoreWebView2BrowserVersionStringWithOptions"));
    // Intentionally never FreeLibrary(hOrig) - the original stays loaded
    // for the rest of the process lifetime, exactly as it would have been
    // if Roblox had loaded it directly.
}

// -----------------------------------------------------------------------------
// Exported thunks. Each one tail-calls through its cached pointer.
//
// Note we deliberately DON'T use __declspec(noinline) or a forced jmp
// thunk here; the optimizer handles this idiomatically. With /O2 plus
// the `__declspec(dllexport)` linkage, MSVC emits something like:
//
//   CompareBrowserVersions PROC
//       jmp QWORD PTR [rip + g_pCompareBrowserVersions]
//   CompareBrowserVersions ENDP
//
// which is the minimum-overhead trampoline. If the cached pointer is
// null (rare but possible - e.g. WebView2Loader_orig.dll missing from
// disk), we return kHResultMissing rather than dereferencing nullptr.
// -----------------------------------------------------------------------------

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE CompareBrowserVersions(LPCWSTR a, LPCWSTR b, int* result) {
    if (!g_pCompareBrowserVersions) return kHResultMissing;
    return g_pCompareBrowserVersions(a, b, result);
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE CreateCoreWebView2Environment(void* handler) {
    if (!g_pCreateCoreWebView2Environment) return kHResultMissing;
    return g_pCreateCoreWebView2Environment(handler);
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE CreateCoreWebView2EnvironmentWithOptions(
    LPCWSTR browserExecutableFolder,
    LPCWSTR userDataFolder,
    void* environmentOptions,
    void* environmentCreatedHandler)
{
    if (!g_pCreateCoreWebView2EnvironmentWithOptions) return kHResultMissing;
    return g_pCreateCoreWebView2EnvironmentWithOptions(
        browserExecutableFolder, userDataFolder,
        environmentOptions, environmentCreatedHandler);
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE GetAvailableCoreWebView2BrowserVersionString(
    LPCWSTR browserExecutableFolder, LPWSTR* versionInfo)
{
    if (!g_pGetAvailableCoreWebView2BrowserVersionString) return kHResultMissing;
    return g_pGetAvailableCoreWebView2BrowserVersionString(
        browserExecutableFolder, versionInfo);
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE GetAvailableCoreWebView2BrowserVersionStringWithOptions(
    LPCWSTR browserExecutableFolder, void* options, LPWSTR* versionInfo)
{
    if (!g_pGetAvailableCoreWebView2BrowserVersionStringWithOptions) return kHResultMissing;
    return g_pGetAvailableCoreWebView2BrowserVersionStringWithOptions(
        browserExecutableFolder, options, versionInfo);
}
