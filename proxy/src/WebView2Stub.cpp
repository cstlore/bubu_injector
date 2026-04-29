// =============================================================================
// WebView2Stub.cpp - empty-shell DLL for diagnosing the launch failure
// =============================================================================
//
// Purpose: prove (or disprove) the hypothesis that Roblox/Hyperion is doing
// a pre-launch Authenticode signature check against install-dir DLLs.
//
// This DLL has:
//   - The five WebView2Loader exports, but each one is a no-op returning
//     S_OK (NOT a forwarder, NOT a runtime thunk, NOT calling any real
//     code). No LoadLibrary, no GetProcAddress.
//   - An empty DllMain that returns TRUE immediately. No worker thread.
//   - Same compiler flags as the proxy build: /MT /EHsc /W4.
//   - No imports beyond what the C++ entry stub pulls in (kernel32 only).
//
// If Roblox launches with this in place: the issue isn't a signature
// scan, it's something specific in our proxy's DllMain or thunks.
//
// If Roblox FAILS the same way: signature check confirmed, move on.
//
// We only test as far as launch + login screen. The five exports return
// S_OK with bogus output - any actual WebView2 use (chat, store) will
// crash later, but we don't get there in a smoke test.
// =============================================================================

#include <windows.h>

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE CompareBrowserVersions(LPCWSTR, LPCWSTR, int* result) {
    if (result) *result = 0;
    return S_OK;
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE CreateCoreWebView2Environment(void*) {
    return S_OK;
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE CreateCoreWebView2EnvironmentWithOptions(
    LPCWSTR, LPCWSTR, void*, void*)
{
    return S_OK;
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE GetAvailableCoreWebView2BrowserVersionString(
    LPCWSTR, LPWSTR* versionInfo)
{
    if (versionInfo) *versionInfo = nullptr;
    return S_OK;
}

extern "C" __declspec(dllexport)
HRESULT STDMETHODCALLTYPE GetAvailableCoreWebView2BrowserVersionStringWithOptions(
    LPCWSTR, void*, LPWSTR* versionInfo)
{
    if (versionInfo) *versionInfo = nullptr;
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Intentionally empty - we want the absolute minimum DLL that
        // satisfies the export surface. Anything that runs here adds
        // confounding factors to the diagnostic test.
    }
    return TRUE;
}
