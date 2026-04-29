// =============================================================================
// Stubs.cpp - libHttpClient.GDK.dll fake export bodies
// =============================================================================
//
// Each function listed in src/exports.def has a corresponding body here.
// All bodies return E_NOTIMPL (0x80000001) for HRESULT-shaped APIs, or are
// no-ops for void sinks. Roblox already runs fine when libHttpClient.GDK.dll
// is absent entirely (verified: the file does not exist on this PC and
// Roblox boots normally). That means one of two things is true for every
// import:
//
//   (a) The delay-load helper handles ImportNotFound and Roblox's caller
//       wraps the call in __try / __except or checks the HMODULE for null
//       before dereferencing. In this case our stubs are never invoked.
//
//   (b) Roblox's caller IS invoked, gets back our E_NOTIMPL, and degrades
//       gracefully (the relevant cloud feature is non-functional this
//       session, but the engine continues).
//
// Either way nothing user-visible breaks. We don't try to actually proxy
// to a real implementation - that would require shipping the GDK runtime
// and is far more surface than we need.
//
// The signatures use `void*` placeholders for every parameter. On x64
// Windows ABI, __cdecl/__fastcall collapse to a single convention: first
// four args in RCX/RDX/R8/R9, rest on the stack, caller cleans. Our stub
// simply ignores RCX..R9 and returns a constant in EAX/RAX. There's no
// stack imbalance because we never touched the caller-cleaned spill area.
//
// =============================================================================

#include <cstdint>
#include <windows.h>

namespace {

// Standard COM/WinRT not-implemented sentinel. Surfaces as
// HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) for callers that translate.
constexpr std::uint32_t kHResultNotImpl = 0x80004001; // E_NOTIMPL (corrected)

} // namespace

// -----------------------------------------------------------------------------
// HRESULT-returning functions: return E_NOTIMPL.
// -----------------------------------------------------------------------------

#define STUB_HR(name) \
    extern "C" __declspec(dllexport) std::uint32_t name( \
        void*, void*, void*, void*, void*, void*, void*, void*) \
    { return kHResultNotImpl; }

STUB_HR(HCCleanupAsync)
STUB_HR(HCGetWebSocketConnectResult)
STUB_HR(HCGetWebSocketSendMessageResult)
STUB_HR(HCHttpCallCloseHandle)
STUB_HR(HCHttpCallCreate)
STUB_HR(HCHttpCallDuplicateHandle)
STUB_HR(HCHttpCallGetRequestUrl)
STUB_HR(HCHttpCallPerformAsync)
STUB_HR(HCHttpCallRequestGetHeaderAtIndex)
STUB_HR(HCHttpCallRequestGetNumHeaders)
STUB_HR(HCHttpCallRequestGetRequestBodyBytes)
STUB_HR(HCHttpCallRequestGetRetryAllowed)
STUB_HR(HCHttpCallRequestGetRetryCacheId)
STUB_HR(HCHttpCallRequestGetRetryDelay)
STUB_HR(HCHttpCallRequestGetTimeout)
STUB_HR(HCHttpCallRequestGetTimeoutWindow)
STUB_HR(HCHttpCallRequestGetUrl)
STUB_HR(HCHttpCallRequestSetHeader)
STUB_HR(HCHttpCallRequestSetRequestBodyBytes)
STUB_HR(HCHttpCallRequestSetRequestBodyString)
STUB_HR(HCHttpCallRequestSetRetryAllowed)
STUB_HR(HCHttpCallRequestSetRetryCacheId)
STUB_HR(HCHttpCallRequestSetRetryDelay)
STUB_HR(HCHttpCallRequestSetTimeout)
STUB_HR(HCHttpCallRequestSetTimeoutWindow)
STUB_HR(HCHttpCallRequestSetUrl)
STUB_HR(HCHttpCallResponseGetHeader)
STUB_HR(HCHttpCallResponseGetHeaderAtIndex)
STUB_HR(HCHttpCallResponseGetNetworkErrorCode)
STUB_HR(HCHttpCallResponseGetNumHeaders)
STUB_HR(HCHttpCallResponseGetPlatformNetworkErrorMessage)
STUB_HR(HCHttpCallResponseGetResponseBodyBytes)
STUB_HR(HCHttpCallResponseGetResponseBodyBytesSize)
STUB_HR(HCHttpCallResponseGetResponseString)
STUB_HR(HCHttpCallResponseGetStatusCode)
STUB_HR(HCHttpCallSetTracing)
STUB_HR(HCInitialize)
STUB_HR(HCSettingsGetTraceLevel)
STUB_HR(HCTraceImplMessage)
STUB_HR(HCTraceSetEtwEnabled)
STUB_HR(HCWebSocketCloseHandle)
STUB_HR(HCWebSocketConnectAsync)
STUB_HR(HCWebSocketCreate)
STUB_HR(HCWebSocketDisconnect)
STUB_HR(HCWebSocketSendMessageAsync)
STUB_HR(HCWebSocketSetHeader)

// -----------------------------------------------------------------------------
// No-op forwarder resolver. The WebView2 build provides a real implementation
// in WebView2Forwarders.cpp; the libHttpClient build doesn't need any
// runtime forwarding (its exports are real stubs, not thunks). Keeping a
// stub here lets ProxyEntry.cpp call ENI_ResolveWebView2Forwarders
// unconditionally without conditional compilation - the linker picks
// whichever TU defines it for each target.
// -----------------------------------------------------------------------------

extern "C" void ENI_ResolveWebView2Forwarders(HMODULE) {
    // libHttpClient build: nothing to forward.
}
