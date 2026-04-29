# =============================================================================
# ENIProxy - search-order-hijack DLL for PPL-protected Roblox
# =============================================================================
#
# Produces bin/libHttpClient.GDK.dll. The filename is load-bearing: that is
# the exact basename Roblox's RobloxPlayerBeta.exe lists in its delay-load
# import table. Roblox's __delayLoadHelper2 resolves it via LoadLibraryExW
# with the standard search order; the install directory (where the operator
# drops our build artifact) wins ahead of System32 for non-KnownDlls names.
# That gets our DllMain executed inside the protected process, with full
# read access to the address space - no kernel injection callback is fired
# because Roblox is loading us itself.
#
# This sibling-target is to payload/dumper/ what payload/dumper/ is to
# payload/: the v2 dumper primitives (Logger, formatters, EnumModules,
# DiscoverImageExtent, WritePagewiseDump, etc.) get reused as-is. The
# only structural difference is we run under Roblox's CRT-initialized
# loader, so the freestanding constraints (no <cstdio>, no thread_local,
# no global ctors) DO NOT apply here. We use the full STL.
#
# CRITICAL: this DLL must be built WITHOUT the static CRT initializer
# crashing. We're loaded by an LdrLoadDll path inside a normal
# (non-suspicious-to-the-loader) process, so TLS callbacks fire normally
# and the CRT bootstraps cleanly. That's the inverse of the dumper's
# CreateRemoteThread environment.
# =============================================================================

set(PROXY_SOURCES
    src/ProxyEntry.cpp
    src/Stubs.cpp
    # Reuse the v2 SEH page-copy primitive verbatim. It's a leaf function -
    # plain pointers in, bool out, no shared state - so cross-target
    # recompilation has zero ABI risk.
    ../payload/dumper/src/Pagewise.cpp
)

set(PROXY_HEADERS
    ../payload/dumper/src/Pagewise.h
)

add_library(ENIProxy SHARED
    ${PROXY_SOURCES}
    ${PROXY_HEADERS}
    src/exports.def
)

target_include_directories(ENIProxy PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../payload/dumper/src   # for Pagewise.h
)

target_compile_features(ENIProxy PRIVATE cxx_std_23)

if(MSVC)
    set_property(TARGET ENIProxy PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENIProxy PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /wd4100             # unreferenced formal parameter (stub args)
        /wd4324             # struct-padding on PEB types
    )

    target_link_options(ENIProxy PRIVATE
        /DEBUG:FULL
    )
endif()

# kernel32 - VirtualQuery, HeapAlloc, CreateFileW
# user32   - harmless transitive dep via windows.h conventions
# shell32  - SHGetFolderPathW for resolving %LOCALAPPDATA%
target_link_libraries(ENIProxy PRIVATE
    kernel32
    user32
    shell32
)

# OUTPUT_NAME is the load-bearing piece. The on-disk file MUST be
# libHttpClient.GDK.dll - that exact spelling, including the dot before GDK,
# because the delay-load resolver does a literal basename match.
set_target_properties(ENIProxy PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "libHttpClient.GDK"
)

# No POST_BUILD encryption / copy - the artifact IS the deliverable.
# The operator copies it manually into the Roblox install dir.

# =============================================================================
# Sibling target: ENIProxyWebView - same dumper, masquerades as
# WebView2Loader.dll instead.
# =============================================================================
#
# Why a second target instead of just swapping the first:
#
#  - Empirically (verified via Get-Process Modules on a live Roblox PPL):
#    WebView2Loader.dll IS loaded eagerly into RobloxPlayerBeta. Our
#    libHttpClient.GDK.dll equivalent is NOT - the delay-load helper
#    never resolves it during a normal session because no GDK function
#    is invoked. So WebView2 is the load-reliable target.
#
#  - We keep ENIProxy alive as documentation of the libHttpClient
#    approach. If a future Roblox build starts invoking a GDK function
#    (e.g. they wire up WebSocket telemetry through it) we have the
#    stubs ready.
#
#  - The two targets share ProxyEntry.cpp and Pagewise.cpp. Only the
#    public-facing "what does this DLL pretend to be" surface differs.
#
# Forwarder strategy: WebView2Forwarders.cpp uses /EXPORT:Foo=Other.Foo
# pragma comments to make the linker emit PE-level forwarder records.
# At LoadLibrary time the loader resolves these against
# WebView2Loader_orig.dll (the renamed Microsoft DLL), so all five
# WebView2 entry points still work transparently and no shim code in
# our DLL ever runs on the call path.
# =============================================================================

set(PROXY_WEBVIEW_SOURCES
    src/ProxyEntry.cpp
    src/WebView2Forwarders.cpp
    ../payload/dumper/src/Pagewise.cpp
)

add_library(ENIProxyWebView SHARED
    ${PROXY_WEBVIEW_SOURCES}
    ${PROXY_HEADERS}
)

target_include_directories(ENIProxyWebView PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../payload/dumper/src
)

target_compile_features(ENIProxyWebView PRIVATE cxx_std_23)

if(MSVC)
    set_property(TARGET ENIProxyWebView PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENIProxyWebView PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /wd4100
        /wd4324
    )

    target_link_options(ENIProxyWebView PRIVATE
        /DEBUG:FULL
    )
endif()

target_link_libraries(ENIProxyWebView PRIVATE
    kernel32
    user32
    shell32
)

# OUTPUT_NAME = WebView2Loader. Exact spelling Roblox / Microsoft expect.
set_target_properties(ENIProxyWebView PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "WebView2Loader"
)

# =============================================================================
# Diagnostic target: ENIProxyStub - minimal empty-shell DLL.
# =============================================================================
#
# Single-TU shim that exports the five WebView2Loader symbols as no-ops
# returning S_OK, with an empty DllMain. Used to determine whether
# Roblox's "Failed to load library" error is caused by an Authenticode
# signature scan (in which case THIS DLL fails identically) or by
# something in our real proxy's DllMain / runtime thunks (in which
# case this passes and the real one fails).
#
# Built into bin\WebView2LoaderStub.dll. Operator copies it as
# WebView2Loader.dll for the test. NOT for production use - any actual
# WebView2 call will get back garbage.
# =============================================================================

add_library(ENIProxyStub SHARED src/WebView2Stub.cpp)

target_compile_features(ENIProxyStub PRIVATE cxx_std_23)

if(MSVC)
    set_property(TARGET ENIProxyStub PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_options(ENIProxyStub PRIVATE
        /W4 /permissive- /utf-8 /EHsc
        /wd4100
    )
endif()

target_link_libraries(ENIProxyStub PRIVATE kernel32)

set_target_properties(ENIProxyStub PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "WebView2LoaderStub"
)
