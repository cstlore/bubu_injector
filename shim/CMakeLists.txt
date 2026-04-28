# =============================================================================
# ENILauncherShim - the launcher-process shim DLL
# =============================================================================
#
# This DLL is manual-mapped by ENILauncher.exe into RobloxPlayerLauncher.exe.
# Its sole job is to hook CreateProcessW and, when Roblox is spawned, manual-
# map the ENIPayload DLL into the suspended Roblox process before resuming
# the main thread (i.e. before Hyperion has a chance to run).
#
# Note that the shim links the ManualMapper translation unit from the
# injector subproject directly. We don't expose ManualMapper as its own
# library because its include layout assumes a sibling layout that's only
# true for in-tree consumers. Adding it as a source file here is the
# pragmatic path - one file, one ABI surface, no shared library plumbing.
# =============================================================================

set(SHIM_SOURCES
    src/ShimMain.cpp
    ../injector/src/ManualMapper.cpp
)

set(SHIM_HEADERS
    include/ShimStatus.h
    src/InlineHook.h
    ../injector/include/ManualMapper.h
    ../shared/BootInfo.h
    ../shared/ShimContract.h
)

add_library(ENILauncherShim SHARED ${SHIM_SOURCES} ${SHIM_HEADERS})

target_include_directories(ENILauncherShim PRIVATE
    include
    src
    ../injector/include
    ../shared
)

target_compile_features(ENILauncherShim PRIVATE cxx_std_23)

# Static CRT - the shim runs inside RobloxPlayerLauncher.exe's process.
# We can't assume any particular VC redistributable is present, and we
# definitely don't want to link the dynamic CRT (msvcp*.dll) - that would
# require LoadLibrary on first use and the manual-map runs before
# Hyperion DLLs are around to interfere, but other AVs might still flag a
# fresh msvcp dependency appearing.
if(MSVC)
    set_property(TARGET ENILauncherShim PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENILauncherShim PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /wd4100  # unreferenced formal parameter (Win32 headers)
        /wd4505  # unreferenced local function (some helpers conditionally used)
    )

    # Strip default exports - we want exactly one entry point visible.
    target_link_options(ENILauncherShim PRIVATE
        /DEBUG:FULL
        /EXPORT:ENIShimEntry
    )
endif()

target_link_libraries(ENILauncherShim PRIVATE
    kernel32
    user32
    advapi32
    psapi
    version             # needed by ManualMapper for GetFileVersionInfoW
)

# Output goes into bin/ alongside the launcher and the payload, so deployment
# is one folder.
set_target_properties(ENILauncherShim PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "ENILauncherShim"
    SUFFIX ".dll"
)
