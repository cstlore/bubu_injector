# =============================================================================
# ENILauncher - the user-facing launcher EXE
# =============================================================================
#
# Spawns RobloxPlayerLauncher.exe suspended, manual-maps ENILauncherShim.dll
# into it, hands the shim a ShimEnvelope, then resumes the launcher.
#
# Single-file deployment: static CRT, no external dependencies. The launcher
# reads the shim DLL and the payload DLL from disk at runtime - both must
# sit alongside ENILauncher.exe (or be passed via --shim / --payload).
# =============================================================================

set(LAUNCHER_SOURCES
    src/main.cpp
    src/ShimMapper.cpp
)

set(LAUNCHER_HEADERS
    src/ShimMapper.h
    ../shared/BootInfo.h
    ../shared/ShimContract.h
)

add_executable(ENILauncher ${LAUNCHER_SOURCES} ${LAUNCHER_HEADERS})

# Console subsystem - we use wmain (not wWinMain) so stdout/stderr are
# usable when invoked from a terminal. When we ship a tray-app GUI later
# we'll set WIN32_EXECUTABLE ON and switch the entry point to wWinMain.

target_include_directories(ENILauncher PRIVATE
    src
    ../shared
)

target_compile_features(ENILauncher PRIVATE cxx_std_23)

if(MSVC)
    set_property(TARGET ENILauncher PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENILauncher PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /wd4100  # unreferenced formal parameter
    )
    target_link_options(ENILauncher PRIVATE /DEBUG:FULL)
endif()

target_link_libraries(ENILauncher PRIVATE
    kernel32
    user32
    advapi32
    psapi
    shell32
    shlwapi
    ole32
)

set_target_properties(ENILauncher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)

# Make sure the shim is built before the launcher tries to ship next to it.
# The shim is what the launcher will actually consume at runtime - if it
# isn't built, ENILauncher.exe runs but fails on the file-not-found check
# the moment a user tries to use it. CMake target_dependency keeps the
# build order honest in IDEs; it's a no-op for command-line ninja.
if(TARGET ENILauncherShim)
    add_dependencies(ENILauncher ENILauncherShim)
endif()
