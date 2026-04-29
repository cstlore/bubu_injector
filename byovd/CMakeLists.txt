# =============================================================================
# ENIKernelDumper - BYOVD-backed cross-process memory dumper
# =============================================================================
#
# Standalone executable. Brings up a third-party signed kernel driver via
# the SCM, issues a kernel-virtual-memory-read IOCTL against
# RobloxPlayerBeta.exe (which is otherwise PPL-locked from user-mode
# injection), dumps the runtime-decrypted .text/.byfron sections to
# %LOCALAPPDATA%\ENI\logs\, then unloads the driver.
#
# This sidesteps test-signing detection: we don't enable test-signing,
# we use a driver that's already signed by an OEM in Microsoft's trust
# chain. Hyperion's CodeIntegrityOptions check passes; the only way it
# spots us is by enumerating loaded kernel modules during the brief
# window the driver is up, which is mitigated by randomizing the
# service name + on-disk filename.
#
# Operator workflow:
#   1. Launch Roblox; wait for in-game (engine .text decrypted).
#   2. Run as Administrator: bin\ENIKernelDumper.exe
#   3. Look in %LOCALAPPDATA%\ENI\logs\ for the dumped .bin files.
#
# REQUIRES: a signed driver .sys placed alongside the exe (default
# kprocesshacker.sys with device \\.\KProcessHacker3). Provide via
# --driver <path> --device <name> if using a different one.
# =============================================================================

set(BYOVD_SOURCES
    src/main.cpp
    src/DriverLoader.cpp
    src/KernelRead.cpp
)

set(BYOVD_HEADERS
    include/DriverLoader.h
    include/KernelRead.h
)

add_executable(ENIKernelDumper ${BYOVD_SOURCES} ${BYOVD_HEADERS})

target_include_directories(ENIKernelDumper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(ENIKernelDumper PRIVATE cxx_std_23)

if(MSVC)
    set_property(TARGET ENIKernelDumper PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENIKernelDumper PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /wd4100        # unreferenced formal parameter
        /wd4324        # struct padding
    )

    # Make it Unicode-aware (wmain entrypoint, wide-string Win32 APIs).
    target_compile_definitions(ENIKernelDumper PRIVATE
        UNICODE _UNICODE
    )

    # Manifest: requireAdministrator (we MUST be elevated to talk to
    # SCM with SC_MANAGER_ALL_ACCESS / register a kernel driver).
    target_link_options(ENIKernelDumper PRIVATE
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
        /SUBSYSTEM:CONSOLE
        /ENTRY:wmainCRTStartup
    )
endif()

target_link_libraries(ENIKernelDumper PRIVATE
    advapi32     # SCM
    bcrypt       # randomness
    shell32      # SHGetFolderPath / SHCreateDirectoryEx
    kernel32
)

set_target_properties(ENIKernelDumper PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "ENIKernelDumper"
)
