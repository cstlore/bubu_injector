# =============================================================================
# ENILoader - the manual-mapping injector
# =============================================================================
#
# Standalone EXE that maps the payload DLL into a target Roblox process.
# Has no link-time dependency on the payload - the payload is consumed at
# runtime as a binary blob (file or, eventually, embedded resource).
#
# Static linking of the C/C++ runtime is intentional: we want a single-file
# loader that runs on a fresh Windows install with no VC redistributables
# required. Binary size cost is ~200 KB - negligible for a one-shot launcher.
# =============================================================================

set(LOADER_SOURCES
    src/main.cpp
    src/ManualMapper.cpp
)

set(LOADER_HEADERS
    include/ManualMapper.h
    ../shared/BootInfo.h
)

add_executable(ENILoader ${LOADER_SOURCES} ${LOADER_HEADERS})

target_include_directories(ENILoader PRIVATE
    include
    ../shared
)

target_compile_features(ENILoader PRIVATE cxx_std_23)

# Static CRT - one-file deployment
if(MSVC)
    set_property(TARGET ENILoader PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENILoader PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /wd4100  # unreferenced formal parameter (common in Win32 headers)
    )
    target_link_options(ENILoader PRIVATE /DEBUG:FULL)
endif()

# Windows libraries explicitly named (no nonexistent "winapi" target)
target_link_libraries(ENILoader PRIVATE
    kernel32
    user32
    advapi32
    psapi
    shell32
    version             # needed by ManualMapper for GetFileVersionInfoW
)

# Output goes to the same bin/ as the payload so they sit side-by-side
# (loader looks for payload.bin in its own directory).
set_target_properties(ENILoader PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)
