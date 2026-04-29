# =============================================================================
# ENIDumper - runtime memory snapshot tool
# =============================================================================
#
# Produces bin/ENIDumper.dll, a plaintext PE meant to be manual-mapped into
# a live, fully-booted RobloxPlayerBeta.exe via the existing loader's
# attach-to-running mode:
#
#     ENILoader.exe --payload bin\ENIDumper.dll --pid <roblox_pid>
#
# Single export: ENIBootEntry. The dumper walks the process's own virtual
# memory, snapshots Roblox's image (including the runtime-decrypted
# .byfron section), and writes the bytes to disk under BootInfo.LogsDir.
# That snapshot is what the offline signature-derivation pass against
# Ghidra/IDA actually consumes for TODO #18.
#
# Deliberately omitted vs. the production payload:
#   - No MinHook (no detours)
#   - No Sentry arming
#   - No POST_BUILD ChaCha20 step (the loader sniffs the ENIE magic and
#     falls through to plaintext mapping when it's absent)
#   - No PCH, no __ImageBase tricks beyond what BootInfo already provides
#
# FREESTANDING: this DLL must not pull in any CRT-formatter dependency
# (std::snprintf / std::vsnprintf / std::swprintf). The CRT's TLS
# bootstrap (__dyn_tls_init) tries to register the calling thread with
# the FLS subsystem at first-touch, and on a CreateRemoteThread thread
# that never passed through LdrInitializeThunk, that call returns
# STATUS_INVALID_THREAD (0xC000071C) - we observed this in practice.
#
# So we deliberately do NOT pull in payload/src/Log.cpp (uses snprintf)
# or payload/src/SigScan.cpp (template + std::memcmp). DumperEntry.cpp
# hand-rolls its own ASCII formatters and a needle search.
# =============================================================================

set(DUMPER_SOURCES
    src/DumperEntry.cpp
    src/Pagewise.cpp
)

set(DUMPER_HEADERS
    src/Pagewise.h
)

add_library(ENIDumper SHARED ${DUMPER_SOURCES} ${DUMPER_HEADERS})

target_include_directories(ENIDumper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src       # for Pagewise.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shared  # for BootInfo.h
)

target_compile_features(ENIDumper PRIVATE cxx_std_23)

if(MSVC)
    set_property(TARGET ENIDumper PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(ENIDumper PRIVATE
        /W4 /permissive- /utf-8 /EHsc /MP
        /GS-                # disable stack canary (no full CRT)
        /wd4100             # unreferenced formal parameter
        /wd4505             # unreferenced local function
        /wd4324             # struct-padding warning from PEB types
    )

    target_link_options(ENIDumper PRIVATE
        /DEBUG:FULL
        /EXPORT:ENIBootEntry
    )
endif()

# kernel32 for VirtualQuery / HeapAlloc / CreateFileW / WriteFile.
# user32 / advapi32 only because Log.cpp transitively pulls them via
# windows.h conventions; harmless if unused at link time.
target_link_libraries(ENIDumper PRIVATE
    kernel32
    user32
    advapi32
)

set_target_properties(ENIDumper PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "ENIDumper"
)

# No POST_BUILD encryption. ENIDumper.dll on disk is the final artifact;
# the loader handles plaintext PE consumption directly.
