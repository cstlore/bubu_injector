# =============================================================================
# ENI - Top-level build
# =============================================================================
#
# Two-component build:
#   1. ENILoader  (executable) - the manual-mapping injector. See injector/.
#   2. RobloxExecutor (DLL)    - the in-process payload. Source under src/.
#
# These are intentionally decoupled - no link-time dependency. The loader
# consumes the payload DLL at runtime as bytes (file for now; encrypted
# resource later).
#
# Both share shared/BootInfo.h - that's the only cross-component coupling.
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(ENI C CXX)   # C is needed for the kernel driver subproject (driver/src/EniDrv.c)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Output directories - everything to bin/.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Common compile options for both subprojects.
if(MSVC)
    add_compile_options(/W4 /WX- /permissive- /utf-8 /EHsc /MP)
    # Suppress noisy third-party warnings without disabling them globally.
    add_compile_options(/wd4251 /wd4244 /wd4267 /wd4127 /wd4100)
endif()

# -----------------------------------------------------------------------------
# Third-party deps - added FIRST so all subprojects see their targets.
# -----------------------------------------------------------------------------
#
# In particular, the new payload/ subproject needs MinHook to exist as a
# target before its own add_subdirectory runs. Guard each one so an
# incomplete `deps/` clone doesn't fail the configure.

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deps/MinHook/CMakeLists.txt)
    add_subdirectory(deps/MinHook)
endif()
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deps/lua/CMakeLists.txt)
    add_subdirectory(deps/lua)
endif()
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deps/ImGui/CMakeLists.txt)
    add_subdirectory(deps/ImGui)
endif()

# Optional: nlohmann/json. We need it for the legacy Config.cpp. If
# deps/json doesn't exist, fall back to a header-only INTERFACE target.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deps/json/CMakeLists.txt)
    add_subdirectory(deps/json)
elseif(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deps/json-src/include/nlohmann/json.hpp)
    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/json-src/include)
endif()

# -----------------------------------------------------------------------------
# Subproject 1: the loader (raw injector EXE - useful for direct attach)
# -----------------------------------------------------------------------------
add_subdirectory(injector)

# -----------------------------------------------------------------------------
# Subproject 1b: the launcher-process shim DLL
# -----------------------------------------------------------------------------
#
# The shim is manual-mapped by ENILauncher.exe into RobloxPlayerLauncher.exe.
# Order matters: it must be added before the launcher subdirectory so
# add_dependencies() in the launcher's CMakeLists can see it as a target.
add_subdirectory(shim)

# -----------------------------------------------------------------------------
# Subproject 1c: the launcher EXE
# -----------------------------------------------------------------------------
add_subdirectory(launcher)

# -----------------------------------------------------------------------------
# Subproject 1d: the new in-process payload DLL (Hyperion-aware)
# -----------------------------------------------------------------------------
#
# This is the in-process payload that gets manual-mapped into Roblox by
# the shim. It exports ENIBootEntry and runs the Hyperion-neutralization
# arming sequence. Built parallel to the legacy RobloxExecutor target
# below - whichever target POST_BUILD-copies last wins for bin/payload.bin.
# In a clean build, payload/ is added before the legacy target so the
# legacy copy overwrites this one. We'll remove the legacy POST_BUILD
# in a follow-up; for now the build order is intentional and documented.
add_subdirectory(payload)

# -----------------------------------------------------------------------------
# Subproject 1e: the runtime memory dumper (sibling of payload/)
# -----------------------------------------------------------------------------
#
# ENIDumper.dll is a small read-only DLL the operator manual-maps into a
# live, fully-booted Roblox to snapshot Roblox's address space (including
# the runtime-decrypted .byfron section) for offline signature derivation.
# Built parallel to ENIPayload, but no payload.bin collision because
# ENIDumper writes its own plaintext bin/ENIDumper.dll and skips the
# encryption POST_BUILD step.
#
# Operator workflow:
#   ENILoader.exe --payload bin\ENIDumper.dll --pid <roblox_pid>
add_subdirectory(payload/dumper)

# -----------------------------------------------------------------------------
# Subproject 1f: the search-order-hijack proxy (ENIProxy / libHttpClient.GDK)
# -----------------------------------------------------------------------------
#
# When PPL kills every external injection vector (OpenProcess returns 87,
# DebugActiveProcess returns 5, CREATE_SUSPENDED + manual map yields
# STATUS_PROCESS_IS_PROTECTED), the only surviving path is to have Roblox
# load us itself. ENIProxy ships as libHttpClient.GDK.dll - a delay-load
# import Roblox tries to resolve and which doesn't currently exist on
# disk. Drop it in the install dir; Roblox's own LdrLoadDll picks it up
# via standard search order; DllMain runs INSIDE the protected process
# and spawns a worker thread that runs the v2 dumper pipeline once
# Hyperion has finished decrypting the engine .text.
#
# Operator workflow: copy bin\libHttpClient.GDK.dll into Roblox's
# version-<hash>\ install directory, launch Roblox normally, harvest
# the dump from %LOCALAPPDATA%\ENI\logs\.
add_subdirectory(proxy)

# -----------------------------------------------------------------------------
# Subproject 1g: BYOVD kernel-read dumper (ring-0 path, sidesteps PPL)
# -----------------------------------------------------------------------------
#
# When the user-mode loader is locked down (PPL kernel callback filters
# OpenProcess, Hyperion signature-checks install-dir DLLs by name, and
# the user-mode module set is fully System32 + signed install dir) the
# remaining option is ring-0. Test-signing is detectable via
# NtQuerySystemInformation(SystemCodeIntegrityInformation), so we go
# BYOVD: load a third-party signed driver via SCM, abuse its
# kernel-virtual-memory-read IOCTL to snapshot RobloxPlayerBeta from
# kernel context (where PPL doesn't apply).
#
# Standalone elevated CLI tool. Run AFTER Roblox is in-game so the
# engine .text has finished its runtime decryption pass. Outputs go to
# the same %LOCALAPPDATA%\ENI\logs\ as the in-process dumpers.
add_subdirectory(byovd)

# -----------------------------------------------------------------------------
# Subproject 1h: ENIDrv kernel driver (test-signed, our own ring-0)
# -----------------------------------------------------------------------------
#
# When BYOVD with currently-signed third-party drivers stops working
# (PH 2.x revoked, KSystemInformer self-protected), the remaining ring-0
# path is to write our own minimal driver and load it under
# `bcdedit /set testsigning on`. This subproject builds bin\EniDrv.sys
# from driver/src/EniDrv.c. ENIKernelDumper.exe expects to find it
# alongside in bin/.
#
# IMPORTANT: this target depends on the WDK being installed at
# "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/km/".
# If the WDK isn't present, configure-time include resolution fails.
# We don't gate the target on file existence - if the WDK is missing
# you'll see it loud and clear at build time.
add_subdirectory(driver)

# -----------------------------------------------------------------------------
# Subproject 2: the payload DLL (existing code, retained as-is for now)
# -----------------------------------------------------------------------------
#
# This will be moved under payload/ in a later cleanup pass once we strip
# the *Ex APIs out of it. For point 1 we leave the existing layout intact
# so the loader has something to inject during initial smoke testing.
# -----------------------------------------------------------------------------

add_definitions(-DEXECUTOR_EXPORTS)

set(PAYLOAD_SOURCES
    src/main.cpp
    src/Core/Globals.cpp
    src/Core/Config.cpp
    src/Memory/MemoryManager.cpp
    src/Memory/PatternScanner.cpp
    src/Executor/LuaContext.cpp
    src/Executor/ScriptEngine.cpp
    src/Hooking/HookManager.cpp
    src/Hooking/Hooks.cpp
    src/UI/ImGuiRenderer.cpp
    src/UI/Menu.cpp
    src/UI/ScriptEditor.cpp
    src/UI/ESP.cpp
    src/ScriptHub/ScriptHub.cpp
)

set(PAYLOAD_HEADERS
    include/Core/Globals.h
    include/Core/Config.h
    include/Memory/MemoryManager.h
    include/Memory/PatternScanner.h
    include/Executor/LuaContext.h
    include/Executor/ScriptEngine.h
    include/Hooking/HookManager.h
    include/Hooking/Hooks.h
    include/UI/ImGuiRenderer.h
    include/UI/Menu.h
    include/UI/ScriptEditor.h
    include/UI/ESP.h
    include/ScriptHub/ScriptHub.h
    include/Utils/Utils.h
)

# EXCLUDE_FROM_ALL: the legacy executor doesn't build cleanly under MSVC 14.50
# / std:c++latest right now (missing includes for ImU32, std::mutex, MH_HANDLE,
# imgui_impl_dx11.h, etc) and we're retiring it once its features (Lua, ImGui,
# ScriptHub, ESP) are ported onto the Sentry-armed payload. Keep the target
# alive for the future port - explicit `cmake --build build --target
# RobloxExecutor` still triggers it - but don't let its bitrot block the
# default new-chain build that we actually ship.
add_library(RobloxExecutor SHARED EXCLUDE_FROM_ALL ${PAYLOAD_SOURCES} ${PAYLOAD_HEADERS})

target_include_directories(RobloxExecutor PRIVATE
    include
    shared                          # for BootInfo.h
    deps/MinHook/include
    deps/MinHook/MinHook-src/include
    deps/lua/lua-src/VM/include
    deps/ImGui
    deps/ImGui/ImGui-src
    deps/json-src/include
)

# Link only what exists. The hard Windows libs are unconditional; the
# third-party targets are conditional on having been added above.
target_link_libraries(RobloxExecutor PRIVATE
    d3d11
    dxgi
    opengl32
    gdi32
    kernel32
    user32
    advapi32
    psapi
)

if(TARGET MinHook)
    target_link_libraries(RobloxExecutor PRIVATE MinHook)
endif()
if(TARGET lua)
    target_link_libraries(RobloxExecutor PRIVATE lua)
endif()
if(TARGET ImGui)
    target_link_libraries(RobloxExecutor PRIVATE ImGui)
endif()
if(TARGET nlohmann_json)
    target_link_libraries(RobloxExecutor PRIVATE nlohmann_json)
endif()

# PCH support
target_precompile_headers(RobloxExecutor PRIVATE include/pch.h)

# NOTE: This target USED to POST_BUILD-copy itself to bin/payload.bin so the
# loader smoke test would pick it up. That role now belongs to ENIPayload
# (under payload/), which is the in-process Hyperion-aware payload that
# the launcher actually wants to inject. The legacy RobloxExecutor.dll
# stays in bin/ under its own name for any in-tree consumer that still
# references it; nothing should be reading payload.bin from this target.
