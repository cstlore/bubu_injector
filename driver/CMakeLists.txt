# =============================================================================
# ENIDrv - kernel-mode driver for cross-process VA reads
# =============================================================================
#
# Produces bin/EniDrv.sys, a tiny WDM driver that exposes one IOCTL
# (IOCTL_ENI_READ_VM) which performs PsLookupProcessByProcessId +
# KeStackAttachProcess + bounce-buffered cross-process read. Loaded
# via the SCM by user-mode ENIKernelDumper.exe.
#
# Build constraints differ wildly from user-mode targets:
#
#   - The driver is C, not C++. Keeps us out of CRT-mismatch territory.
#   - cl.exe needs /kernel to enable the right calling conventions and
#     forbid SSE state save/restore (kernel can't safely use SSE state
#     across IRQL changes without explicit setup).
#   - link.exe needs /SUBSYSTEM:NATIVE,6.00 + /DRIVER to produce a
#     native PE the I/O manager recognizes as a driver.
#   - We must NOT link the user-mode CRT or default libs - /NODEFAULTLIB
#     for kernel32, etc. We DO link ntoskrnl.lib and BufferOverflowK.lib
#     (the kernel-side stack-canary helper, mandatory in modern WDK).
#   - WDK headers live in a different include root than user-mode -
#     "Windows Kits\10\Include\<ver>\km" instead of "...\um".
#
# This is intentionally NOT a generic CMake-WDK template. It's a
# minimum-viable build for one tiny driver, hardcoded to the Win 11 24H2
# WDK we know is on this machine. If you move to a different machine,
# adjust WDK_VERSION below.
# =============================================================================

set(WDK_ROOT     "C:/Program Files (x86)/Windows Kits/10")
set(WDK_VERSION  "10.0.26100.0")

set(WDK_INC_KM      "${WDK_ROOT}/Include/${WDK_VERSION}/km")
set(WDK_INC_SHARED  "${WDK_ROOT}/Include/${WDK_VERSION}/shared")
set(WDK_LIB_KM_X64  "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64")

# We use /X to suppress the user-mode SDK include path, but we still
# need MSVC's own intrinsics headers (<intrin.h>, <vcruntime.h>) which
# live under the toolchain installation. Detect the MSVC tools root
# from the C compiler path so this isn't hardcoded to one VS version.
get_filename_component(MSVC_BIN_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
# CMAKE_C_COMPILER -> .../VC/Tools/MSVC/<ver>/bin/Hostx64/x64/cl.exe
# Walk up four levels to .../VC/Tools/MSVC/<ver>/
set(MSVC_TOOLS_ROOT "${MSVC_BIN_DIR}/../../../..")
get_filename_component(MSVC_TOOLS_ROOT "${MSVC_TOOLS_ROOT}" ABSOLUTE)
set(MSVC_INC "${MSVC_TOOLS_ROOT}/include")

set(DRIVER_SOURCES
    src/EniDrv.c
)

set(DRIVER_HEADERS
    include/EniDrvShared.h
)

add_library(EniDrv SHARED ${DRIVER_SOURCES} ${DRIVER_HEADERS})

# .sys, not .dll
set_target_properties(EniDrv PROPERTIES
    PREFIX ""
    SUFFIX ".sys"
    OUTPUT_NAME "EniDrv"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Kernel-mode include path. Order matters: the WDK km/ headers must
# come BEFORE the MSVC intrinsics headers, and we explicitly do NOT
# pull in the user-mode SDK at .../Include/<ver>/um/ - /X kills the
# default INCLUDE env var that would otherwise add it.
target_include_directories(EniDrv BEFORE PRIVATE
    ${WDK_INC_KM}/crt          # kernel-mode CRT subset (excpt.h, intrin.h, etc.)
    ${WDK_INC_KM}              # ntddk.h, wdm.h proper
    ${WDK_INC_SHARED}          # shared user/kernel definitions
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
# Note: we deliberately omit MSVC's own include/ directory. Its
# winnt.h defines _CONTEXT and friends incompatibly with the WDK's
# kernel definitions. The WDK ships its own intrinsics under km/crt
# (intrin.h there is kernel-friendly), so we don't need MSVC's.

# Compile flags. We deliberately reset everything the parent CMakeLists
# set globally because /EHsc /MP /W4 + C++ flags are wrong for a C
# kernel driver. Hence the bare list, no inheritance.
#
# /X is critical: it suppresses cl.exe's default INCLUDE environment
# variable processing. Without it, the user-mode SDK at
# Include/<ver>/um/ leaks in via VsDevCmd's INCLUDE export and
# user-mode <winnt.h> shadows the kernel's _CONTEXT, _KPCR, KAPC_STATE,
# _SLIST_HEADER definitions - leading to scores of redefinition errors
# that look unrelated until you realize the wrong winnt.h won.
target_compile_options(EniDrv PRIVATE
    /X                   # ignore default INCLUDE env var (no um/ SDK leakage)
    /TC                  # treat sources as C, not C++
    /kernel              # kernel-mode codegen (no SSE state, etc.)
    /GS                  # stack-cookie checks (BufferOverflowK provides the helper)
    /Gz                  # __stdcall default (driver entry points use it)
    /W4
    /WX-
    /Zp8                 # 8-byte struct packing matching kernel ABI
    /Gm-                 # no minimal rebuild
    /Zc:wchar_t-         # wchar_t is unsigned short, not built-in
    /wd4100              # unreferenced formal parameter
    /wd4201              # nameless struct/union
    /wd4324              # struct padding due to __declspec(align)
)

# Drop the parent's /EHsc and other inherited C++ flags. CMake adds
# them via add_compile_options at the root level, which would still
# apply. Override.
target_compile_options(EniDrv PRIVATE /EHs- /EHa-)

# Definitions kernel headers expect.
target_compile_definitions(EniDrv PRIVATE
    _AMD64_
    AMD64
    _WIN64
    NDEBUG
    NTDDI_VERSION=0x0A00000C        # NTDDI_WIN10_NI / Win11 22H2 - high
                                    # enough to expose ExAllocatePool2's
                                    # prototype, gated >= NTDDI_WIN10_VB
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    POOL_NX_OPTIN=1
    # Note: _KERNEL_MODE is auto-defined by cl.exe's /kernel switch.
    # Don't redefine _X86_ or _IA64_ to 0 - WDK headers use
    # `defined(_X86_)` not `_X86_ != 0`, so any definition (even =0)
    # poisons the architecture check and pulls in mixed x86/x64 code.
)

# Link as a native kernel driver. /SUBSYSTEM:NATIVE,6.00 + /DRIVER +
# /ENTRY:DriverEntry + /NODEFAULTLIB are the magic combo that flips
# link.exe from "user-mode DLL" mode to "kernel driver" mode.
target_link_options(EniDrv PRIVATE
    /SUBSYSTEM:NATIVE,6.00
    /DRIVER
    /ENTRY:DriverEntry
    /NODEFAULTLIB
    /MANIFEST:NO
    /MERGE:.edata=.rdata
    /MERGE:_TEXT=.text
    /MERGE:_PAGE=PAGE
    /SECTION:INIT,d
    /INTEGRITYCHECK
    /DEBUG:FULL
    /MACHINE:X64
)

# Kernel-mode libs. ntoskrnl.lib gives us PsLookupProcessByProcessId,
# Ke*, Io*, Ex*, Rtl*. hal.lib has hardware-abstraction helpers we
# don't actually call but the linker complains without it. wdmsec.lib
# and BufferOverflowK.lib cover the security descriptor stuff and the
# /GS canary helper respectively.
target_link_directories(EniDrv PRIVATE ${WDK_LIB_KM_X64})
target_link_libraries(EniDrv PRIVATE
    ntoskrnl
    hal
    BufferOverflowK
)
