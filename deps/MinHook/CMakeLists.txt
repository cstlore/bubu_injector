# MinHook CMake wrapper
# MinHook is a light-weight API hooking library

cmake_minimum_required(VERSION 3.15)

project(MinHook)

# Source files from cloned repository
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../MinHook-src/src/buffer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../MinHook-src/src/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../MinHook-src/src/trampoline.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../MinHook-src/src/hde/hde32.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../MinHook-src/src/hde/hde64.c
)

# Create static library
add_library(MinHook STATIC ${SOURCES})

target_include_directories(MinHook PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../MinHook-src/include
)

# Platform-specific settings
if(WIN32)
    target_compile_definitions(MinHook PRIVATE
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0501
    )
endif()

# Compiler-specific optimizations
if(MSVC)
    target_compile_options(MinHook PRIVATE
        /W4
        /WX-
        /O2
        /GF
        /Gy
    )
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(MinHook PRIVATE
        -Wall
        -Wextra
        -Wno-pedantic
        -O2
    )
endif()

# Platform-specific settings
if(WIN32)
    target_compile_definitions(MinHook PRIVATE
        WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0501
    )
endif()

# Compiler-specific optimizations
if(MSVC)
    target_compile_options(MinHook PRIVATE
        /W4
        /WX-
        /O2
        /GF
        /Gy
    )
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(MinHook PRIVATE
        -Wall
        -Wextra
        -O2
    )
endif()
