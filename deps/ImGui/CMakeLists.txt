# ImGui CMake wrapper
# ImGui is a header-only GUI library

cmake_minimum_required(VERSION 3.15)

project(ImGui)

# ImGui sources from cloned repository
set(IMGUI_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/imgui.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/imgui_demo.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/imgui_draw.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/imgui_tables.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/imgui_widgets.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/backends/imgui_impl_dx11.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/backends/imgui_impl_win32.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src/backends/imgui_impl_opengl3.cpp
)

add_library(ImGui STATIC ${IMGUI_SOURCES})

target_include_directories(ImGui PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../ImGui-src
)

# Platform-specific definitions
if(WIN32)
    target_compile_definitions(ImGui PRIVATE
        _WIN32_WINNT=0x0601
        WIN32_LEAN_AND_MEAN
    )
endif()

# Compiler-specific settings
if(MSVC)
    target_compile_options(ImGui PRIVATE
        /W4
        /WX-
        /wd4127  # suppress "conditional expression is constant"
        /wd4718  # suppress "recursive call has no side effect"
    )
endif()