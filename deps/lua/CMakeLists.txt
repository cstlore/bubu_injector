# Lua wrapper - Roblox executor uses Roblox's own Lua state
# This provides header-only compatibility for Lua API

cmake_minimum_required(VERSION 3.15)

project(lua)

# Create empty static library - Lua state comes from Roblox
add_library(lua INTERFACE)
target_include_directories(lua INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lua-src/VM/include
)
