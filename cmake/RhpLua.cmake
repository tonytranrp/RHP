include_guard(GLOBAL)

# rhp_lua: PUC Lua built as C++ (see cmake/lua/lua_cxx.cpp). Only Rhp::script links it, PRIVATE,
# so lua.h never reaches a consumer. Upstream sources are not warning-clean under RHP's flags,
# so this target keeps the compiler defaults and is marked SYSTEM for includers.
if(NOT DEFINED lua_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpLua after CPMAddPackage(NAME lua ...)")
endif()

add_library(rhp_lua STATIC "${PROJECT_SOURCE_DIR}/cmake/lua/lua_cxx.cpp")
add_library(Rhp::lua ALIAS rhp_lua)
# Build tree only: an installed RHP ships the archive (Rhp::script needs it at link time), not lua.h.
target_include_directories(rhp_lua SYSTEM PUBLIC "$<BUILD_INTERFACE:${lua_SOURCE_DIR}>")
target_compile_features(rhp_lua PUBLIC cxx_std_23)
set_target_properties(rhp_lua PROPERTIES FOLDER "third_party" EXPORT_NAME lua)
set_property(GLOBAL APPEND PROPERTY RHP_INSTALL_THIRD_PARTY_TARGETS rhp_lua)

# Platform feature switches understood by upstream luaconf.h (CMake-level, not C++ #ifdefs).
if(RHP_PLATFORM STREQUAL "LINUX" OR RHP_PLATFORM STREQUAL "ANDROID")
    target_compile_definitions(rhp_lua PUBLIC LUA_USE_LINUX)
    target_link_libraries(rhp_lua PUBLIC ${CMAKE_DL_LIBS})
elseif(RHP_PLATFORM STREQUAL "MACOS")
    target_compile_definitions(rhp_lua PUBLIC LUA_USE_MACOSX)
elseif(RHP_PLATFORM STREQUAL "IOS")
    target_compile_definitions(rhp_lua PUBLIC LUA_USE_IOS)
elseif(RHP_PLATFORM STREQUAL "WINDOWS")
    target_compile_definitions(rhp_lua PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Coroutine yields jump instead of throwing (cmake/lua/lua_cxx.cpp), except with the MSVC ABI,
# whose longjmp unwinds like an exception, and under ThreadSanitizer: its shadow call stack doesn't
# follow those jumps, and a request that yields some thousands of times crashes it.
if(RHP_LUA_JUMP_YIELDS AND NOT MSVC AND NOT "thread" IN_LIST RHP_SANITIZE)
    target_compile_definitions(rhp_lua PRIVATE RHP_LUA_JUMP_YIELDS)
endif()

# API misuse asserts in Debug: a broken trampoline aborts loudly instead of corrupting the VM.
target_compile_definitions(rhp_lua PUBLIC $<$<CONFIG:Debug>:LUA_USE_APICHECK>)

if(MSVC)
    target_compile_options(rhp_lua PRIVATE /utf-8 /W0)
else()
    target_compile_options(rhp_lua PRIVATE -w)
endif()
