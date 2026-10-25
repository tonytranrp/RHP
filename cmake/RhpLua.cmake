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

# Coroutine yields jump instead of throwing (cmake/lua/lua_cxx.cpp). With the MSVC ABI only on x64,
# where the CRT's longjmp can skip unwinding; not under ThreadSanitizer: its shadow call stack
# doesn't follow those jumps, and a request that yields some thousands of times crashes it.
set(_rhp_lua_jumps_here TRUE)
if(MSVC AND NOT CMAKE_CXX_COMPILER_ARCHITECTURE_ID MATCHES "^(x64|X64|AMD64|x86_64)$")
    set(_rhp_lua_jumps_here FALSE)
endif()
if(RHP_LUA_JUMP_YIELDS AND _rhp_lua_jumps_here AND NOT "thread" IN_LIST RHP_SANITIZE)
    target_compile_definitions(rhp_lua PRIVATE RHP_LUA_JUMP_YIELDS)
endif()

# The interpreter's computed-goto dispatch: upstream enables it for __GNUC__ only, which clang-cl
# doesn't define although it supports labels as values.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_definitions(rhp_lua PRIVATE LUA_USE_JUMPTABLE=1)
endif()

# API misuse asserts in Debug: a broken trampoline aborts loudly instead of corrupting the VM.
target_compile_definitions(rhp_lua PUBLIC $<$<CONFIG:Debug>:LUA_USE_APICHECK>)

if(MSVC)
    target_compile_options(rhp_lua PRIVATE /utf-8 /W0 /Zc:inline /Gw)
else()
    target_compile_options(rhp_lua PRIVATE -w -ffunction-sections -fdata-sections)
endif()
