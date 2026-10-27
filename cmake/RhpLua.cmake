include_guard(GLOBAL)

# rhp_lua: PUC Lua built as C++ (see cmake/lua/lua_cxx.cpp). Only Rhp::script links it, PRIVATE,
# so lua.h never reaches a consumer. Upstream sources are not warning-clean under RHP's flags,
# so this target keeps the compiler defaults and is marked SYSTEM for includers.
if(NOT DEFINED lua_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpLua after CPMAddPackage(NAME lua ...)")
endif()

# Safe-point counting (cmake/lua/lua_cxx.cpp): lvm.c is copied into the build tree with a charge added
# at its loop back-edges (OP_JMP backwards, OP_FORLOOP, OP_TFORLOOP) and at Lua function entry, so a
# count hook RHP sets with internals::set_safepoint_hook costs nothing in straight-line code. Each
# replacement must match upstream exactly once: a Lua update that moves one fails here, not at run time.
file(READ "${lua_SOURCE_DIR}/lvm.c" _rhp_lvm)
string(REPLACE "\r\n" "\n" _rhp_lvm "${_rhp_lvm}") # a Windows checkout may have CRLF
function(_rhp_lvm_patch from to)
    string(FIND "${_rhp_lvm}" "${from}" _first)
    string(FIND "${_rhp_lvm}" "${from}" _last REVERSE)
    if(_first EQUAL -1 OR NOT _first EQUAL _last)
        message(FATAL_ERROR "RHP: lvm.c changed upstream; update the safe-point patch in cmake/RhpLua.cmake (looking for: ${from})")
    endif()
    string(REPLACE "${from}" "${to}" _patched "${_rhp_lvm}")
    set(_rhp_lvm "${_patched}" PARENT_SCOPE)
endfunction()
_rhp_lvm_patch("#define dojump(ci,i,e)\t{ pc += GETARG_sJ(i) + e; updatetrap(ci); }"
               "#define dojump(ci,i,e)\t{ int rhp_jump = GETARG_sJ(i) + e; pc += rhp_jump; updatetrap(ci); if (rhp_jump < 0) rhp_lua_charge(-rhp_jump); }")
_rhp_lvm_patch("        updatetrap(ci);  /* allows a signal to break the loop */\n"
               "        updatetrap(ci);  /* allows a signal to break the loop */\n        rhp_lua_charge(GETARG_Bx(i));\n")
_rhp_lvm_patch("        if (!ttisnil(s2v(ra + 3)))  /* continue loop? */\n          pc -= GETARG_Bx(i);  /* jump back */\n"
               "        if (!ttisnil(s2v(ra + 3))) {  /* continue loop? */\n          pc -= GETARG_Bx(i);  /* jump back */\n          rhp_lua_charge(GETARG_Bx(i));\n        }\n")
_rhp_lvm_patch(" startfunc:\n  trap = L->hookmask;\n"
               " startfunc:\n  trap = L->hookmask;\n  rhp_lua_charge(1);\n")
set(_rhp_lvm_out "${CMAKE_CURRENT_BINARY_DIR}/rhp_lua/rhp_lvm.c")
set(_rhp_lvm_old "")
if(EXISTS "${_rhp_lvm_out}")
    file(READ "${_rhp_lvm_out}" _rhp_lvm_old)
endif()
if(NOT _rhp_lvm_old STREQUAL _rhp_lvm) # rewrite only on change: the Lua TU rebuilds otherwise
    file(WRITE "${_rhp_lvm_out}" "${_rhp_lvm}")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${lua_SOURCE_DIR}/lvm.c" "${CMAKE_CURRENT_LIST_FILE}")

add_library(rhp_lua STATIC "${PROJECT_SOURCE_DIR}/cmake/lua/lua_cxx.cpp")
target_include_directories(rhp_lua PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/rhp_lua")
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

rhp_third_party_flags(rhp_lua UTF8 SECTIONS)
