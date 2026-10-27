include_guard(GLOBAL)

# rhp_lua: PUC Lua built as C++ (see cmake/lua/lua_cxx.cpp). Rhp::script links it PRIVATE, so lua.h
# never reaches a consumer; RHP's own script tests and benchmarks link it too (they compare with a
# plain Lua state). Upstream sources are not warning-clean under RHP's flags, so this target keeps
# the compiler defaults and is marked SYSTEM for includers.
if(NOT DEFINED lua_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpLua after CPMAddPackage(NAME lua ...)")
endif()

# Patched upstream sources (cmake/lua/lua_cxx.cpp includes them): each is copied into the build tree as
# rhp_<file> with its replacements. Each replacement must match upstream exactly once: a Lua update
# that moves one fails here, not at run time.
function(_rhp_lua_read file) # upstream <file> into the variable <file>
    file(READ "${lua_SOURCE_DIR}/${file}" _text)
    string(REPLACE "\r\n" "\n" _text "${_text}") # a Windows checkout may have CRLF
    set(${file} "${_text}" PARENT_SCOPE)
endfunction()
function(_rhp_lua_patch file from to)
    string(FIND "${${file}}" "${from}" _first)
    string(FIND "${${file}}" "${from}" _last REVERSE)
    if(_first EQUAL -1 OR NOT _first EQUAL _last)
        message(FATAL_ERROR "RHP: ${file} changed upstream; update its patch in cmake/RhpLua.cmake (looking for: ${from})")
    endif()
    string(REPLACE "${from}" "${to}" _patched "${${file}}")
    set(${file} "${_patched}" PARENT_SCOPE)
endfunction()
function(_rhp_lua_write file)
    set(_out "${CMAKE_CURRENT_BINARY_DIR}/rhp_lua/rhp_${file}")
    set(_old "")
    if(EXISTS "${_out}")
        file(READ "${_out}" _old)
    endif()
    if(NOT _old STREQUAL "${${file}}") # rewrite only on change: the Lua TU rebuilds otherwise
        file(WRITE "${_out}" "${${file}}")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${lua_SOURCE_DIR}/${file}")
endfunction()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_FILE}")

# Safe-point counting: a charge at lvm.c's loop back-edges (OP_JMP backwards, OP_FORLOOP, OP_TFORLOOP)
# and at Lua function entry, so a count hook RHP sets with internals::set_safepoint_hook costs nothing
# in straight-line code.
_rhp_lua_read(lvm.c)
_rhp_lua_patch(lvm.c "#define dojump(ci,i,e)\t{ pc += GETARG_sJ(i) + e; updatetrap(ci); }"
                     "#define dojump(ci,i,e)\t{ int rhp_jump = GETARG_sJ(i) + e; pc += rhp_jump; updatetrap(ci); if (rhp_jump < 0) rhp_lua_charge(-rhp_jump); }")
_rhp_lua_patch(lvm.c "        updatetrap(ci);  /* allows a signal to break the loop */\n"
                     "        updatetrap(ci);  /* allows a signal to break the loop */\n        rhp_lua_charge(GETARG_Bx(i));\n")
_rhp_lua_patch(lvm.c "        if (!ttisnil(s2v(ra + 3)))  /* continue loop? */\n          pc -= GETARG_Bx(i);  /* jump back */\n"
                     "        if (!ttisnil(s2v(ra + 3))) {  /* continue loop? */\n          pc -= GETARG_Bx(i);  /* jump back */\n          rhp_lua_charge(GETARG_Bx(i));\n        }\n")
_rhp_lua_patch(lvm.c " startfunc:\n  trap = L->hookmask;\n"
                     " startfunc:\n  trap = L->hookmask;\n  rhp_lua_charge(1);\n")
_rhp_lua_write(lvm.c)

# Steps in C: pattern matching (each match call, each character an expansion or %b scans, the bytes a
# back-reference compares) and plain find (the bytes each candidate compares) count down a step budget
# that calls the state's step function when it runs out (rhp_lua_step).
_rhp_lua_read(lstrlib.c)
_rhp_lua_patch(lstrlib.c "  int matchdepth;  /* control for recursive depth (to avoid C stack overflow) */\n"
                         "  int matchdepth;  /* control for recursive depth (to avoid C stack overflow) */\n  ptrdiff_t rhp_steps;  /* RHP: steps left until the next charge */\n")
_rhp_lua_patch(lstrlib.c "  ms->p_end = p + lp;\n}\n"
                         "  ms->p_end = p + lp;\n  ms->rhp_steps = RHP_LUA_STEPS;\n}\n")
_rhp_lua_patch(lstrlib.c "  if (l_unlikely(ms->matchdepth-- == 0))\n"
                         "  rhp_lua_step(ms->L, ms->rhp_steps, 1);\n  if (l_unlikely(ms->matchdepth-- == 0))\n")
_rhp_lua_patch(lstrlib.c "  while (singlematch(ms, s + i, p, ep))\n    i++;\n"
                         "  while (singlematch(ms, s + i, p, ep))\n    i++;\n  rhp_lua_step(ms->L, ms->rhp_steps, i);\n")
_rhp_lua_patch(lstrlib.c "    while (++s < ms->src_end) {\n"
                         "    while (++s < ms->src_end) {\n      rhp_lua_step(ms->L, ms->rhp_steps, 1);\n")
_rhp_lua_patch(lstrlib.c "  len = cast_sizet(ms->capture[l].len);\n"
                         "  len = cast_sizet(ms->capture[l].len);\n  rhp_lua_step(ms->L, ms->rhp_steps, len / RHP_LUA_BYTES_PER_STEP);\n")
_rhp_lua_patch(lstrlib.c "static const char *lmemfind (const char *s1, size_t l1,\n"
                         "static const char *lmemfind (lua_State *L, const char *s1, size_t l1,\n")
_rhp_lua_patch(lstrlib.c "    const char *init;  /* to search for a '*s2' inside 's1' */\n"
                         "    const char *init;  /* to search for a '*s2' inside 's1' */\n    ptrdiff_t rhp_steps = RHP_LUA_STEPS;\n")
_rhp_lua_patch(lstrlib.c "      if (memcmp(init, s2+1, l2) == 0)\n"
                         "      rhp_lua_step(L, rhp_steps, 1 + l2 / RHP_LUA_BYTES_PER_STEP);\n      if (memcmp(init, s2+1, l2) == 0)\n")
_rhp_lua_patch(lstrlib.c "lmemfind(s + init, ls - init, p, lp)"
                         "lmemfind(L, s + init, ls - init, p, lp)")
_rhp_lua_write(lstrlib.c)

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
