include_guard(GLOBAL)

option(RHP_ENABLE "Build the live RHP host. OFF compiles hosts to inert stubs and patch points to direct calls." ON)
option(RHP_BUILD_TESTS "Build Tests/" ${RHP_IS_TOP_LEVEL})
option(RHP_BUILD_EXAMPLES "Build Examples/" ${RHP_IS_TOP_LEVEL})
option(RHP_BUILD_TOOLS "Build Tools/ (rhp-cli)" ${RHP_IS_TOP_LEVEL})
option(RHP_BUILD_BENCH "Build Tests/bench (rhp_bench, Catch2 benchmarks; needs RHP_BUILD_TESTS)" OFF)
option(RHP_INSTALL "Generate install rules and the rhp CMake package (find_package(rhp))" ${RHP_IS_TOP_LEVEL})
# A project that adds RHP as a subdirectory keeps building when a newer compiler adds a warning.
option(RHP_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ${RHP_IS_TOP_LEVEL})
option(RHP_WITH_TLS "TLS 1.3 for network endpoints (OpenSSL on desktop, Mbed TLS on mobile)" ON)
set(RHP_TLS_OPENSSL "AUTO" CACHE STRING "Use the system's OpenSSL (>= 3.0): AUTO (if found, desktop only), ON (required) or OFF")
set_property(CACHE RHP_TLS_OPENSSL PROPERTY STRINGS AUTO ON OFF)
option(RHP_TLS_MBEDTLS "Build the Mbed TLS backend (fetched; the mobile backend and the fallback without OpenSSL)" ON)
option(RHP_LUA_JUMP_YIELDS "Coroutine yields jump (_longjmp) instead of throwing; errors still throw. Ignored with the MSVC ABI outside x64 and under ThreadSanitizer" ON)
option(RHP_FUZZ "Build Tests/fuzz as libFuzzer executables (Clang only); without it they are ctest replay drivers" OFF)
# Clean builds (CI) compile RHP's own targets as unity files, 16 sources each: about a third less wall
# time; an edit then recompiles its whole batch, so it is off for everyday work.
# Shared precompiled headers: on for RHP's own desktop builds (measured there), off for cross builds.
if(RHP_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
    set(_rhp_pch_default ON)
else()
    set(_rhp_pch_default OFF)
endif()
option(RHP_PCH "Precompile the standard headers once for RHP's libraries and once for its tests (cmake/RhpPch.cmake)" ${_rhp_pch_default})
option(RHP_UNITY_BUILD "Compile RHP's libraries, tests and tools as unity files (clean builds)" OFF)
set(RHP_SANITIZE "" CACHE STRING "Sanitizers to enable: 'address;undefined', 'address' (MSVC) or 'thread'")

# The stage this tree implements, recorded in the installed package (rhp_STAGE). RHP has no
# release numbers; the wire protocol has its own revision (wire/ops.hpp).
set(RHP_STAGE "stage-12")

# Everything below is directory-scoped: it applies to RHP's own targets (and the dependencies it
# builds), never to the project that includes RHP, and a value that project already set wins.

# RHP's targets require C++23 through their compile features, so a consumer target linking them
# compiles as C++23 or later whatever the parent's CMAKE_CXX_STANDARD is.
if(NOT DEFINED CMAKE_CXX_STANDARD OR CMAKE_CXX_STANDARD MATCHES "^(98|11|14|17|20)$")
    set(CMAKE_CXX_STANDARD 23)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static libraries that may end up inside a shared library: position-independent code, and symbols
# hidden so that RHP (and the Lua, Monocypher and Mbed TLS it carries) never interposes on, or is
# interposed by, another copy in the same process.
if(NOT DEFINED CMAKE_POSITION_INDEPENDENT_CODE)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
if(NOT DEFINED CMAKE_CXX_VISIBILITY_PRESET)
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
endif()
if(NOT DEFINED CMAKE_C_VISIBILITY_PRESET)
    set(CMAKE_C_VISIBILITY_PRESET hidden)
endif()
if(NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
endif()

# Debug and release archives install side by side (rhp_cored.lib next to rhp_core.lib).
if(NOT DEFINED CMAKE_DEBUG_POSTFIX)
    set(CMAKE_DEBUG_POSTFIX d)
endif()

# Ninja, RHP built on its own: links share a pool sized by the machine's memory. A Debug test
# executable's link takes 1-2 s and up to 1 GB alone, but 13-22 s when every core links at once and
# the machine runs out of memory.
if(RHP_IS_TOP_LEVEL AND CMAKE_GENERATOR MATCHES "Ninja" AND NOT DEFINED CMAKE_JOB_POOL_LINK)
    cmake_host_system_information(RESULT _rhp_memory_mb QUERY TOTAL_PHYSICAL_MEMORY)
    math(EXPR _rhp_links "${_rhp_memory_mb} / 3072")
    if(_rhp_links LESS 2)
        set(_rhp_links 2)
    elseif(_rhp_links GREATER 8)
        set(_rhp_links 8)
    endif()
    set_property(GLOBAL APPEND PROPERTY JOB_POOLS rhp_link=${_rhp_links})
    set(CMAKE_JOB_POOL_LINK rhp_link)
endif()

# MSVC: debug information inside the objects (/Z7), so an installed static library needs no PDBs.
if(NOT DEFINED CMAKE_MSVC_DEBUG_INFORMATION_FORMAT)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>")
endif()
