# A separate project that uses RHP the way an application does. RHP's ctest builds it against the
# tree it just installed (package.find_package); CI also builds it with RHP as a subdirectory:
#
#   cmake -S Tests/package -B build/consumer -DCMAKE_PREFIX_PATH=<prefix>            # installed package
#   cmake -S Tests/package -B build/consumer -DRHP_PACKAGE_CONSUME=subdirectory      # this checkout
cmake_minimum_required(VERSION 3.28)

project(rhp_package_consumer LANGUAGES CXX)

# Below C++23 on purpose: Rhp:: targets raise their users to C++23 through their compile features,
# and RHP added as a subdirectory must not reject the parent's setting.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RHP_PACKAGE_CONSUME "find_package" CACHE STRING "How the consumer gets RHP: find_package or subdirectory")
set_property(CACHE RHP_PACKAGE_CONSUME PROPERTY STRINGS find_package subdirectory)

if(RHP_PACKAGE_CONSUME STREQUAL "subdirectory")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../.." rhp)
    foreach(leaked IN ITEMS rhp_core_tests hello_console rhp-cli)
        if(TARGET ${leaked})
            message(FATAL_ERROR "RHP as a subdirectory built '${leaked}' (tests, examples and tools are top-level only)")
        endif()
    endforeach()
else()
    find_package(rhp CONFIG REQUIRED)
    foreach(var IN ITEMS rhp_STAGE rhp_PROTOCOL_REVISION rhp_ENABLE rhp_HARDENING rhp_PLATFORM)
        if(NOT DEFINED ${var})
            message(FATAL_ERROR "the rhp package doesn't set ${var}")
        endif()
    endforeach()
    message(STATUS "rhp package: ${rhp_STAGE}, protocol revision ${rhp_PROTOCOL_REVISION}, RHP_ENABLE ${rhp_ENABLE}, RHP_HARDENING ${rhp_HARDENING}, ${rhp_PLATFORM}")
endif()

function(consumer_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE Rhp::rhp)
consumer_warnings(consumer)
if(DEFINED rhp_PROTOCOL_REVISION)
    target_compile_definitions(consumer PRIVATE RHP_PACKAGE_PROTOCOL_REVISION=${rhp_PROTOCOL_REVISION})
endif()

enable_testing()
add_test(NAME consumer COMMAND consumer)

# <windows.h> first, without NOMINMAX: its min / max macros must not break RHP's headers.
if(WIN32)
    add_executable(windows_h_first windows_h_first.cpp)
    target_link_libraries(windows_h_first PRIVATE Rhp::rhp)
    consumer_warnings(windows_h_first)
    add_test(NAME windows_h_first COMMAND windows_h_first)
endif()

# Lua tests through the package: Rhp::test and rhp_add_lua_tests (RhpLuaTests.cmake).
if(NOT COMMAND rhp_add_lua_tests)
    message(FATAL_ERROR "the rhp package doesn't define rhp_add_lua_tests")
endif()
add_executable(consumer_lua_tests lua_tests_main.cpp)
target_link_libraries(consumer_lua_tests PRIVATE Rhp::test)
consumer_warnings(consumer_lua_tests)
if((DEFINED rhp_ENABLE AND rhp_ENABLE) OR (NOT DEFINED rhp_ENABLE AND RHP_ENABLE))
    rhp_add_lua_tests(consumer_lua TARGET consumer_lua_tests FILES lua/consumer_spec.lua)
endif()
