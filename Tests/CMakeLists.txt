include(Catch)

# rhp_add_test_suite(<name> SOURCES <files...> LINKS <targets...>)
# One executable per module; every TEST_CASE is registered with ctest individually. Cases tagged
# [multicast] share the mDNS port and group, so they hold one RESOURCE_LOCK under ctest -j; they
# carry the ctest label `multicast` too (they need a working LAN): `ctest -LE multicast` skips them.
# Cases tagged [process] (separate rhp-cli / headless_server processes) carry the label `process`.
function(rhp_add_test_suite name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "SOURCES;LINKS")
    add_executable(${name} ${arg_SOURCES})
    target_link_libraries(${name} PRIVATE ${arg_LINKS} Catch2::Catch2WithMain)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/support")
    rhp_set_warnings(${name})
    set_target_properties(${name} PROPERTIES FOLDER "tests")
    catch_discover_tests(${name} TEST_PREFIX "${name}." DISCOVERY_MODE PRE_TEST TEST_SPEC "~[multicast]~[process]")
    catch_discover_tests(${name} TEST_PREFIX "${name}." DISCOVERY_MODE PRE_TEST TEST_SPEC "[process]~[multicast]" PROPERTIES LABELS process)
    catch_discover_tests(${name} TEST_PREFIX "${name}." DISCOVERY_MODE PRE_TEST TEST_SPEC "[multicast]" PROPERTIES RESOURCE_LOCK multicast LABELS multicast)
endfunction()

# rhp_add_compile_fail(<name> SOURCE <file> LINKS <targets...>)
# The source must compile as-is AND must fail to compile with RHP_COMPILE_FAIL defined, so the
# test proves the guarded snippet is what breaks the build (not an unrelated error).
function(rhp_add_compile_fail name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "SOURCE" "LINKS")

    add_library(${name}_ok OBJECT ${arg_SOURCE})
    target_link_libraries(${name}_ok PRIVATE ${arg_LINKS})
    rhp_set_warnings(${name}_ok)

    add_library(${name}_fail OBJECT EXCLUDE_FROM_ALL ${arg_SOURCE})
    target_link_libraries(${name}_fail PRIVATE ${arg_LINKS})
    target_compile_definitions(${name}_fail PRIVATE RHP_COMPILE_FAIL=1)
    set_target_properties(${name}_ok ${name}_fail PROPERTIES FOLDER "tests/compile_fail")

    add_test(NAME compile_fail.${name}
        COMMAND ${CMAKE_COMMAND} --build "${CMAKE_BINARY_DIR}" --target ${name}_fail --config $<CONFIG>)
    set_tests_properties(compile_fail.${name} PROPERTIES WILL_FAIL TRUE LABELS compile_fail)
endfunction()

add_subdirectory(unit)
add_subdirectory(compile_fail)
if(RHP_ENABLE)
    add_subdirectory(integration)
    add_subdirectory(fuzz)
endif()
if(RHP_ENABLE AND RHP_BUILD_TOOLS)
    add_subdirectory(tools)
endif()
if(RHP_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# The Python client (clients/python) against this build's headless_server, when Python 3 with pytest
# is available: its codec and frame vectors, then live sessions (signed scripts, events, cancel, resume).
if(RHP_ENABLE AND RHP_BUILD_EXAMPLES AND NOT CMAKE_CROSSCOMPILING)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        execute_process(COMMAND "${Python3_EXECUTABLE}" -c "import pytest" RESULT_VARIABLE rhp_no_pytest OUTPUT_QUIET ERROR_QUIET)
        if(rhp_no_pytest EQUAL 0)
            add_test(NAME python.client
                COMMAND "${Python3_EXECUTABLE}" -m pytest -q -p no:cacheprovider "${PROJECT_SOURCE_DIR}/clients/python/tests"
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/clients/python")
            set_tests_properties(python.client PROPERTIES
                ENVIRONMENT "RHP_HEADLESS_SERVER=$<TARGET_FILE:headless_server>;PYTHONPATH=${PROJECT_SOURCE_DIR}/clients/python/src"
                LABELS "python;process" TIMEOUT 600)
        endif()
    endif()
endif()

# The VS Code extension (clients/vscode), when Node.js is available: its protocol and glue code
# (against a stand-in vscode module), then the protocol against the lua_tests example's runner.
if(NOT CMAKE_CROSSCOMPILING)
    find_program(RHP_NODE node)
    if(RHP_NODE)
        add_test(NAME vscode.unit
            COMMAND "${RHP_NODE}" --test test/protocol.test.js test/extension.test.js
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/clients/vscode")
        set_tests_properties(vscode.unit PROPERTIES LABELS "vscode;process" TIMEOUT 120)
        if(RHP_ENABLE AND RHP_BUILD_EXAMPLES)
            add_test(NAME vscode.protocol
                COMMAND "${RHP_NODE}" --test test/runner.test.js
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/clients/vscode")
            set_tests_properties(vscode.protocol PROPERTIES
                ENVIRONMENT "RHP_TEST_RUNNER=$<TARGET_FILE:lua_tests_example>;RHP_TEST_EXAMPLE=${PROJECT_SOURCE_DIR}/Examples/lua_tests"
                LABELS "vscode;process" TIMEOUT 120)
        endif()
    endif()
endif()

# Public headers stay ASCII: a compiler reading them in another code page (MSVC without /utf-8 on
# a CJK system, with /WX) must not trip over a comment.
add_test(NAME hygiene.ascii_headers
    COMMAND ${CMAKE_COMMAND} -DROOT=${PROJECT_SOURCE_DIR}/Src -DGENERATED=${RHP_GENERATED_INCLUDE_DIR} -P "${CMAKE_CURRENT_SOURCE_DIR}/hygiene/check_ascii.cmake")
set_tests_properties(hygiene.ascii_headers PROPERTIES LABELS hygiene)

# The package: install this build, then build and run Tests/package against the installed tree
# with a fresh CMake project (find_package(rhp)). Skipped where the result couldn't run here
# (cross builds) or would mix runtimes (sanitizers, libFuzzer instrumentation).
if(RHP_INSTALL AND NOT CMAKE_CROSSCOMPILING AND NOT RHP_SANITIZE AND NOT RHP_FUZZ)
    set(rhp_package_prefix "${CMAKE_BINARY_DIR}/package/prefix-$<CONFIG>")
    add_test(NAME package.install
        COMMAND ${CMAKE_COMMAND} --install "${CMAKE_BINARY_DIR}" --config $<CONFIG> --prefix "${rhp_package_prefix}" --component development)
    set_tests_properties(package.install PROPERTIES FIXTURES_SETUP rhp_package LABELS package)

    set(rhp_package_options
        "-DCMAKE_BUILD_TYPE=$<CONFIG>"
        "-DCMAKE_PREFIX_PATH=${rhp_package_prefix}"
        "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
    )
    if(CMAKE_C_COMPILER)
        list(APPEND rhp_package_options "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
    endif()
    if(CMAKE_OSX_ARCHITECTURES)
        list(APPEND rhp_package_options "-DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}")
    endif()
    if(CMAKE_GENERATOR MATCHES "Ninja")
        set(rhp_package_generator Ninja) # single-config: CMAKE_BUILD_TYPE picks the runtime
        list(APPEND rhp_package_options "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}")
    else()
        set(rhp_package_generator "${CMAKE_GENERATOR}")
    endif()
    add_test(NAME package.find_package
        COMMAND ${CMAKE_CTEST_COMMAND}
            --build-and-test "${CMAKE_CURRENT_SOURCE_DIR}/package" "${CMAKE_BINARY_DIR}/package/consumer-$<CONFIG>"
            --build-generator "${rhp_package_generator}"
            --build-config $<CONFIG>
            --build-noclean
            --build-options ${rhp_package_options}
            --test-command ${CMAKE_CTEST_COMMAND} -C $<CONFIG> --output-on-failure)
    set_tests_properties(package.find_package PROPERTIES FIXTURES_REQUIRED rhp_package LABELS package TIMEOUT 900)
endif()
