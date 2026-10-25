include_guard(GLOBAL)

# rhp_add_lua_tests(<name>
#     TARGET <executable>        a test executable (Rhp::test::main) with the program's libs, or rhp-cli
#     FILES <specs...>           test files (each is a ctest of its own: <name>.<file stem>)
#     [SCRIPTS <folders...>]     module folders loaded into every test sandbox
#     [ROOT <folder>]            paths in reports are relative to it (default: this CMakeLists' folder)
#     [ARGS <arguments...>]      more runner arguments (--isolation test, --coverage lcov:..., ...)
#     [LABELS <labels...>]       ctest labels (lua is always one)
#     [JUNIT]                    also write <build>/<name>/<file stem>.junit.xml for CI test reports
#     [TIMEOUT <seconds>]        ctest timeout of each file
#     [STORE_SNAPSHOTS])         let ctest store new snapshots (by default it runs with --ci: a missing
#                                snapshot fails instead of being written into the source tree)
#
# Lua test files run as ctest tests through the program's own test executable:
#
#   add_executable(game_lua_tests lua_tests_main.cpp)   # return Rhp::test::main(argc, argv, install);
#   target_link_libraries(game_lua_tests PRIVATE game Rhp::test)
#   rhp_add_lua_tests(game TARGET game_lua_tests SCRIPTS scripts FILES tests/combat_spec.lua tests/ui_spec.lua)
#
# With TARGET rhp-cli (built in this tree) the files run with the `rhp` API only (or the fakes of an
# --api FILE.json in ARGS). Files are listed, never globbed: adding one is a CMake change like a source.
# Two files with the same stem get their folder in the test name too.
function(rhp_add_lua_tests name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "JUNIT;STORE_SNAPSHOTS" "TARGET;ROOT;TIMEOUT" "FILES;SCRIPTS;ARGS;LABELS")
    if(NOT arg_TARGET)
        message(FATAL_ERROR "rhp_add_lua_tests(${name}): TARGET is required (a test executable, or rhp-cli)")
    endif()
    if(NOT arg_FILES)
        message(FATAL_ERROR "rhp_add_lua_tests(${name}): FILES lists no test file")
    endif()
    if(NOT arg_ROOT)
        set(arg_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
    endif()
    cmake_path(ABSOLUTE_PATH arg_ROOT BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)

    # The target's name, not its file: add_test then runs it through CMAKE_CROSSCOMPILING_EMULATOR
    # (the iOS simulator's simctl_run.sh) like any other test executable. Paths given are absolute.
    set(command "${arg_TARGET}")
    if(arg_TARGET STREQUAL "rhp-cli" OR arg_TARGET STREQUAL "Rhp::rhp-cli")
        list(APPEND command test)
    endif()
    set(common --no-color --root "${arg_ROOT}")
    if(NOT arg_STORE_SNAPSHOTS)
        list(APPEND common --ci)
    endif()
    foreach(folder IN LISTS arg_SCRIPTS)
        cmake_path(ABSOLUTE_PATH folder BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)
        list(APPEND common --scripts "${folder}")
    endforeach()

    set(used "")
    foreach(file IN LISTS arg_FILES)
        cmake_path(ABSOLUTE_PATH file BASE_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" NORMALIZE)
        cmake_path(GET file STEM stem)
        string(REGEX REPLACE "[^A-Za-z0-9_]" "_" stem "${stem}")
        if(stem IN_LIST used)
            cmake_path(GET file PARENT_PATH parent)
            cmake_path(GET parent FILENAME folder)
            string(REGEX REPLACE "[^A-Za-z0-9_]" "_" folder "${folder}")
            set(stem "${folder}.${stem}")
        endif()
        list(APPEND used "${stem}")
        set(reports "")
        if(arg_JUNIT)
            set(reports --reporter "junit:${CMAKE_CURRENT_BINARY_DIR}/${name}/${stem}.junit.xml")
        endif()
        add_test(NAME "${name}.${stem}"
            COMMAND ${command} "${file}" ${common} ${reports} ${arg_ARGS}
            WORKING_DIRECTORY "${arg_ROOT}")
        set_tests_properties("${name}.${stem}" PROPERTIES LABELS "lua;${arg_LABELS}")
        if(arg_TIMEOUT)
            set_tests_properties("${name}.${stem}" PROPERTIES TIMEOUT "${arg_TIMEOUT}")
        endif()
    endforeach()
endfunction()
