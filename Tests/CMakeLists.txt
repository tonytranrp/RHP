include(Catch)

# rhp_add_test_suite(<name> SOURCES <files...> LINKS <targets...>)
# One executable per module; every TEST_CASE is registered with ctest individually.
function(rhp_add_test_suite name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "SOURCES;LINKS")
    add_executable(${name} ${arg_SOURCES})
    target_link_libraries(${name} PRIVATE ${arg_LINKS} Catch2::Catch2WithMain)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/support")
    rhp_set_warnings(${name})
    set_target_properties(${name} PROPERTIES FOLDER "tests")
    catch_discover_tests(${name} TEST_PREFIX "${name}." DISCOVERY_MODE PRE_TEST)
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
endif()
if(RHP_ENABLE AND RHP_BUILD_TOOLS)
    add_subdirectory(tools)
endif()
