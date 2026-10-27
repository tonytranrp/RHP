# Lua tests of a game's scripts: a test executable with the game's own lib, and ctest tests for
# each spec file (rhp_add_lua_tests, cmake/RhpLuaTests.cmake).
add_executable(lua_tests_example lua_tests_main.cpp)
target_link_libraries(lua_tests_example PRIVATE Rhp::rhp)
set_target_properties(lua_tests_example PROPERTIES FOLDER "examples")

if(RHP_BUILD_TESTS AND RHP_ENABLE)
    rhp_add_lua_tests(example.lua_tests
        TARGET lua_tests_example
        SCRIPTS scripts
        FILES tests/rules_spec.lua tests/sales_spec.lua
        JUNIT
    )
endif()
