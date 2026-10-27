add_executable(hello_console main.cpp)
target_link_libraries(hello_console PRIVATE Rhp::rhp)
target_compile_definitions(hello_console PRIVATE RHP_HELLO_SCRIPTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/scripts")
set_target_properties(hello_console PROPERTIES FOLDER "examples")

# The example needs the live engine; with RHP_ENABLE=OFF it builds but would only report kDisabled.
if(RHP_BUILD_TESTS AND RHP_ENABLE)
    add_test(NAME example.hello_console COMMAND hello_console)
endif()
