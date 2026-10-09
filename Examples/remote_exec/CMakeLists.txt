add_executable(remote_exec main.cpp)
target_link_libraries(remote_exec PRIVATE Rhp::rhp)
rhp_set_warnings(remote_exec)
target_compile_definitions(remote_exec PRIVATE RHP_REMOTE_SCRIPTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/scripts")
set_target_properties(remote_exec PROPERTIES FOLDER "examples")

# The example needs the live engine; with RHP_ENABLE=OFF it builds but would only report kDisabled.
if(RHP_BUILD_TESTS AND RHP_ENABLE)
    add_test(NAME example.remote_exec COMMAND remote_exec)
    set_tests_properties(example.remote_exec PROPERTIES TIMEOUT 120)
endif()
