add_executable(frame_loop main.cpp)
target_link_libraries(frame_loop PRIVATE Rhp::rhp)
rhp_set_warnings(frame_loop)
target_compile_definitions(frame_loop PRIVATE RHP_FRAME_LOOP_SCRIPTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/scripts"
                                              RHP_FRAME_LOOP_OUT_DIR="${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(frame_loop PROPERTIES FOLDER "examples")

# The example needs the live engine; with RHP_ENABLE=OFF it builds but would only report kDisabled.
if(RHP_BUILD_TESTS AND RHP_ENABLE)
    add_test(NAME example.frame_loop COMMAND frame_loop)
endif()
