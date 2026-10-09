add_executable(custom_transport main.cpp)
target_link_libraries(custom_transport PRIVATE Rhp::rhp)
rhp_set_warnings(custom_transport)
set_target_properties(custom_transport PROPERTIES FOLDER "examples")

# The example needs the live engine; with RHP_ENABLE=OFF it builds but would only report kDisabled.
if(RHP_BUILD_TESTS AND RHP_ENABLE)
    add_test(NAME example.custom_transport COMMAND custom_transport)
endif()
