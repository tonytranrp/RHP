add_subdirectory(hello_console)
add_subdirectory(frame_loop)
add_subdirectory(remote_exec)
add_subdirectory(custom_transport)
add_subdirectory(headless_server)
add_subdirectory(lua_tests)

# The examples share a precompiled header in RHP's own build (cmake/RhpPch.cmake); each example's
# CMakeLists stays plain.
foreach(example IN ITEMS hello_console frame_loop remote_exec custom_transport headless_server lua_tests_example)
    rhp_use_shared_pch(${example} apps)
endforeach()
