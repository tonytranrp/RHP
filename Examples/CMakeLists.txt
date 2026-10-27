add_subdirectory(hello_console)
add_subdirectory(frame_loop)
add_subdirectory(remote_exec)
add_subdirectory(custom_transport)
add_subdirectory(headless_server)
add_subdirectory(lua_tests)

# RHP's warning set and, in RHP's own build, a shared precompiled header (cmake/RhpPch.cmake): both are
# RHP-internal helpers the installed package doesn't have, so each example's CMakeLists stays plain
# enough to copy into a project that uses find_package(rhp).
foreach(example IN ITEMS hello_console frame_loop remote_exec custom_transport headless_server lua_tests_example)
    rhp_set_warnings(${example})
    rhp_use_shared_pch(${example} apps)
endforeach()
