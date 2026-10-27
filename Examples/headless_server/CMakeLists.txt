add_executable(headless_server main.cpp)
target_link_libraries(headless_server PRIVATE Rhp::rhp)
set_target_properties(headless_server PROPERTIES FOLDER "examples")
