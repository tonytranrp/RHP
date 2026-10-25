# rhp-cli: REPL and scripting client. rhp_cli_core holds everything but the terminal front-end
# (text helpers, the command shell) so the tests can drive it in-process.
add_library(rhp_cli_core STATIC src/text.cpp src/release_files.cpp src/json.cpp)
target_sources(rhp_cli_core PUBLIC
    FILE_SET HEADERS
    BASE_DIRS src
    FILES src/text.hpp src/shell.hpp src/release_files.hpp src/json.hpp src/dap.hpp
)
target_link_libraries(rhp_cli_core PUBLIC Rhp::rhp)
target_compile_features(rhp_cli_core PUBLIC cxx_std_23)
rhp_set_warnings(rhp_cli_core)
set_target_properties(rhp_cli_core PROPERTIES FOLDER "tools")

add_executable(rhp-cli src/main.cpp)
target_link_libraries(rhp-cli PRIVATE rhp_cli_core Rhp::cli11 Rhp::replxx)
rhp_set_warnings(rhp-cli)
set_target_properties(rhp-cli PROPERTIES FOLDER "tools")

if(RHP_INSTALL)
    install(TARGETS rhp-cli RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT tools)
endif()
