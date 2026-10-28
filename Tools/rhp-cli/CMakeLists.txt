# rhp-cli: REPL and scripting client. rhp_cli_core holds everything but the terminal front-end
# (text helpers, the command shell) so the tests can drive it in-process.
add_library(rhp_cli_core STATIC src/text.cpp src/release_files.cpp src/dev.cpp)
target_sources(rhp_cli_core PUBLIC
    FILE_SET HEADERS
    BASE_DIRS src
    FILES src/cli_auth.hpp src/cli_signer.hpp src/text.hpp src/shell.hpp src/release_files.hpp src/json.hpp src/dap.hpp src/dev.hpp
)
target_link_libraries(rhp_cli_core PUBLIC Rhp::rhp)
target_compile_features(rhp_cli_core PUBLIC cxx_std_23)
rhp_set_warnings(rhp_cli_core)
set_target_properties(rhp_cli_core PROPERTIES FOLDER "tools")

add_executable(rhp-cli
    src/main.cpp
    src/commands.hpp
    src/connection.cpp
    src/connection.hpp
    src/certs.cpp
    src/fleet.cpp
    src/keys.cpp
    src/releases.cpp
    src/test_command.cpp
    src/trust.cpp
)
target_link_libraries(rhp-cli PRIVATE rhp_cli_core Rhp::cli11 Rhp::replxx)
rhp_set_warnings(rhp-cli)
# main.cpp instantiates the client and shell for every credential and transport the CLI speaks: as a
# unity file that is more sections than an MSVC object holds by default (C1128).
if(MSVC)
    target_compile_options(rhp-cli PRIVATE /bigobj)
endif()
rhp_use_shared_pch(rhp-cli apps)
set_target_properties(rhp-cli PROPERTIES FOLDER "tools")

if(RHP_INSTALL)
    install(TARGETS rhp-cli RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT tools)
endif()
