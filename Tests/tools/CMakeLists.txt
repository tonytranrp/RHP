# rhp-cli: its helpers and command shell in-process (over loopback), then the real rhp-cli and
# headless_server binaries talking over TCP on 127.0.0.1.
rhp_add_test_suite(rhp_cli_tests
    SOURCES
        rhp_cli_tests.cpp
    LINKS
        rhp_cli_core
)
if(RHP_BUILD_EXAMPLES)
    target_compile_definitions(rhp_cli_tests PRIVATE
        RHP_CLI_EXE="$<TARGET_FILE:rhp-cli>"
        RHP_HEADLESS_EXE="$<TARGET_FILE:headless_server>"
    )
    add_dependencies(rhp_cli_tests rhp-cli headless_server)
endif()
