rhp_add_test_suite(rhp_utils_tests
    SOURCES
        utils/byte_buffer_tests.cpp
        utils/crc32c_tests.cpp
        utils/fixed_string_tests.cpp
        utils/function_traits_tests.cpp
        utils/scope_guard_tests.cpp
        utils/spsc_ring_tests.cpp
        utils/type_list_tests.cpp
        utils/units_tests.cpp
    LINKS
        Rhp::utils
)

rhp_add_test_suite(rhp_core_tests
    SOURCES
        core/async_tests.cpp
        core/convert_tests.cpp
        core/error_tests.cpp
        core/errors_mode_tests.cpp
        core/ids_tests.cpp
        core/listener_table_tests.cpp
        core/log_tests.cpp
        core/value_tests.cpp
    LINKS
        Rhp::core
)

rhp_add_test_suite(rhp_platform_tests
    SOURCES
        platform/platform_tests.cpp
    LINKS
        Rhp::platform
)

rhp_add_test_suite(rhp_wire_tests
    SOURCES
        wire/cross_language_tests.cpp
        wire/frame_tests.cpp
        wire/messages_tests.cpp
        wire/msgpack_tests.cpp
    LINKS
        Rhp::wire
)

rhp_add_test_suite(rhp_config_tests
    SOURCES
        config/config_tests.cpp
    LINKS
        Rhp::config
)
# What CMake decided, to compare with what a config user sees (the macros arrive through Rhp::config).
target_compile_definitions(rhp_config_tests PRIVATE
    RHP_TEST_EXPECT_TLS_OPENSSL=${RHP_BUILD_CONFIG_TLS_HAS_OPENSSL}
    RHP_TEST_EXPECT_TLS_MBEDTLS=${RHP_BUILD_CONFIG_TLS_HAS_MBEDTLS}
)

rhp_add_test_suite(rhp_event_tests
    SOURCES
        event/event_tests.cpp
    LINKS
        Rhp::audit
)

rhp_add_test_suite(rhp_client_tests
    SOURCES
        client/pending_tests.cpp
    LINKS
        Rhp::client
)

if(RHP_ENABLE)
    rhp_add_test_suite(rhp_security_tests
        SOURCES
            security/key_tests.cpp
            security/psk_tests.cpp
            security/signing_tests.cpp
            security/tls_tests.cpp
            security/http_auth_tests.cpp
        LINKS
            Rhp::security
            Rhp::tls
    )

    rhp_add_test_suite(rhp_net_tests
        SOURCES
            net/loopback_tests.cpp
            net/tcp_tests.cpp
            net/http_tests.cpp
            net/websocket_tests.cpp
            net/udp_reliable_tests.cpp
            net/local_ipc_tests.cpp
            net/mdns_tests.cpp
            net/datagram_relay.cpp
        LINKS
            Rhp::net
            Rhp::asio
    )

    rhp_add_test_suite(rhp_session_tests
        SOURCES
            session/session_tests.cpp
        LINKS
            Rhp::session
    )

    rhp_add_test_suite(rhp_release_tests
        SOURCES
            release/codec_tests.cpp
            release/manager_tests.cpp
        LINKS
            Rhp::release
    )
else()
    # RHP_ENABLE=OFF: keys, the keyring and signer files still build (a disabled host takes them);
    # signing reports kDisabled; host and client are inert.
    rhp_add_test_suite(rhp_security_tests
        SOURCES
            security/key_tests.cpp
            security/signing_disabled_tests.cpp
        LINKS
            Rhp::security
    )

    rhp_add_test_suite(rhp_host_tests
        SOURCES
            host/disabled_tests.cpp
        LINKS
            Rhp::host
            Rhp::client
    )
endif()

if(RHP_ENABLE)
    rhp_add_test_suite(rhp_script_tests
        SOURCES
            script/async_tests.cpp
            script/binding_tests.cpp
            script/event_tests.cpp
            script/handler_error_tests.cpp
            script/ledger_tests.cpp
            script/lib_tests.cpp
            script/limits_tests.cpp
            script/method_tests.cpp
            script/patch_point_tests.cpp
            script/reload_tests.cpp
            script/require_tests.cpp
            script/sandbox_tests.cpp
            script/schedule_tests.cpp
            script/scheduler_tests.cpp
            script/script_event_tests.cpp
            script/stubs_tests.cpp
            script/task_tests.cpp
            script/testing_tests.cpp
            script/tools_tests.cpp
        LINKS
            Rhp::script
            Rhp::lua # testing_tests compares the meter with a plain Lua state
    )
else()
    # RHP_ENABLE=OFF: no Lua; checks the inert sandbox and direct-call patch points instead.
    rhp_add_test_suite(rhp_script_tests
        SOURCES
            script/disabled_tests.cpp
            script/ledger_tests.cpp
            script/lib_tests.cpp
            script/stubs_tests.cpp
        LINKS
            Rhp::script
    )
endif()

if(RHP_ENABLE)
    rhp_add_test_suite(rhp_test_tests
        SOURCES
            test/runner_tests.cpp
        LINKS
            Rhp::test
    )
    target_compile_definitions(rhp_test_tests PRIVATE RHP_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures")
endif()
