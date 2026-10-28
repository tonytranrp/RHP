rhp_add_test_suite(rhp_utils_tests
    SOURCES
        utils/byte_buffer_tests.cpp
        utils/crc32c_tests.cpp
        utils/fixed_string_tests.cpp
        utils/function_traits_tests.cpp
        utils/scope_guard_tests.cpp
        utils/siphash_tests.cpp
        utils/spsc_ring_tests.cpp
        utils/type_list_tests.cpp
        utils/units_tests.cpp
        utils/utf8_tests.cpp
    LINKS
        Rhp::utils
)

rhp_add_test_suite(rhp_core_tests
    SOURCES
        core/async_tests.cpp
        core/convert_tests.cpp
        core/error_tests.cpp
        core/errors_mode_tests.cpp
        core/hardening_tests.cpp
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
            security/key_file_tests.cpp
            security/key_tests.cpp
            security/psk_tests.cpp
            security/signing_tests.cpp
            security/tls_tests.cpp
            security/http_auth_tests.cpp
        LINKS
            Rhp::security
            Rhp::tls
    )

    # The relay is the suite's only Asio code: it compiles apart, so the rest of the suite shares the
    # tests' precompiled header (Asio's macros would change what its standard headers mean).
    add_library(rhp_test_datagram_relay OBJECT net/datagram_relay.cpp)
    target_link_libraries(rhp_test_datagram_relay PRIVATE Rhp::net Rhp::asio)
    target_include_directories(rhp_test_datagram_relay PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../support")
    rhp_set_warnings(rhp_test_datagram_relay)
    set_target_properties(rhp_test_datagram_relay PROPERTIES FOLDER "tests")

    rhp_add_test_suite(rhp_net_tests
        SOURCES
            net/address_tests.cpp
            net/loopback_tests.cpp
            net/tcp_tests.cpp
            net/http_tests.cpp
            net/websocket_tests.cpp
            net/udp_reliable_tests.cpp
            net/local_ipc_tests.cpp
            net/mdns_tests.cpp
            $<TARGET_OBJECTS:rhp_test_datagram_relay>
        LINKS
            Rhp::net
    )

    rhp_add_test_suite(rhp_session_tests
        SOURCES
            session/admission_tests.cpp
            session/channel_policy_tests.cpp
            session/session_tests.cpp
        LINKS
            Rhp::session
    )

    rhp_add_test_suite(rhp_release_tests
        SOURCES
            release/bytecode_tests.cpp
            release/codec_tests.cpp
            release/manager_tests.cpp
        LINKS
            Rhp::release
    )
    # RHP_UNITY_BUILD: the bytecode cache tests reuse manager_tests.cpp's fixture names.
    set_source_files_properties(release/bytecode_tests.cpp PROPERTIES SKIP_UNITY_BUILD_INCLUSION ON)
else()
    # RHP_ENABLE=OFF: keys, the keyring and signer files still build (a disabled host takes them);
    # signing reports kDisabled; host and client are inert.
    rhp_add_test_suite(rhp_security_tests
        SOURCES
            security/key_file_tests.cpp
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
            script/allocator_tests.cpp
            script/async_tests.cpp
            script/binding_tests.cpp
            script/bytecode_tests.cpp
            script/event_tests.cpp
            script/handler_error_tests.cpp
            script/ledger_tests.cpp
            script/lib_tests.cpp
            script/limits_tests.cpp
            script/method_tests.cpp
            script/patch_point_tests.cpp
            script/reload_tests.cpp
            script/request_tests.cpp
            script/require_tests.cpp
            script/sandbox_tests.cpp
            script/schedule_tests.cpp
            script/scheduler_tests.cpp
            script/script_event_tests.cpp
            script/stubs_tests.cpp
            script/task_tests.cpp
            script/testing_tests.cpp
            script/tools_tests.cpp
            script/view_tests.cpp
            script/yield_tests.cpp
        LINKS
            Rhp::script
            Rhp::lua # testing_tests compares the meter with a plain Lua state
    )
    # x64 MSVC: the yield tests again in an executable linked /CETCOMPAT. On a CPU with CET the
    # process runs with a shadow stack, where coroutine yields must throw instead of jumping.
    if(MSVC AND CMAKE_CXX_COMPILER_ARCHITECTURE_ID MATCHES "^(x64|X64|AMD64|x86_64)$" AND NOT RHP_SANITIZE)
        rhp_add_test_suite(rhp_script_cet_tests SOURCES script/yield_tests.cpp LINKS Rhp::script)
        target_link_options(rhp_script_cet_tests PRIVATE /CETCOMPAT)
    endif()
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

# Rhp::test: Lua fixture specs with known outcomes through the runner (with RHP_ENABLE=OFF, what
# still works without Lua).
if(RHP_ENABLE)
    set(rhp_test_test_sources test/runner_tests.cpp)
else()
    set(rhp_test_test_sources test/disabled_tests.cpp)
endif()
# The fixtures are also embedded, for devices that can't read the source tree (Android).
include(RhpEmbed)
set(rhp_test_fixture_files
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/scripts/game/combat.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/scripts/game/util.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/abort_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/assert_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/basics_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/broken_describe_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/clock_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/coverage_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/dsl_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/dup_snapshot_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/expect_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/fake_cpp_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/fakes_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/fuzz_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/isolation_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/measure_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/only_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/property_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/select_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/snapshot_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/spy_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/syntax_error_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/timeout_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures/specs/views_fakes_spec.lua"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/golden/basics.github"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/golden/basics.jsonl"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/golden/basics.junit.xml"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/golden/basics.tap"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/golden/basics.txt"
)
set(rhp_test_fixtures_cpp "${CMAKE_CURRENT_BINARY_DIR}/rhp_test_fixtures.cpp")
rhp_embed_text("${rhp_test_fixtures_cpp}"
    NAMESPACE rhp_test_fixtures
    FUNCTION fixture_files
    HEADER embedded_fixtures.hpp
    BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/test"
    FILES ${rhp_test_fixture_files}
)
rhp_add_test_suite(rhp_test_tests
    SOURCES
        ${rhp_test_test_sources}
        "${rhp_test_fixtures_cpp}"
    LINKS
        Rhp::test
)
target_include_directories(rhp_test_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/test")
target_compile_definitions(rhp_test_tests PRIVATE RHP_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/test/fixtures")

# RHP_UNITY_BUILD: the script tests alias their fixture namespaces with the same names (fx).
set_target_properties(rhp_script_tests PROPERTIES UNITY_BUILD OFF)
