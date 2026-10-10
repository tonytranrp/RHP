# Host <-> client over real transports (loopback and TCP on 127.0.0.1). Needs the live engine.
rhp_add_test_suite(rhp_integration_tests
    SOURCES
        host_client_tests.cpp
        stage4_tests.cpp
        stage5_tests.cpp
        stage6_tests.cpp
    LINKS
        Rhp::host
        Rhp::client
        Rhp::audit
        Rhp::session
        Rhp::tls
)
