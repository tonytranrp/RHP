# Host <-> client over real transports (loopback and TCP on 127.0.0.1). Needs the live engine.
rhp_add_test_suite(rhp_integration_tests
    SOURCES
        host_client_tests.cpp
        stage4_tests.cpp
        stage5_tests.cpp
        stage6_tests.cpp
        stage6_fleet_tests.cpp
        stage7_tests.cpp
        stage9_tests.cpp
        stage10_tests.cpp
        stage11_tests.cpp
        stage13_hardening_tests.cpp
        stage13_network_tests.cpp
        stage13_limits_tests.cpp
        stage13_trust_tests.cpp
        stage13_certified_tests.cpp
        stage13_scopes_tests.cpp
    LINKS
        Rhp::host
        Rhp::client
        Rhp::audit
        Rhp::session
        Rhp::tls
        Rhp::release
)

# RHP_UNITY_BUILD: the integration tests' fixture namespaces share names (keys, eventually, ...).
set_target_properties(rhp_integration_tests PROPERTIES UNITY_BUILD OFF)
