# Layer 3: TLS 1.3 engines (sans-IO) behind Rhp::security::tls::backend. OpenSSL and Mbed TLS are
# PRIVATE: only openssl.cpp / mbedtls.cpp include their headers. Which backends exist is public
# (RHP_TLS_HAS_OPENSSL / RHP_TLS_HAS_MBEDTLS), so auto_backend means the same everywhere.
# unavailable.cpp gives the missing backends factories that report kDisabled.
set(rhp_tls_sources unavailable.cpp)
set(rhp_tls_private_deps "")
if(RHP_ENABLE AND RHP_TLS_HAS_OPENSSL)
    list(APPEND rhp_tls_sources openssl.cpp)
    list(APPEND rhp_tls_private_deps OpenSSL::SSL OpenSSL::Crypto)
endif()
if(RHP_ENABLE AND RHP_TLS_HAS_MBEDTLS)
    list(APPEND rhp_tls_sources mbedtls.cpp)
    list(APPEND rhp_tls_private_deps Rhp::mbedtls)
endif()

rhp_add_module(tls
    HEADERS
        auto_backend.hpp
        mbedtls.hpp
        openssl.hpp
        tls.hpp
    SOURCES
        ${rhp_tls_sources}
    DEPS
        Rhp::core
        Rhp::platform
    PRIVATE_DEPS
        ${rhp_tls_private_deps}
)

if(RHP_ENABLE AND RHP_TLS_HAS_OPENSSL)
    target_compile_definitions(rhp_tls PUBLIC RHP_TLS_HAS_OPENSSL=1)
else()
    target_compile_definitions(rhp_tls PUBLIC RHP_TLS_HAS_OPENSSL=0)
endif()
if(RHP_ENABLE AND RHP_TLS_HAS_MBEDTLS)
    target_compile_definitions(rhp_tls PUBLIC RHP_TLS_HAS_MBEDTLS=1)
else()
    target_compile_definitions(rhp_tls PUBLIC RHP_TLS_HAS_MBEDTLS=0)
endif()
