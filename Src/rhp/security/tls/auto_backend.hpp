#pragma once

#include <rhp/build_config.hpp>
#include <rhp/security/tls/mbedtls.hpp>
#include <rhp/security/tls/openssl.hpp>
#include <rhp/security/tls/tls.hpp>

namespace Rhp::security::tls {

// The default TLS backend: OpenSSL where CMake found it (desktop), Mbed TLS otherwise (iOS,
// Android, Windows without OpenSSL), nothing when built with RHP_WITH_TLS=OFF.
#if RHP_TLS_HAS_OPENSSL
using auto_backend = openssl;
#elif RHP_TLS_HAS_MBEDTLS
using auto_backend = mbedtls;
#else
using auto_backend = none;
#endif

} // namespace Rhp::security::tls
