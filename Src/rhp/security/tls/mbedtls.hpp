#pragma once

#include <memory>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/security/tls/tls.hpp>

namespace Rhp::security::tls {

// TLS 1.3 through Mbed TLS 4 (fetched by CPM; the mobile backend, and the desktop fallback where
// no OpenSSL is installed). Built when RHP_TLS_HAS_MBEDTLS; elsewhere both factories report
// kDisabled. Every call into Mbed TLS takes one process-wide lock (its PSA core is not thread-safe
// in the default configuration).
struct mbedtls {
    static constexpr std::string_view name = "mbedtls";

    static result<std::shared_ptr<context>> server(const settings& s);
    static result<std::shared_ptr<context>> client(const settings& s);
};

static_assert(backend<mbedtls>);

} // namespace Rhp::security::tls
