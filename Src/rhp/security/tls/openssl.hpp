#pragma once

#include <memory>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/security/tls/tls.hpp>

namespace Rhp::security::tls {

// TLS 1.3 through the system's OpenSSL (3.0 or newer, found by CMake). Built only where CMake found
// OpenSSL (RHP_TLS_HAS_OPENSSL); elsewhere both factories report kDisabled.
struct openssl {
    static constexpr std::string_view name = "openssl";

    static result<std::shared_ptr<context>> server(const settings& s);
    static result<std::shared_ptr<context>> client(const settings& s);
};

static_assert(backend<openssl>);

} // namespace Rhp::security::tls
