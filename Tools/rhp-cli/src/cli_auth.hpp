#pragma once

// rhp-cli's authenticator policy: one client type whose credential is a PSK identity or a device key
// (security::device_keys), as cli_signer is one for its two kinds of signing key. rhp-cli never
// hosts, so the host side is only there to satisfy the concept.

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <rhp/security/authenticator.hpp>
#include <rhp/security/device_keys.hpp>
#include <rhp/security/psk_keyring.hpp>

namespace rhp_cli {

struct cli_auth {
    class credential {
    public:
        // Implicit: everything that took an identity_file::credential() keeps working.
        credential(Rhp::security::psk_identity id) : name(id.name), begin_(wrap(std::move(id))) {}
        credential(Rhp::security::device_credential id) : name(id.name), begin_(wrap(std::move(id))) {}

        // The identity's name (certified claims name it; Rhp::client reads it).
        std::string name;

        [[nodiscard]] std::unique_ptr<Rhp::security::client_handshake> begin() const { return begin_(); }

    private:
        using begin_fn = std::function<std::unique_ptr<Rhp::security::client_handshake>()>;

        template <Rhp::security::credential C>
        static begin_fn wrap(C c) {
            return [c = std::move(c)] { return c.begin(); };
        }

        begin_fn begin_;
    };

    [[nodiscard]] std::unique_ptr<Rhp::security::host_handshake> begin() const { return Rhp::security::psk_keyring{}.begin(); }
};

static_assert(Rhp::security::authenticator<cli_auth>);

} // namespace rhp_cli
