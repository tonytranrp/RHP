#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/http_auth.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>

namespace Rhp::security {

// A client's PSK identity: the key name and secret it proves.
struct psk_identity {
    std::string name;
    key secret;

    [[nodiscard]] std::unique_ptr<client_handshake> begin() const;
};

// PSK mutual challenge-response with keyed BLAKE2b (Monocypher):
//
//   client -> hello     {key = name, nonce = Nc}
//   host   -> challenge {nonce = Nh, proof = MAC(psk, "rhp/host"   || T)}     T = name || Nc || Nh
//   client -> response  {proof = MAC(psk, "rhp/client" || T)}                  (after checking the host's proof)
//   frame keys: MAC(psk, "rhp/c2h" || T) and MAC(psk, "rhp/h2c" || T), 32 bytes each
//
// Under TLS, T also ends with the connection's channel binding (tls-exporter): both ends of one
// TLS connection share it, a relay with two TLS connections has two, so its proofs never match.
//
// Every frame after the handshake carries a 32-byte keyed-BLAKE2b MAC under its direction's key.
class psk_keyring {
public:
    using credential = psk_identity;

    psk_keyring() : keys_(std::make_shared<const keyring>()) {}
    psk_keyring(keyring keys) : keys_(std::make_shared<const keyring>(std::move(keys))) {}

    [[nodiscard]] std::unique_ptr<host_handshake> begin() const;
    [[nodiscard]] const keyring& keys() const noexcept { return *keys_; }
    // Per-request HTTP proofs against the same keys (Rhp::security::http_authenticator).
    [[nodiscard]] result<http_grant> verify_http(const http_proof& request, std::chrono::system_clock::time_point now) const {
        return verify_http_authorization(*keys_, request, now);
    }

private:
    std::shared_ptr<const keyring> keys_;
};

static_assert(authenticator<psk_keyring>);
static_assert(http_authenticator<psk_keyring>);

} // namespace Rhp::security
