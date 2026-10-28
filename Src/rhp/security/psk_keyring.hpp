#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <utility>

#include <rhp/core/result.hpp>
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
//   host   -> challenge {nonce = Nh, proof = MAC(psk, "rhp/host"   || T)}     T = len || name || Nc || Nh
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

    // A copy that also accepts `entry` (kAlreadyLoaded when its name is taken); this one is unchanged.
    [[nodiscard]] result<psk_keyring> with(keyring_entry entry) const {
        keyring more = *keys_;
        if (auto added = more.add(std::move(entry)); !added) {
            return std::unexpected{std::move(added).error()};
        }
        return psk_keyring{std::move(more)};
    }

    // A copy that leaves out the keys tagged `env` (Rhp::host: dev keys at production hardening).
    [[nodiscard]] psk_keyring without(key_env env) const { return psk_keyring{keys_->without(env)}; }

    [[nodiscard]] std::unique_ptr<host_handshake> begin() const;
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
