#pragma once

#include <cstddef>
#include <cstdint>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/security/ed25519.hpp>

namespace Rhp::security {

// A public key of a named algorithm ("ed25519" today; "p256" later), as revocations name keys.
struct public_key_ref {
    std::string alg{"ed25519"};
    std::vector<std::byte> pub;

    [[nodiscard]] bool operator==(const public_key_ref&) const = default;
};

[[nodiscard]] public_key_ref key_ref(const ed25519_public_key& k);

// One identity revocation list (decision AL12; signed by the root's revocation role, see
// release/identity_revocations.hpp for the signed document): operator certificates by serial,
// script signer keys and device keys a host must stop trusting. Lists are cumulative: a host keeps
// the union of every list it accepted.
struct identity_revocation_list {
    std::uint64_t seq = 0;                 // >= 1, increasing
    std::uint64_t issued_at = 0;           // Unix seconds (informational)
    std::vector<std::string> cert_serials; // operator certificate serials (a numeric serial is its decimal text)
    std::vector<public_key_ref> signer_keys;
    std::vector<public_key_ref> device_keys;

    [[nodiscard]] bool operator==(const identity_revocation_list&) const = default;
};

// What every identity revocation list a host accepted withdrew, for the certificate and device-key
// checks to ask (a release::manager keeps one: manager::identities()). Only grows, except when the
// manager's recover step drops lists signed by compromised keys (replace). Thread-safe: the
// handshake and signature checks call it from the network thread while the pump thread updates it.
class revoked_identities {
public:
    [[nodiscard]] bool is_revoked_serial(std::string_view serial) const;
    [[nodiscard]] bool is_revoked_signer(std::span<const std::byte> pub, std::string_view alg = "ed25519") const;
    [[nodiscard]] bool is_revoked_signer(const ed25519_public_key& k) const { return is_revoked_signer(k.bytes()); }
    [[nodiscard]] bool is_revoked_device(std::span<const std::byte> pub, std::string_view alg = "ed25519") const;
    [[nodiscard]] bool is_revoked_device(const ed25519_public_key& k) const { return is_revoked_device(k.bytes()); }

    // The newest list merged (0: none).
    [[nodiscard]] std::uint64_t seq() const;
    // Everything withdrawn, as one list (seq: the newest; issued_at 0).
    [[nodiscard]] identity_revocation_list snapshot() const;

    void merge(const identity_revocation_list& list);
    // Replaces everything with the union of `lists`.
    void replace(std::span<const identity_revocation_list> lists);

private:
    static void merge_into(identity_revocation_list& into, const identity_revocation_list& list);

    mutable std::shared_mutex mutex_;
    identity_revocation_list all_;
};

} // namespace Rhp::security
