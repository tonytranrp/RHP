#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/known_hosts.hpp>

namespace Rhp::security {

// One device a host accepts (decision AL10): its name is the identity (one lua_State per identity),
// its role and scopes what it may do and reach, its public key what it proves.
struct device_entry {
    std::string name{};
    role granted = role::kObserve;
    key_algorithm alg = key_algorithm::kEd25519;
    std::vector<std::byte> public_key{};
    scope_set scopes{};
    std::optional<key_env> env; // the `env=` tag (decision AL11); none for an untagged line
};

// The host's device allow-list: public keys only, so the file holds nothing secret. Names and keys
// are unique (add() fails with kAlreadyLoaded on a duplicate of either).
class device_allow_list {
public:
    device_allow_list() = default;

    result<void> add(device_entry entry);

    // Text with one `name role alg base64-public-key [scopes] [env=dev|prod]` per line (role: observe,
    // patch or admin; alg: ed25519 or p256; scopes: comma-separated scope patterns, Rhp::scope_set,
    // everything when left out; '#' starts a comment), e.g. what `rhp-cli keygen --device` prints.
    [[nodiscard]] static result<device_allow_list> parse(std::string_view text);
    [[nodiscard]] static result<device_allow_list> from_file(const std::string& path);
    // The text parse() reads back (for an app that enrolls devices and keeps the file).
    [[nodiscard]] std::string to_text() const;

    [[nodiscard]] const device_entry* find(std::string_view name) const noexcept;
    [[nodiscard]] const device_entry* find(key_algorithm alg, std::span<const std::byte> public_key) const noexcept;
    // The `env=` tag of a device (nullopt for an untagged or unknown name), as keyring::env_of.
    [[nodiscard]] std::optional<key_env> env_of(std::string_view name) const noexcept;
    // A copy without the entries tagged `env` (a production host leaves out dev keys: Rhp::host).
    [[nodiscard]] device_allow_list without(key_env env) const;

    [[nodiscard]] std::span<const device_entry> entries() const noexcept { return entries_; }
    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    // What from_file noticed that isn't fatal (a file other users can write to or read).
    [[nodiscard]] const std::vector<std::string>& warnings() const noexcept { return warnings_; }

private:
    std::vector<device_entry> entries_;
    std::vector<std::string> warnings_;
};

// A client's device identity: its key, the host keys it trusts, and what to do about a host it has
// never seen.
struct device_credential {
    // Trust on first use: asked with the endpoint and the host key's fingerprint (key_fingerprint)
    // when `pins` has no key for the endpoint, after the host proved it holds that key. True pins it
    // (known_hosts::add; a file-backed set writes it down) and goes on. Runs on the client's network
    // thread inside the handshake, which the host drops after limits.handshake_timeout_ms: don't wait
    // for a person here (rhp-cli refuses, asks, and connects again).
    using trust_function = std::function<bool(std::string_view endpoint, std::string_view fingerprint)>;

    // The client's own name for itself (an identity file's `name`): what certified script claims
    // carry. The host names the session from its allow-list entry.
    std::string name{};
    key_handle key{};
    known_hosts pins{};
    // The name the host is pinned under in `pins` ("192.168.1.5:7777").
    std::string endpoint{};
    // Empty: an endpoint without pins is refused.
    trust_function trust_new{};

    [[nodiscard]] std::unique_ptr<client_handshake> begin() const;
};

// Device-key mutual authentication (decision AL10), a config<>::auth<> policy:
//
//   client -> hello     {scheme = "device", alg, pub, nonce = Nc}
//   host   -> challenge {nonce = Nh, alg, pub, sig = sign(host key, "rhp/device/host\0" || T)}
//   client -> response  {sig = sign(client key, "rhp/device/client\0" || T)}   (after checking the
//                        host's signature, then its key against the pins or trust on first use)
//   T = the length-prefixed (u32 little-endian) client alg name, client public key, Nc, Nh, host
//       alg name, host public key, channel binding
//   frame keys: keyed BLAKE2b-256 with the channel binding as key over "rhp/c2h" || T / "rhp/h2c" || T
//
// TLS is required: with an empty channel binding (plaintext) both sides fail with kAuth ("device keys
// need TLS"). An unlisted or revoked client key still gets a challenge and fails at verify (kAuth), so
// a client can't probe the list. The grant carries the entry's name, role and scopes; the host's
// welcome carries its key's fingerprint.
//
// Revocation: a key that `revoked` names (release::manager::identities(): the identity revocation
// lists the host accepted) is refused like an unlisted one, checked at every handshake.
class device_keys {
public:
    using credential = device_credential;

    device_keys(device_allow_list allowed, key_handle host_key, std::shared_ptr<const revoked_identities> revoked = {})
        : allowed_(std::make_shared<const device_allow_list>(std::move(allowed))), host_(std::move(host_key)), revoked_(std::move(revoked)) {}

    [[nodiscard]] std::unique_ptr<host_handshake> begin() const;

    // A copy that leaves out the devices tagged `env` (Rhp::host: dev keys at production hardening).
    [[nodiscard]] device_keys without(key_env env) const { return {allowed_->without(env), host_, revoked_}; }

    [[nodiscard]] const device_allow_list& allowed() const noexcept { return *allowed_; }
    [[nodiscard]] const key_handle& host_key() const noexcept { return host_; }

private:
    std::shared_ptr<const device_allow_list> allowed_;
    key_handle host_;
    std::shared_ptr<const revoked_identities> revoked_;
};

static_assert(authenticator<device_keys>);

} // namespace Rhp::security
