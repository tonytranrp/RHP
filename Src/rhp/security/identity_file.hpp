#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/psk_keyring.hpp>

namespace Rhp::security {

// A developer's identity on disk (`~/.rhp/dev.rhpid`): the key name the host knows, the PSK it
// shares with the host's keyring, and the Ed25519 key that signs scripts. Small TOML-like text:
//
//   name        = "dev"
//   psk         = "base64..."     # shared with the host's keyring
//   signing_key = "base64..."     # Ed25519 private key; the host trusts the public half
//   signer      = "dev"         # optional: the name the host's trusted signers use (default: name)
//
// Treat the file like an SSH private key. Secrets are wiped when the object dies.
struct identity_file {
    // Reads a field the identity doesn't have, for formats built on this one (the dev session file):
    // true when it took it, false for a field it doesn't know either, an error for a bad value.
    using field_reader = std::function<result<bool>(std::string_view field, std::string_view value)>;

    std::string name;
    key psk;
    std::optional<ed25519_secret_key> signing;
    std::string signer; // empty = name
    // What load noticed that isn't fatal: a file other users can read. Callers show them (rhp-cli
    // prints "warning: ..."); to_text leaves them out.
    std::vector<std::string> warnings;

    [[nodiscard]] static result<identity_file> parse(std::string_view text, const field_reader& extra = {});
    [[nodiscard]] static result<identity_file> load(const std::string& path);
    // A new identity with a fresh 32-byte PSK and a fresh signing key.
    [[nodiscard]] static result<identity_file> generate(std::string name);

    [[nodiscard]] std::string to_text() const;
    // Writes to_text() to `path` (replacing it atomically), its owner's alone on every OS
    // (platform::write_private_file).
    result<void> save(const std::string& path) const;

    // What Rhp::client takes.
    [[nodiscard]] psk_identity credential() const { return {name, psk}; }
    [[nodiscard]] std::optional<signing_key> signer_key() const;

    // The lines a host adds to its keyring file and trusted-signers file for this identity.
    [[nodiscard]] std::string keyring_line(role granted) const;
    [[nodiscard]] std::optional<std::string> signers_line() const;
};

} // namespace Rhp::security
