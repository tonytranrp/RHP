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
#include <rhp/security/key_handle.hpp>
#include <rhp/security/key_store.hpp>
#include <rhp/security/psk_keyring.hpp>

namespace Rhp::security {

struct signing_key_file;

// A device key's private half (decision AL10): an Ed25519 seed or a P-256 scalar.
struct device_secret {
    key_algorithm alg = key_algorithm::kEd25519;
    key secret;
};

// A developer's connection identity on disk (`dev.rhpid`): the name the host knows and the PSK it
// shares with the host's keyring, or a device key whose public half is on the host's allow-list.
// Small TOML-like text:
//
//   name        = "dev"
//   psk         = "base64..."     # shared with the host's keyring
//   alg         = "ed25519"       # instead of psk: a device key ("ed25519" or "p256")
//   device_key  = "base64..."     #   its private key (the host lists the public half)
//   env         = "dev"           # optional: "dev" or "prod" (decision AL11)
//
// Since Stage 13b `rhp-cli keygen` keeps the Ed25519 key that signs scripts in a file of its own
// beside it (`dev.rhpsign`, signing_key_file). The combined format from before still reads (and is
// what dev sessions write):
//
//   signing_key = "base64..."     # Ed25519 private key; the host trusts the public half
//   signer      = "dev"           # optional: the name the host's trusted signers use (default: name)
//
// Treat the file like an SSH private key. Secrets are wiped when the object dies.
struct identity_file {
    // Reads a field the identity doesn't have, for formats built on this one (the dev session file):
    // true when it took it, false for a field it doesn't know either, an error for a bad value.
    using field_reader = std::function<result<bool>(std::string_view field, std::string_view value)>;

    std::string name;
    key psk; // empty for a device-key identity
    std::optional<device_secret> device;
    std::optional<ed25519_secret_key> signing;
    std::string signer; // empty = name
    std::optional<key_env> env;
    // The signing key's own tag when it came from a signing key file; else `env` covers it too.
    std::optional<key_env> signing_env;
    // What parse and load noticed that isn't fatal: a psk that looks like a passphrase, a file other
    // users can read. Callers show them (rhp-cli prints "warning: ..."); to_text leaves them out.
    std::vector<std::string> warnings;

    [[nodiscard]] static result<identity_file> parse(std::string_view text, const field_reader& extra = {});
    // The file at `path`; when it has no signing_key and a signing key file is beside it
    // (signing_key_file::beside), that one too, opened with `passphrase` if it is sealed (kAuth for a
    // wrong one; without one a sealed file is left out with a warning).
    [[nodiscard]] static result<identity_file> load(const std::string& path, std::string_view passphrase = {});
    // A new identity with a fresh 32-byte PSK and a fresh signing key.
    [[nodiscard]] static result<identity_file> generate(std::string name);
    // A new identity with a fresh device key of `alg` (no PSK) and a fresh signing key.
    [[nodiscard]] static result<identity_file> generate_device(std::string name, key_algorithm alg = key_algorithm::kEd25519);

    [[nodiscard]] std::string to_text() const;
    // Writes to_text() to `path` (replacing it atomically), its owner's alone on every OS
    // (platform::write_private_file).
    result<void> save(const std::string& path) const;

    // Takes the signing key (and its signer name and tag) of a signing key file.
    void attach(const signing_key_file& signing_file);

    // What Rhp::client takes.
    [[nodiscard]] psk_identity credential() const { return {name, psk}; }
    [[nodiscard]] std::optional<signing_key> signer_key() const;
    // The device key as a key handle (kNotFound for a PSK identity).
    [[nodiscard]] result<key_handle> device_key() const;

    // The lines a host adds to its keyring file, trusted-signers file and device allow-list for this
    // identity, each ending in ` env=dev|prod` when the identity is tagged.
    [[nodiscard]] std::string keyring_line(role granted) const;
    [[nodiscard]] std::optional<std::string> signers_line() const;
    // `name role alg base64-public-key [env=..]` (kNotFound for a PSK identity).
    [[nodiscard]] result<std::string> device_line(role granted) const;
};

// A script-signing key on its own (`dev.rhpsign`, decision AL11), what `rhp-cli keygen` writes
// beside the connection identity:
//
//   signer      = "dev"           # the name the host's trusted signers use
//   signing_key = "base64..."     # Ed25519 private key, or sealed with a passphrase:
//                                 #   "argon2i:m=65536,t=3:base64..." (seal_with_passphrase)
//   env         = "dev"           # optional: "dev" or "prod"
struct signing_key_file {
    std::string signer;
    ed25519_secret_key secret;
    std::optional<key_env> env;
    std::vector<std::string> warnings; // as identity_file::warnings

    // A sealed signing_key needs `passphrase`: kAuth without it or with a wrong one.
    [[nodiscard]] static result<signing_key_file> parse(std::string_view text, std::string_view passphrase = {});
    [[nodiscard]] static result<signing_key_file> load(const std::string& path, std::string_view passphrase = {});
    // Whether the file at `path` holds a sealed key (false when there is no such file).
    [[nodiscard]] static bool sealed(const std::string& path);
    // Where the signing key of the identity file at `identity_path` is kept: the same path with the
    // extension `.rhpsign` (`dev.rhpid` -> `dev.rhpsign`).
    [[nodiscard]] static std::string beside(const std::string& identity_path);

    // A non-empty `passphrase` seals the key (seal_with_passphrase).
    [[nodiscard]] result<std::string> to_text(std::string_view passphrase = {}, const passphrase_kdf& kdf = {}) const;
    // Writes to_text() owner-only, as identity_file::save.
    result<void> save(const std::string& path, std::string_view passphrase = {}, const passphrase_kdf& kdf = {}) const;

    [[nodiscard]] signing_key signer_key() const { return {signer, secret}; }
    // The host's trusted-signers line: `signer base64-public-key [env=..]`.
    [[nodiscard]] std::string signers_line() const;
};

} // namespace Rhp::security
