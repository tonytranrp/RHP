#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>

namespace Rhp::security {

// ---- passphrases ----------------------------------------------------------------------------------

// How a passphrase becomes a key: Argon2i (RFC 9106, one lane) with this much memory and this many
// passes. The defaults (64 MiB, 3 passes: about a second on a laptop) follow Monocypher's advice
// for interactive use; what a sealed value used is written in it, so they can change.
struct passphrase_kdf {
    std::uint32_t memory_kib = 64u * 1024u;
    std::uint32_t passes = 3;
};

// `secret` encrypted under `passphrase`: XChaCha20-Poly1305 (Monocypher's crypto_aead_lock) with a
// key from Argon2i over the passphrase and a random 16-byte salt. One line of text:
//
//   argon2i:m=65536,t=3:<base64 of salt (16) || nonce (24) || mac (16) || ciphertext>
//
// The header ("argon2i:m=..,t=..:") names the KDF and its parameters and is the AEAD's associated
// data. kInvalidArgument for parameters below Argon2's minimum (8 KiB, 1 pass); kDisabled with
// RHP_ENABLE=OFF.
[[nodiscard]] result<std::string> seal_with_passphrase(std::span<const std::byte> secret, std::string_view passphrase, const passphrase_kdf& kdf = {});

// The secret in a value seal_with_passphrase made: kAuth for a wrong passphrase or a changed value,
// kInvalidArgument for one that isn't sealed or asks for more than 1 GiB or 64 passes.
[[nodiscard]] result<key> open_with_passphrase(std::string_view sealed, std::string_view passphrase);

// Whether `value` is a sealed one ("argon2i:" first).
[[nodiscard]] bool is_passphrase_sealed(std::string_view value) noexcept;

// ---- key stores -----------------------------------------------------------------------------------

// Where secrets live (decision AL10): a name -> secret map with the OS or the app holding it.
// Names are 1..64 characters of letters, digits, '.', '_' and '-', not starting with '.'.
// Secrets are keys (16..64 bytes, wiped when they go): PSKs, and private keys through store_key.
//
//   file_key_store       owner-only files in a folder, optionally sealed with a passphrase
//   dpapi_key_store      the same files, sealed with Windows DPAPI for the current user
//   keychain_key_store   Apple Keychain generic passwords (Apple targets only; untested so far)
//   callback_key_store   the app's own functions (Android Keystore wrapping, an HSM, ...)
//
// Hardware keys whose private half can't be exported aren't stored here: they are
// key_handle::from_callback.
class key_store {
public:
    virtual ~key_store() = default;

    // kNotFound when there is none.
    [[nodiscard]] virtual result<key> load(std::string_view name) const = 0;
    // Replaces what is stored under `name`.
    [[nodiscard]] virtual result<void> store(std::string_view name, const key& secret) = 0;
    // kNotFound when there is none.
    [[nodiscard]] virtual result<void> remove(std::string_view name) = 0;

protected:
    key_store() = default;
    key_store(const key_store&) = default;
    key_store& operator=(const key_store&) = default;
};

// A private key in a store: the secret is a tag byte (1 = Ed25519, 2 = P-256) followed by the
// key_handle::kPrivateKeySize private-key bytes.
[[nodiscard]] result<void> store_key(key_store& to, std::string_view name, key_algorithm alg, std::span<const std::byte> private_key);
[[nodiscard]] result<key_handle> load_key(const key_store& from, std::string_view name);

// What file_key_store and dpapi_key_store hold: one owner-only file per name, `<name>.rhpkey`:
//
//   # RHP key: keep it private
//   secret = "<base64>"                        no protection beyond the file's permissions
//   secret = "argon2i:m=65536,t=3:<base64>"    sealed with a passphrase
//   secret = "wrapped:<base64>"                wrapped by the store's key_wrapping (DPAPI, the app)
//
// A store reads every form it can open: a sealed file needs the passphrase (kAuth without it or
// with a wrong one), a wrapped one the wrapping.
struct file_key_store_options {
    std::string passphrase; // non-empty: secrets are stored sealed with it
    passphrase_kdf kdf{};
};

// Wrapping done elsewhere: what the store writes is wrap(secret), what it reads unwrap(bytes).
struct key_wrapping {
    std::function<result<std::vector<std::byte>>(std::span<const std::byte> plain)> wrap;
    std::function<result<std::vector<std::byte>>(std::span<const std::byte> wrapped)> unwrap;
};

class file_key_store : public key_store {
public:
    explicit file_key_store(std::filesystem::path directory, file_key_store_options options = {});
    file_key_store(std::filesystem::path directory, key_wrapping wrapping);

    [[nodiscard]] result<key> load(std::string_view name) const override;
    [[nodiscard]] result<void> store(std::string_view name, const key& secret) override;
    [[nodiscard]] result<void> remove(std::string_view name) override;

    // Where `name` is kept (its name is checked by the calls above, not here).
    [[nodiscard]] std::filesystem::path path_of(std::string_view name) const;

private:
    std::filesystem::path directory_;
    file_key_store_options options_;
    key_wrapping wrapping_;
};

// file_key_store with Windows DPAPI (platform::protect): only this user on this machine opens the
// files. Every call reports kDisabled on other OSes.
class dpapi_key_store : public file_key_store {
public:
    explicit dpapi_key_store(std::filesystem::path directory);
};

// Apple Keychain generic passwords: `service` (default "rhp") and the key's name as the account
// (platform::keychain_*). Every call reports kDisabled elsewhere. Compiled on Apple targets only and
// not yet run on one.
class keychain_key_store : public key_store {
public:
    explicit keychain_key_store(std::string service = "rhp");

    [[nodiscard]] result<key> load(std::string_view name) const override;
    [[nodiscard]] result<void> store(std::string_view name, const key& secret) override;
    [[nodiscard]] result<void> remove(std::string_view name) override;

private:
    std::string service_;
};

// The app's own storage, e.g. Android: secrets wrapped with a Keystore key through JNI and kept in
// the app's files. A function left empty reports kDisabled. Names are checked before they're called.
struct key_store_callbacks {
    std::function<result<key>(std::string_view name)> load;
    std::function<result<void>(std::string_view name, const key& secret)> store;
    std::function<result<void>(std::string_view name)> remove;
};

class callback_key_store : public key_store {
public:
    explicit callback_key_store(key_store_callbacks callbacks);

    [[nodiscard]] result<key> load(std::string_view name) const override;
    [[nodiscard]] result<void> store(std::string_view name, const key& secret) override;
    [[nodiscard]] result<void> remove(std::string_view name) override;

private:
    key_store_callbacks callbacks_;
};

} // namespace Rhp::security
