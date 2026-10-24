#pragma once

#include <array>
#include <cstddef>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/signer.hpp>

namespace Rhp::security {

// A developer's Ed25519 (RFC 8032) public key: what a host trusts. Text form is base64.
class ed25519_public_key {
public:
    static constexpr std::size_t kSize = 32;

    ed25519_public_key() = default;

    [[nodiscard]] static result<ed25519_public_key> from_bytes(std::span<const std::byte> bytes);
    [[nodiscard]] static result<ed25519_public_key> from_base64(std::string_view text);

    [[nodiscard]] std::span<const std::byte, kSize> bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::string to_base64() const;

    [[nodiscard]] bool operator==(const ed25519_public_key&) const = default;

private:
    std::array<std::byte, kSize> bytes_{};
};

// A developer's Ed25519 private key (its 32-byte seed): what signs scripts. Wiped on destruction,
// never printed. Text form is base64.
class ed25519_secret_key {
public:
    static constexpr std::size_t kSize = 32;
    static constexpr std::size_t kSignatureSize = 64;

    ed25519_secret_key() = default;
    ~ed25519_secret_key();
    ed25519_secret_key(const ed25519_secret_key&) = default;
    ed25519_secret_key& operator=(const ed25519_secret_key&) = default;

    [[nodiscard]] static result<ed25519_secret_key> from_bytes(std::span<const std::byte> bytes);
    [[nodiscard]] static result<ed25519_secret_key> from_base64(std::string_view text);
    // A fresh key from the OS random source.
    [[nodiscard]] static result<ed25519_secret_key> generate();

    [[nodiscard]] ed25519_public_key public_key() const;
    [[nodiscard]] std::array<std::byte, kSignatureSize> sign(std::span<const std::byte> message) const;
    [[nodiscard]] std::string to_base64() const;
    [[nodiscard]] bool empty() const noexcept { return !set_; }

private:
    // The public half, derived once from the seed (deriving it costs as much as a signature).
    [[nodiscard]] static std::array<std::byte, ed25519_public_key::kSize> derive_public(std::span<const std::byte, kSize> seed) noexcept;

    std::array<std::byte, kSize> seed_{};
    std::array<std::byte, ed25519_public_key::kSize> public_{};
    bool set_ = false;
};

// True if `signature` is `key`'s signature of `message`.
[[nodiscard]] bool ed25519_check(const ed25519_public_key& key, std::span<const std::byte> signature, std::span<const std::byte> message) noexcept;

// Client side: who signs (the name the host knows the public key by) and with what.
struct signing_key {
    std::string name;
    ed25519_secret_key secret;

    // {signer = name, sig = 64 bytes} over kScriptSignatureDomain || source.
    [[nodiscard]] result<value> sign(std::string_view source) const;
};

// Host side: the developer keys whose signatures it accepts. Names are unique.
class trusted_signers {
public:
    trusted_signers() = default;
    // Throws Rhp::exception on a duplicate or empty name; use add() to get the error instead.
    trusted_signers(std::initializer_list<std::pair<std::string, ed25519_public_key>> keys);

    result<void> add(std::string name, ed25519_public_key key);

    // Text with one `name base64-public-key` per line ('#' starts a comment), e.g. what
    // `rhp-cli keygen` prints for the host.
    [[nodiscard]] static result<trusted_signers> parse(std::string_view text);
    [[nodiscard]] static result<trusted_signers> from_file(const std::string& path);

    // The signer's name, or kBadSignature (unsigned, unknown signer, wrong signature, malformed).
    [[nodiscard]] result<std::string> verify(std::string_view source, const value& signature) const;

    [[nodiscard]] const ed25519_public_key* find(std::string_view name) const noexcept;
    [[nodiscard]] std::size_t size() const noexcept { return keys_.size(); }

private:
    std::vector<std::pair<std::string, ed25519_public_key>> keys_;
};

// The default signer policy: standard Ed25519 (Monocypher's optional RFC 8032 implementation).
struct ed25519 {
    static constexpr std::string_view name = "ed25519";
    using key = signing_key;
    using trust = trusted_signers;
};

static_assert(signer<ed25519>);

} // namespace Rhp::security
