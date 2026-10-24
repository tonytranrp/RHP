// Ed25519 signing and checking (Monocypher's optional RFC 8032 implementation). The key bytes and
// the trusted-signers file are in signing_keys.cpp.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <monocypher-ed25519.h>
#include <monocypher.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/signer.hpp>

namespace Rhp::security {

namespace {

[[nodiscard]] const std::uint8_t* u8(const std::byte* p) noexcept {
    return reinterpret_cast<const std::uint8_t*>(p);
}

[[nodiscard]] std::uint8_t* u8(std::byte* p) noexcept {
    return reinterpret_cast<std::uint8_t*>(p);
}

// kScriptSignatureDomain || source.
[[nodiscard]] std::vector<std::byte> script_message(std::string_view source) {
    std::vector<std::byte> message(kScriptSignatureDomain.size() + source.size());
    std::memcpy(message.data(), kScriptSignatureDomain.data(), kScriptSignatureDomain.size());
    if (!source.empty()) {
        std::memcpy(message.data() + kScriptSignatureDomain.size(), source.data(), source.size());
    }
    return message;
}

[[nodiscard]] error bad_signature(std::string message) {
    return make_error(errc::kBadSignature, std::move(message), "security.signature");
}

// Monocypher's 64-byte secret key: seed || public key. Wiped when it goes.
struct monocypher_secret {
    std::array<std::byte, 64> bytes{};

    monocypher_secret(std::span<const std::byte, ed25519_secret_key::kSize> seed, std::span<const std::byte, ed25519_public_key::kSize> pub) noexcept {
        std::copy(seed.begin(), seed.end(), bytes.begin());
        std::copy(pub.begin(), pub.end(), bytes.begin() + ed25519_secret_key::kSize);
    }

    ~monocypher_secret() { crypto_wipe(u8(bytes.data()), bytes.size()); }

    monocypher_secret(const monocypher_secret&) = delete;
    monocypher_secret& operator=(const monocypher_secret&) = delete;
};

} // namespace

std::array<std::byte, ed25519_public_key::kSize> ed25519_secret_key::derive_public(std::span<const std::byte, kSize> seed) noexcept {
    // crypto_ed25519_key_pair wipes the seed it is given: it gets a copy.
    std::array<std::byte, kSize> copy{};
    std::copy(seed.begin(), seed.end(), copy.begin());
    std::array<std::byte, 64> secret{};
    std::array<std::byte, ed25519_public_key::kSize> pub{};
    crypto_ed25519_key_pair(u8(secret.data()), u8(pub.data()), u8(copy.data()));
    crypto_wipe(u8(secret.data()), secret.size());
    return pub;
}

ed25519_public_key ed25519_secret_key::public_key() const {
    return *ed25519_public_key::from_bytes(public_);
}

std::array<std::byte, ed25519_secret_key::kSignatureSize> ed25519_secret_key::sign(std::span<const std::byte> message) const {
    const monocypher_secret secret{seed_, public_};
    std::array<std::byte, kSignatureSize> signature{};
    crypto_ed25519_sign(u8(signature.data()), u8(secret.bytes.data()), u8(message.data()), message.size());
    return signature;
}

bool ed25519_check(const ed25519_public_key& key, std::span<const std::byte> signature, std::span<const std::byte> message) noexcept {
    if (signature.size() != ed25519_secret_key::kSignatureSize) {
        return false;
    }
    return crypto_ed25519_check(u8(signature.data()), u8(key.bytes().data()), u8(message.data()), message.size()) == 0;
}

result<value> signing_key::sign(std::string_view source) const {
    if (name.empty() || secret.empty()) {
        return fail(errc::kInvalidArgument, "a signing key needs a name and a private key", "security.signature");
    }
    const auto signature = secret.sign(script_message(source));
    value::map m;
    m.emplace_back(value{"signer"}, value{name});
    m.emplace_back(value{"sig"}, value{value::bytes(signature.begin(), signature.end())});
    return value{std::move(m)};
}

result<std::string> trusted_signers::verify(std::string_view source, const value& signature) const {
    if (signature.is_nil()) {
        return std::unexpected{bad_signature("the script is not signed")};
    }
    const auto* m = signature.get_if<value::map>();
    if (m == nullptr) {
        return std::unexpected{bad_signature("malformed signature")};
    }
    const std::string* signer_name = nullptr;
    const value::bytes* sig = nullptr;
    for (const auto& [k, v] : *m) {
        const auto* field = k.get_if<std::string>();
        if (field == nullptr) {
            continue;
        }
        if (*field == "signer") {
            signer_name = v.get_if<std::string>();
        } else if (*field == "sig") {
            sig = v.get_if<value::bytes>();
        }
    }
    if (signer_name == nullptr || sig == nullptr) {
        return std::unexpected{bad_signature("malformed signature")};
    }
    const ed25519_public_key* key = find(*signer_name);
    if (key == nullptr) {
        return std::unexpected{bad_signature(std::format("signer '{}' is not trusted by this host", *signer_name))};
    }
    if (!ed25519_check(*key, *sig, script_message(source))) {
        return std::unexpected{bad_signature(std::format("the signature by '{}' doesn't match the script", *signer_name))};
    }
    return *signer_name;
}

} // namespace Rhp::security
