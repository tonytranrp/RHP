// Ed25519 signing and checking (Monocypher's optional RFC 8032 implementation). The key bytes and
// the trusted-signers file are in signing_keys.cpp.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <format>
#include <mutex>
#include <optional>
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
#include <rhp/security/detail/bytes.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/signer.hpp>

namespace Rhp::security {

using detail::u8;

namespace {

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

[[nodiscard]] error signature_mismatch(std::string_view signer) {
    return bad_signature(std::format("the signature by '{}' doesn't match the script", signer));
}

// The signer's name and the signature bytes of a signature value ({signer = name, sig = bytes}).
struct signature_fields {
    const std::string* signer = nullptr;
    const value::bytes* sig = nullptr;
};

[[nodiscard]] result<signature_fields> read_signature(const value& signature) {
    if (signature.is_nil()) {
        return std::unexpected{bad_signature("the script is not signed")};
    }
    const auto* m = signature.get_if<value::map>();
    if (m == nullptr) {
        return std::unexpected{bad_signature("malformed signature")};
    }
    signature_fields out;
    for (const auto& [k, v] : *m) {
        const auto* field = k.get_if<std::string>();
        if (field == nullptr) {
            continue;
        }
        if (*field == "signer") {
            out.signer = v.get_if<std::string>();
        } else if (*field == "sig") {
            out.sig = v.get_if<value::bytes>();
        }
    }
    if (out.signer == nullptr || out.sig == nullptr) {
        return std::unexpected{bad_signature("malformed signature")};
    }
    return out;
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

// Recent script signatures, and the signatures recently found valid, process-wide: an exec repeated
// with the same source signs and verifies once (Ed25519 costs tens of microseconds each way;
// BLAKE2b of the source a few nanoseconds per byte). Both are facts about bytes - this public key's
// signature of this source, these 64 bytes being one - so whose keyring asked doesn't matter: a
// verifier still checks that the signer is one it trusts before it looks here. Entries are found by
// the source's BLAKE2b-256 (collision resistant) and replaced oldest first.
class script_cache {
public:
    using pub_t = std::array<std::byte, ed25519_public_key::kSize>;
    using sig_t = std::array<std::byte, ed25519_secret_key::kSignatureSize>;

    [[nodiscard]] std::optional<sig_t> signature(const pub_t& pub, const digest256& source) {
        const std::scoped_lock lock{mutex_};
        for (const signed_entry& e : signed_) {
            if (e.used && e.source == source && e.pub == pub) {
                return e.sig;
            }
        }
        return std::nullopt;
    }

    void signed_now(const pub_t& pub, const digest256& source, const sig_t& sig) {
        const std::scoped_lock lock{mutex_};
        signed_[next_signed_++ % kEntries] = signed_entry{pub, source, sig, true};
    }

    [[nodiscard]] bool verified(const pub_t& pub, std::span<const std::byte> sig, const digest256& source) {
        const std::scoped_lock lock{mutex_};
        for (const signed_entry& e : verified_) {
            if (e.used && e.source == source && e.pub == pub && std::ranges::equal(e.sig, sig)) {
                return true;
            }
        }
        return false;
    }

    void verified_now(const pub_t& pub, std::span<const std::byte, ed25519_secret_key::kSignatureSize> sig, const digest256& source) {
        const std::scoped_lock lock{mutex_};
        signed_entry& e = verified_[next_verified_++ % kEntries];
        e = signed_entry{pub, source, {}, true};
        std::ranges::copy(sig, e.sig.begin());
    }

private:
    static constexpr std::size_t kEntries = 64;

    struct signed_entry {
        pub_t pub{};
        digest256 source{};
        sig_t sig{};
        bool used = false;
    };

    std::mutex mutex_;
    std::array<signed_entry, kEntries> signed_{};
    std::array<signed_entry, kEntries> verified_{};
    std::size_t next_signed_ = 0;
    std::size_t next_verified_ = 0;
};

script_cache& recent_scripts() {
    static script_cache cache;
    return cache;
}

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
    const digest256 digest = blake2b_256(source);
    std::array<std::byte, ed25519_public_key::kSize> pub{};
    std::ranges::copy(secret.public_key().bytes(), pub.begin());
    std::array<std::byte, ed25519_secret_key::kSignatureSize> signature{};
    if (const auto known = recent_scripts().signature(pub, digest)) {
        signature = *known;
    } else {
        signature = secret.sign(script_message(source));
        recent_scripts().signed_now(pub, digest, signature);
    }
    value::map m;
    m.emplace_back(value{"signer"}, value{name});
    m.emplace_back(value{"sig"}, value{value::bytes(signature.begin(), signature.end())});
    return value{std::move(m)};
}

result<std::string> trusted_signers::verify(std::string_view source, const value& signature) const {
    const auto fields = read_signature(signature);
    if (!fields) {
        return std::unexpected{fields.error()};
    }
    const std::string* signer_name = fields->signer;
    const value::bytes* sig = fields->sig;
    const ed25519_public_key* key = find(*signer_name);
    if (key == nullptr) {
        return std::unexpected{bad_signature(std::format("signer '{}' is not trusted by this host", *signer_name))};
    }
    if (sig->size() != ed25519_secret_key::kSignatureSize) {
        return std::unexpected{signature_mismatch(*signer_name)};
    }
    const digest256 digest = blake2b_256(source);
    std::array<std::byte, ed25519_public_key::kSize> pub{};
    std::ranges::copy(key->bytes(), pub.begin());
    if (recent_scripts().verified(pub, *sig, digest)) {
        return *signer_name;
    }
    if (!ed25519_check(*key, *sig, script_message(source))) {
        return std::unexpected{signature_mismatch(*signer_name)};
    }
    recent_scripts().verified_now(pub, std::span<const std::byte, ed25519_secret_key::kSignatureSize>{sig->data(), ed25519_secret_key::kSignatureSize}, digest);
    return *signer_name;
}

} // namespace Rhp::security
