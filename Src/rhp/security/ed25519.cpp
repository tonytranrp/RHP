#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <initializer_list>
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
#include <rhp/platform/random.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/signer.hpp>

namespace Rhp::security {

namespace {

[[nodiscard]] const std::uint8_t* u8(const std::byte* p) noexcept {
    return reinterpret_cast<const std::uint8_t*>(p);
}

[[nodiscard]] std::uint8_t* u8(std::byte* p) noexcept {
    return reinterpret_cast<std::uint8_t*>(p);
}

// kScriptSignatureDomain ‖ source.
[[nodiscard]] std::vector<std::byte> script_message(std::string_view source) {
    std::vector<std::byte> message;
    message.reserve(kScriptSignatureDomain.size() + source.size());
    for (const char c : kScriptSignatureDomain) {
        message.push_back(static_cast<std::byte>(c));
    }
    for (const char c : source) {
        message.push_back(static_cast<std::byte>(c));
    }
    return message;
}

[[nodiscard]] error bad_signature(std::string message) {
    return make_error(errc::kBadSignature, std::move(message), "security.signature");
}

// The 64-byte Monocypher secret key (seed ‖ public key) for `seed`, and the public key. The seed
// is copied first: crypto_ed25519_key_pair wipes the one it is given.
struct expanded_key {
    std::array<std::byte, 64> secret{};
    std::array<std::byte, ed25519_public_key::kSize> pub{};

    explicit expanded_key(const std::array<std::byte, ed25519_secret_key::kSize>& seed) noexcept {
        std::array<std::byte, ed25519_secret_key::kSize> copy = seed;
        crypto_ed25519_key_pair(u8(secret.data()), u8(pub.data()), u8(copy.data()));
    }

    ~expanded_key() { crypto_wipe(u8(secret.data()), secret.size()); }

    expanded_key(const expanded_key&) = delete;
    expanded_key& operator=(const expanded_key&) = delete;
};

} // namespace

// ---- public key -------------------------------------------------------------------------------------

result<ed25519_public_key> ed25519_public_key::from_bytes(std::span<const std::byte> bytes) {
    if (bytes.size() != kSize) {
        return fail(errc::kInvalidArgument, std::format("an Ed25519 public key is {} bytes, got {}", kSize, bytes.size()), "security.ed25519");
    }
    ed25519_public_key k;
    std::ranges::copy(bytes, k.bytes_.begin());
    return k;
}

result<ed25519_public_key> ed25519_public_key::from_base64(std::string_view text) {
    auto bytes = base64_decode(detail::trim(text));
    if (!bytes) {
        return std::unexpected{std::move(bytes).error()};
    }
    return from_bytes(*bytes);
}

std::string ed25519_public_key::to_base64() const {
    return base64_encode(bytes_);
}

// ---- secret key ---------------------------------------------------------------------------------------

ed25519_secret_key::~ed25519_secret_key() {
    crypto_wipe(u8(seed_.data()), seed_.size());
}

result<ed25519_secret_key> ed25519_secret_key::from_bytes(std::span<const std::byte> bytes) {
    if (bytes.size() != kSize) {
        return fail(errc::kInvalidArgument, std::format("an Ed25519 private key is a {}-byte seed, got {} bytes", kSize, bytes.size()),
                    "security.ed25519");
    }
    ed25519_secret_key k;
    std::ranges::copy(bytes, k.seed_.begin());
    k.set_ = true;
    return k;
}

result<ed25519_secret_key> ed25519_secret_key::from_base64(std::string_view text) {
    auto bytes = base64_decode(detail::trim(text));
    if (!bytes) {
        return std::unexpected{std::move(bytes).error()};
    }
    auto k = from_bytes(*bytes);
    secure_wipe(bytes->data(), bytes->size());
    return k;
}

result<ed25519_secret_key> ed25519_secret_key::generate() {
    auto seed = platform::random_array<kSize>();
    if (!seed) {
        return std::unexpected{std::move(seed).error()};
    }
    auto k = from_bytes(*seed);
    secure_wipe(seed->data(), seed->size());
    return k;
}

ed25519_public_key ed25519_secret_key::public_key() const {
    const expanded_key k{seed_};
    return *ed25519_public_key::from_bytes(k.pub);
}

std::array<std::byte, ed25519_secret_key::kSignatureSize> ed25519_secret_key::sign(std::span<const std::byte> message) const {
    const expanded_key k{seed_};
    std::array<std::byte, kSignatureSize> signature{};
    crypto_ed25519_sign(u8(signature.data()), u8(k.secret.data()), u8(message.data()), message.size());
    return signature;
}

std::string ed25519_secret_key::to_base64() const {
    return base64_encode(seed_);
}

bool ed25519_check(const ed25519_public_key& key, std::span<const std::byte> signature, std::span<const std::byte> message) noexcept {
    if (signature.size() != ed25519_secret_key::kSignatureSize) {
        return false;
    }
    return crypto_ed25519_check(u8(signature.data()), u8(key.bytes().data()), u8(message.data()), message.size()) == 0;
}

// ---- signing key ---------------------------------------------------------------------------------------

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

// ---- trusted signers ------------------------------------------------------------------------------------

trusted_signers::trusted_signers(std::initializer_list<std::pair<std::string, ed25519_public_key>> keys) {
    for (const auto& [name, key] : keys) {
        if (auto added = add(name, key); !added) {
            throw Rhp::exception{std::move(added).error()};
        }
    }
}

result<void> trusted_signers::add(std::string name, ed25519_public_key key) {
    if (name.empty()) {
        return fail(errc::kInvalidArgument, "a trusted signer needs a name", "security.trusted_signers");
    }
    if (find(name) != nullptr) {
        return fail(errc::kAlreadyLoaded, std::format("signer '{}' is already trusted", name), "security.trusted_signers");
    }
    keys_.emplace_back(std::move(name), key);
    return {};
}

result<trusted_signers> trusted_signers::parse(std::string_view text) {
    trusted_signers out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto f = detail::fields(line.text);
        if (f.size() != 2) {
            return fail(errc::kInvalidArgument, std::format("line {}: expected `name base64-public-key`", line.number), "security.trusted_signers");
        }
        auto key = ed25519_public_key::from_base64(f[1]);
        if (!key) {
            return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, key.error().message), "security.trusted_signers");
        }
        if (auto added = out.add(std::string{f[0]}, *key); !added) {
            return fail(added.error().code, std::format("line {}: {}", line.number, added.error().message), "security.trusted_signers");
        }
    }
    return out;
}

result<trusted_signers> trusted_signers::from_file(const std::string& path) {
    const auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read signers file {}", path), "security.trusted_signers");
    }
    return parse(*text);
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

const ed25519_public_key* trusted_signers::find(std::string_view name) const noexcept {
    for (const auto& [n, k] : keys_) {
        if (n == name) {
            return &k;
        }
    }
    return nullptr;
}

} // namespace Rhp::security
