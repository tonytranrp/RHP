// The parts of ed25519.hpp that need no cryptography — key bytes, base64, the trusted-signers file —
// built with RHP_ENABLE=OFF too. Signing and checking live in ed25519.cpp (ed25519_disabled.cpp
// when RHP is compiled out).
#include <algorithm>
#include <cstddef>
#include <format>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

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
    secure_wipe(seed_.data(), seed_.size());
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

std::string ed25519_secret_key::to_base64() const {
    return base64_encode(seed_);
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

const ed25519_public_key* trusted_signers::find(std::string_view name) const noexcept {
    for (const auto& [n, k] : keys_) {
        if (n == name) {
            return &k;
        }
    }
    return nullptr;
}

} // namespace Rhp::security
