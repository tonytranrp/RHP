// Key handles: software Ed25519 (Monocypher, through ed25519.cpp), software P-256 (the TLS
// backend's crypto, security/tls/p256.hpp) and callbacks into hardware keys.
#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/tls/p256.hpp>

namespace Rhp::security {

namespace {

namespace p256 = tls::detail;

constexpr const char* kHandleWhere = "security.key_handle";

// The P-256 group order n, big-endian.
constexpr std::array<unsigned char, 32> kP256Order{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                                   0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

// 0 < d < n.
[[nodiscard]] bool valid_p256_scalar(std::span<const std::byte> d) noexcept {
    const bool zero = std::ranges::all_of(d, [](std::byte b) { return b == std::byte{0}; });
    const bool below = std::ranges::lexicographical_compare(d, kP256Order, {}, [](std::byte b) { return std::to_integer<unsigned char>(b); });
    return !zero && below;
}

// A P-256 scalar, wiped when the last handle using it goes.
struct p256_secret {
    std::array<std::byte, p256::kP256PrivateKeySize> d{};

    p256_secret() = default;
    ~p256_secret() { secure_wipe(d.data(), d.size()); }
    p256_secret(const p256_secret&) = delete;
    p256_secret& operator=(const p256_secret&) = delete;
};

// One DER INTEGER (short lengths: a P-256 signature is at most 72 bytes) as 32 big-endian bytes at `out`.
[[nodiscard]] bool read_der_integer(std::span<const std::byte>& in, std::span<std::byte, 32> out) noexcept {
    if (in.size() < 2 || in[0] != std::byte{0x02}) {
        return false;
    }
    const auto length = std::to_integer<std::size_t>(in[1]);
    if (length == 0 || length > 33 || in.size() < 2 + length) {
        return false;
    }
    std::span<const std::byte> value = in.subspan(2, length);
    in = in.subspan(2 + length);
    if (value.size() == 33) { // a leading 0 that keeps a high bit positive
        if (value[0] != std::byte{0}) {
            return false;
        }
        value = value.subspan(1);
    }
    std::ranges::fill(out, std::byte{0});
    std::ranges::copy(value, out.begin() + static_cast<std::ptrdiff_t>(out.size() - value.size()));
    return true;
}

// A DER ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) as r || s.
[[nodiscard]] std::optional<std::vector<std::byte>> p256_raw_signature(std::span<const std::byte> der) {
    if (der.size() < 2 || der[0] != std::byte{0x30} || std::to_integer<std::size_t>(der[1]) != der.size() - 2) {
        return std::nullopt;
    }
    std::span<const std::byte> in = der.subspan(2);
    std::vector<std::byte> raw(key_handle::kSignatureSize);
    if (!read_der_integer(in, std::span<std::byte, 32>{raw.data(), 32}) || !read_der_integer(in, std::span<std::byte, 32>{raw.data() + 32, 32}) || !in.empty()) {
        return std::nullopt;
    }
    return raw;
}

[[nodiscard]] result<void> check_public_key(key_algorithm alg, std::span<const std::byte> public_key) {
    if (public_key.size() != key_handle::public_key_size(alg)) {
        return fail(errc::kInvalidArgument, std::format("a {} public key is {} bytes, got {}", to_string(alg), key_handle::public_key_size(alg), public_key.size()), kHandleWhere);
    }
    if (alg == key_algorithm::kP256 && public_key[0] != std::byte{0x04}) {
        return fail(errc::kInvalidArgument, "a P-256 public key is SEC1 uncompressed (it starts with 0x04)", kHandleWhere);
    }
    return {};
}

} // namespace

key_handle::key_handle(key_algorithm alg, std::vector<std::byte> public_key, sign_function sign)
    : alg_(alg), public_(std::move(public_key)), fingerprint_(key_fingerprint(alg, public_)), sign_(std::move(sign)) {}

result<key_handle> key_handle::from_private_key(key_algorithm alg, std::span<const std::byte> private_key) {
    if (private_key.size() != kPrivateKeySize) {
        return fail(errc::kInvalidArgument, std::format("a {} private key is {} bytes, got {}", to_string(alg), kPrivateKeySize, private_key.size()), kHandleWhere);
    }
    if (alg == key_algorithm::kEd25519) {
        auto secret = ed25519_secret_key::from_bytes(private_key);
        if (!secret) {
            return std::unexpected{std::move(secret).error()};
        }
        return from_ed25519(*secret);
    }
    if (!valid_p256_scalar(private_key)) {
        return fail(errc::kInvalidArgument, "not a P-256 private key (0 or not below the group order)", kHandleWhere);
    }
    auto secret = std::make_shared<p256_secret>();
    std::ranges::copy(private_key, secret->d.begin());
    const auto pub = p256::p256_public_from_private(secret->d);
    if (!pub) {
        return std::unexpected{pub.error()};
    }
    return key_handle{alg, std::vector<std::byte>(pub->begin(), pub->end()), [secret = std::shared_ptr<const p256_secret>{std::move(secret)}](std::span<const std::byte> message) -> result<std::vector<std::byte>> {
                          auto sig = p256::p256_sign(secret->d, message);
                          if (!sig) {
                              return std::unexpected{std::move(sig).error()};
                          }
                          return std::vector<std::byte>(sig->begin(), sig->end());
                      }};
}

result<key_handle> key_handle::from_ed25519(const ed25519_secret_key& secret) {
    if (secret.empty()) {
        return fail(errc::kInvalidArgument, "an empty Ed25519 private key", kHandleWhere);
    }
    const ed25519_public_key pub = secret.public_key();
    return key_handle{key_algorithm::kEd25519, std::vector<std::byte>(pub.bytes().begin(), pub.bytes().end()),
                      [secret = std::make_shared<const ed25519_secret_key>(secret)](std::span<const std::byte> message) -> result<std::vector<std::byte>> {
                          const auto sig = secret->sign(message);
                          return std::vector<std::byte>(sig.begin(), sig.end());
                      }};
}

result<key_handle> key_handle::from_callback(key_algorithm alg, std::span<const std::byte> public_key, sign_function sign) {
    if (auto ok = check_public_key(alg, public_key); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    if (!sign) {
        return fail(errc::kInvalidArgument, "a callback key needs a sign function", kHandleWhere);
    }
    return key_handle{alg, std::vector<std::byte>(public_key.begin(), public_key.end()), std::move(sign)};
}

result<std::vector<std::byte>> key_handle::sign(std::span<const std::byte> message) const {
    if (!sign_) {
        return fail(errc::kInvalidArgument, "an empty key handle signs nothing", kHandleWhere);
    }
    auto sig = sign_(message);
    if (!sig || sig->size() == kSignatureSize) {
        return sig;
    }
    if (alg_ == key_algorithm::kP256) {
        if (auto raw = p256_raw_signature(*sig)) {
            return std::move(*raw);
        }
    }
    return fail(errc::kInvalidArgument, std::format("the {} key's signer returned {} bytes, not a signature", to_string(alg_), sig->size()), kHandleWhere);
}

result<void> verify(key_algorithm alg, std::span<const std::byte> public_key, std::span<const std::byte> message, std::span<const std::byte> signature) {
    if (!check_public_key(alg, public_key) || signature.size() != key_handle::kSignatureSize) {
        return fail(errc::kBadSignature, std::format("a malformed {} public key or signature", to_string(alg)), kHandleWhere);
    }
    if (alg == key_algorithm::kEd25519) {
        if (!ed25519_check(*ed25519_public_key::from_bytes(public_key), signature, message)) {
            return fail(errc::kBadSignature, "the Ed25519 signature doesn't match", kHandleWhere);
        }
        return {};
    }
    auto checked = p256::p256_verify(std::span<const std::byte, p256::kP256PublicKeySize>{public_key.data(), p256::kP256PublicKeySize}, message,
                                     std::span<const std::byte, p256::kP256SignatureSize>{signature.data(), p256::kP256SignatureSize});
    if (!checked && checked.error().code == errc::kInvalidArgument) {
        return fail(errc::kBadSignature, checked.error().message, kHandleWhere);
    }
    return checked;
}

std::string key_fingerprint(key_algorithm alg, std::span<const std::byte> public_key) {
    const std::string_view name = to_string(alg);
    std::vector<std::byte> input;
    input.reserve(name.size() + 1 + public_key.size());
    for (const char c : name) {
        input.push_back(static_cast<std::byte>(c));
    }
    input.push_back(static_cast<std::byte>(':'));
    input.insert(input.end(), public_key.begin(), public_key.end());
    const digest256 digest = blake2b_256(input);
    std::string text = base64_encode(std::span{digest}.first<16>());
    std::ranges::replace(text, '+', '-');
    std::ranges::replace(text, '/', '_');
    while (!text.empty() && text.back() == '=') {
        text.pop_back();
    }
    return text;
}

result<key> generate_private_key(key_algorithm alg) {
    while (true) {
        auto bytes = platform::random_array<key_handle::kPrivateKeySize>();
        if (!bytes) {
            return std::unexpected{std::move(bytes).error()};
        }
        if (alg == key_algorithm::kEd25519 || valid_p256_scalar(*bytes)) {
            auto out = key::from_bytes(*bytes);
            secure_wipe(bytes->data(), bytes->size());
            return out;
        }
    }
}

} // namespace Rhp::security
