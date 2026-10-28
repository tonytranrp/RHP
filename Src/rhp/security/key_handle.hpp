#pragma once

#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

// The signature algorithms of device keys, operator certificates and the root of trust. Their names
// in files and on the wire are "ed25519" and "p256" (ECDSA P-256 with SHA-256).
enum class key_algorithm : unsigned char {
    kEd25519,
    kP256
};

[[nodiscard]] constexpr std::string_view to_string(key_algorithm alg) noexcept {
    return alg == key_algorithm::kP256 ? "p256" : "ed25519";
}

[[nodiscard]] constexpr std::optional<key_algorithm> parse_key_algorithm(std::string_view name) noexcept {
    if (name == "ed25519") {
        return key_algorithm::kEd25519;
    }
    if (name == "p256") {
        return key_algorithm::kP256;
    }
    return std::nullopt;
}

// A key that signs, whatever holds its private half (decision AL10): software Ed25519 (Monocypher),
// software P-256 (the TLS backend's crypto: OpenSSL, else Mbed TLS), or a callback into a hardware
// key (Secure Enclave, Android StrongBox, a TPM, a YubiKey), whose private key never enters RHP.
//
//   Ed25519   public key 32 bytes; signature 64 bytes (RFC 8032, over the message itself)
//   P-256     public key 65 bytes, SEC1 uncompressed (0x04 || X || Y); signature 64 bytes, r || s
//             (ECDSA over SHA-256(message), big-endian, 32 bytes each)
//
// Copies share the key (immutable). sign() is const and may be called from any thread: a callback
// key's function must allow that too. An empty handle (default-constructed) signs nothing.
class key_handle {
public:
    static constexpr std::size_t kPrivateKeySize = 32; // an Ed25519 seed, a P-256 scalar (big-endian)
    static constexpr std::size_t kSignatureSize = 64;

    [[nodiscard]] static constexpr std::size_t public_key_size(key_algorithm alg) noexcept { return alg == key_algorithm::kP256 ? 65 : 32; }

    // Signs `message` (not a digest of it). It may return the signature as 64 bytes or, for P-256,
    // as DER (an X9.62 ECDSA-Sig-Value: what the Secure Enclave, Android Keystore and PKCS#11 give),
    // which the handle turns into r || s.
    using sign_function = std::function<result<std::vector<std::byte>>(std::span<const std::byte> message)>;

    key_handle() = default;

    // A software key from its private bytes: an Ed25519 seed, or a P-256 scalar (0 < d < n). The
    // bytes are copied and wiped when the last copy of the handle goes. kInvalidArgument for a wrong
    // size or scalar; P-256 reports kDisabled in a build without a TLS backend.
    [[nodiscard]] static result<key_handle> from_private_key(key_algorithm alg, std::span<const std::byte> private_key);
    [[nodiscard]] static result<key_handle> from_ed25519(const ed25519_secret_key& secret);
    // A key held elsewhere: its public key (checked for size and form, not for being on the curve)
    // and the function that signs with it.
    [[nodiscard]] static result<key_handle> from_callback(key_algorithm alg, std::span<const std::byte> public_key, sign_function sign);

    [[nodiscard]] key_algorithm alg() const noexcept { return alg_; }
    [[nodiscard]] std::span<const std::byte> public_key() const noexcept { return public_; }
    // key_fingerprint(alg(), public_key()).
    [[nodiscard]] const std::string& fingerprint() const noexcept { return fingerprint_; }
    [[nodiscard]] bool empty() const noexcept { return !sign_; }

    // A kSignatureSize-byte signature of `message`; kInvalidArgument for an empty handle, and a
    // callback's own error, or kInvalidArgument when what it returned is no signature.
    [[nodiscard]] result<std::vector<std::byte>> sign(std::span<const std::byte> message) const;

private:
    key_handle(key_algorithm alg, std::vector<std::byte> public_key, sign_function sign);

    key_algorithm alg_ = key_algorithm::kEd25519;
    std::vector<std::byte> public_;
    std::string fingerprint_;
    sign_function sign_;
};

// Success when `signature` is `public_key`'s signature of `message` (sizes as above); kBadSignature
// when it isn't or either is malformed. P-256 needs the TLS backend's crypto: kDisabled without one
// (and with RHP_ENABLE=OFF, for both algorithms).
[[nodiscard]] result<void> verify(key_algorithm alg, std::span<const std::byte> public_key, std::span<const std::byte> message,
                                  std::span<const std::byte> signature);

// A short, stable name for a public key (logs, pins, the pairing QR's `fp=`): the first 16 bytes of
// BLAKE2b-256(alg name || ":" || public key) in unpadded base64url, 22 characters. "" with
// RHP_ENABLE=OFF.
[[nodiscard]] std::string key_fingerprint(key_algorithm alg, std::span<const std::byte> public_key);

// Fresh private-key bytes for `alg` from the OS random source (a P-256 scalar is drawn until it is
// below the group order). Wiped when the key goes.
[[nodiscard]] result<key> generate_private_key(key_algorithm alg);

} // namespace Rhp::security
