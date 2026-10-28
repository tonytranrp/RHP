#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

#include <rhp/core/result.hpp>

// ECDSA P-256 with SHA-256 through the TLS backend's crypto, for Rhp::security::key_handle. Internal:
// applications use key_handle and security::verify. OpenSSL runs them when it is built, else Mbed
// TLS (as auto_backend picks); without either they report kDisabled.
namespace Rhp::security::tls::detail {

inline constexpr std::size_t kP256PrivateKeySize = 32; // the scalar d, big-endian, 0 < d < n
inline constexpr std::size_t kP256PublicKeySize = 65;  // SEC1 uncompressed: 0x04 || X || Y
inline constexpr std::size_t kP256SignatureSize = 64;  // r || s, 32 bytes each, big-endian

using p256_public_key = std::array<std::byte, kP256PublicKeySize>;
using p256_signature = std::array<std::byte, kP256SignatureSize>;

// "openssl", "mbedtls", or "" when neither is built.
[[nodiscard]] std::string_view p256_backend() noexcept;

// The public key of the scalar `d`; kInvalidArgument when d is 0 or not below the group order.
[[nodiscard]] result<p256_public_key> p256_public_from_private(std::span<const std::byte, kP256PrivateKeySize> d);

// ECDSA over SHA-256(message) with a random nonce: two signatures of one message differ.
[[nodiscard]] result<p256_signature> p256_sign(std::span<const std::byte, kP256PrivateKeySize> d, std::span<const std::byte> message);

// Success when `signature` is the key's signature of `message`; kBadSignature when it isn't,
// kInvalidArgument when `public_key` is no point on the curve.
[[nodiscard]] result<void> p256_verify(std::span<const std::byte, kP256PublicKeySize> public_key, std::span<const std::byte> message,
                                       std::span<const std::byte, kP256SignatureSize> signature);

} // namespace Rhp::security::tls::detail
