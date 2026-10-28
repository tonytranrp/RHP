#pragma once

// Private to the security sources (psk_keyring.cpp, device_handshake.cpp): not in the module's
// HEADERS, not installed.

#include <cstddef>
#include <span>

#include <rhp/security/authenticator.hpp>

namespace Rhp::security::detail {

// A grant's frame sealers: keyed BLAKE2b-256 under MAC(key, "rhp/c2h" || t) for frames the client
// sends and MAC(key, "rhp/h2c" || t) for the host's, as the PSK handshake derives them (its sealer
// type). `key` is 1..64 bytes; `host_side` picks which one seals and which one verifies.
[[nodiscard]] auth_grant frame_keys(std::span<const std::byte> key, std::span<const std::byte> t, bool host_side);

} // namespace Rhp::security::detail
