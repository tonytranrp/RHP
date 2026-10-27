#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace Rhp::security {

// A 32-byte digest (BLAKE2b-256): what the audit log records for every script source.
using digest256 = std::array<std::byte, 32>;

[[nodiscard]] digest256 blake2b_256(std::span<const std::byte> data) noexcept;
[[nodiscard]] digest256 blake2b_256(std::string_view text) noexcept;

// Keyed BLAKE2b-256 (a MAC) of domain || data. `key` is 1..64 bytes (BLAKE2b's limit); a longer
// one is cut to 64 bytes, an empty one gives an unkeyed hash.
[[nodiscard]] digest256 keyed_blake2b_256(std::span<const std::byte> key, std::string_view domain, std::span<const std::byte> data) noexcept;

// a == b in constant time (MACs and proofs).
[[nodiscard]] bool digests_equal(std::span<const std::byte, 32> a, std::span<const std::byte, 32> b) noexcept;

// Lowercase hex ("3fa0..."). Built with RHP_ENABLE=OFF too (key.cpp).
[[nodiscard]] std::string to_hex(std::span<const std::byte> bytes);

} // namespace Rhp::security
