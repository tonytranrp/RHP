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

// Lowercase hex ("3fa0...").
[[nodiscard]] std::string to_hex(std::span<const std::byte> bytes);

} // namespace Rhp::security
