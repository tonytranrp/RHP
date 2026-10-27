#pragma once

#include <cstddef>
#include <cstdint>

namespace Rhp::security::detail {

// std::byte pointers as the uint8_t pointers C crypto libraries (Monocypher) take.
[[nodiscard]] inline const std::uint8_t* u8(const std::byte* p) noexcept {
    return reinterpret_cast<const std::uint8_t*>(p);
}

[[nodiscard]] inline std::uint8_t* u8(std::byte* p) noexcept {
    return reinterpret_cast<std::uint8_t*>(p);
}

// Text bytes for the same libraries.
[[nodiscard]] inline const std::uint8_t* u8(const char* p) noexcept {
    return reinterpret_cast<const std::uint8_t*>(p);
}

} // namespace Rhp::security::detail
