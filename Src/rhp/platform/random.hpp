#pragma once

#include <array>
#include <cstddef>
#include <span>

#include <rhp/core/result.hpp>

namespace Rhp::platform {

// Fills `out` from the OS cryptographic random source (BCryptGenRandom, getrandom, arc4random_buf).
// Used for handshake nonces and idempotency keys. Fails with kInvalidArgument only if the OS source
// itself fails.
result<void> random_bytes(std::span<std::byte> out);

template <std::size_t N>
[[nodiscard]] result<std::array<std::byte, N>> random_array() {
    std::array<std::byte, N> out{};
    if (auto filled = random_bytes(out); !filled) {
        return std::unexpected{std::move(filled).error()};
    }
    return out;
}

} // namespace Rhp::platform
