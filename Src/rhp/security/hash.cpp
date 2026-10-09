#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <monocypher.h>

#include <rhp/security/hash.hpp>

namespace Rhp::security {

digest256 blake2b_256(std::span<const std::byte> data) noexcept {
    digest256 out{};
    crypto_blake2b(reinterpret_cast<std::uint8_t*>(out.data()), out.size(), reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    return out;
}

digest256 blake2b_256(std::string_view text) noexcept {
    return blake2b_256(std::as_bytes(std::span{text.data(), text.size()}));
}

std::string to_hex(std::span<const std::byte> bytes) {
    constexpr std::string_view kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::byte b : bytes) {
        const auto n = std::to_integer<unsigned>(b);
        out += kDigits[n >> 4];
        out += kDigits[n & 15u];
    }
    return out;
}

} // namespace Rhp::security
