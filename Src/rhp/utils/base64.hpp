#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Rhp::utils {

// Standard base64 (RFC 4648 §4, `+/`, `=` padding): key files, the WebSocket handshake and HTTP
// Authorization fields all use this one alphabet.
inline constexpr std::string_view kBase64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

[[nodiscard]] constexpr int base64_sextet(char c) noexcept {
    const auto at = kBase64Alphabet.find(c);
    return at == std::string_view::npos ? -1 : static_cast<int>(at);
}

[[nodiscard]] constexpr std::size_t base64_encoded_size(std::size_t bytes) noexcept {
    return (bytes + 2) / 3 * 4;
}

[[nodiscard]] constexpr std::string base64_encode(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve(base64_encoded_size(bytes.size()));
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        const std::size_t rest = bytes.size() - i;
        std::uint32_t n = std::to_integer<std::uint32_t>(bytes[i]) << 16;
        if (rest > 1) {
            n |= std::to_integer<std::uint32_t>(bytes[i + 1]) << 8;
        }
        if (rest > 2) {
            n |= std::to_integer<std::uint32_t>(bytes[i + 2]);
        }
        out += kBase64Alphabet[(n >> 18) & 63];
        out += kBase64Alphabet[(n >> 12) & 63];
        out += rest > 1 ? kBase64Alphabet[(n >> 6) & 63] : '=';
        out += rest > 2 ? kBase64Alphabet[n & 63] : '=';
    }
    return out;
}

// Strict decode: no whitespace, length a multiple of 4, padding only at the end. nullopt otherwise.
[[nodiscard]] constexpr std::optional<std::vector<std::byte>> base64_decode(std::string_view text) {
    if (text.size() % 4 != 0) {
        return std::nullopt;
    }
    std::vector<std::byte> out;
    out.reserve(text.size() / 4 * 3);
    for (std::size_t i = 0; i < text.size(); i += 4) {
        const bool last = i + 4 == text.size();
        std::uint32_t n = 0;
        int pad = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const char c = text[i + j];
            int value = 0;
            if (c == '=' && last && j >= 2) {
                ++pad;
            } else if (pad > 0 || (value = base64_sextet(c)) < 0) {
                return std::nullopt;
            }
            n = (n << 6) | static_cast<std::uint32_t>(value);
        }
        out.push_back(static_cast<std::byte>(n >> 16));
        if (pad < 2) {
            out.push_back(static_cast<std::byte>(n >> 8));
        }
        if (pad < 1) {
            out.push_back(static_cast<std::byte>(n));
        }
    }
    return out;
}

// True for exactly `bytes` of base64 text (the canonical, padded length).
[[nodiscard]] constexpr bool is_base64_of(std::string_view text, std::size_t bytes) {
    const auto decoded = text.size() == base64_encoded_size(bytes) ? base64_decode(text) : std::nullopt;
    return decoded && decoded->size() == bytes;
}

} // namespace Rhp::utils
