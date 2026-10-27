#pragma once

#include <cstddef>
#include <string_view>

namespace Rhp::utils {

// Bytes in the well-formed UTF-8 sequence that starts at text[at] (1 to 4), or 0 when none starts
// there: a continuation byte, a lead byte that never starts one (0xC0, 0xC1, 0xF5-0xFF), a missing or
// wrong continuation byte, an overlong form, a surrogate (U+D800-U+DFFF) or a code point above
// U+10FFFF. Strict, for text written where invalid bytes must not pass (JSON lines, XML reports).
[[nodiscard]] constexpr std::size_t utf8_sequence_length(std::string_view text, std::size_t at) noexcept {
    if (at >= text.size()) {
        return 0;
    }
    const auto b = [&](std::size_t k) { return static_cast<unsigned char>(text[at + k]); };
    const auto cont = [&](std::size_t k) { return at + k < text.size() && (b(k) & 0xC0u) == 0x80u; };
    const unsigned char c = b(0);
    if (c < 0x80) {
        return 1;
    }
    if (c >= 0xC2 && c <= 0xDF) {
        return cont(1) ? 2 : 0;
    }
    if (c >= 0xE0 && c <= 0xEF) {
        if (!cont(1) || !cont(2) || (c == 0xE0 && b(1) < 0xA0) || (c == 0xED && b(1) > 0x9F)) {
            return 0;
        }
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (!cont(1) || !cont(2) || !cont(3) || (c == 0xF0 && b(1) < 0x90) || (c == 0xF4 && b(1) > 0x8F)) {
            return 0;
        }
        return 4;
    }
    return 0;
}

} // namespace Rhp::utils
