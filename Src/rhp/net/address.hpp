#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace Rhp::net {

// An IP address. IPv4 is kept in its IPv4-mapped IPv6 form (::ffff:a.b.c.d), so one comparison covers
// both. Network transports report their peer's (link::address()): admission control counts
// unauthenticated connections per source by it.
class ip_address {
public:
    using bytes_type = std::array<std::uint8_t, 16>;

    constexpr ip_address() noexcept = default;
    constexpr explicit ip_address(const bytes_type& v6) noexcept : bytes_(v6) {}

    [[nodiscard]] static constexpr ip_address v4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
        return ip_address{bytes_type{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d}};
    }

    // Dotted IPv4 ("192.168.1.20": four decimal parts, no leading zeros) or IPv6 text ("fe80::1",
    // "::ffff:10.0.0.1"; brackets and a zone such as "%eth0" are allowed). Anything else, host names
    // such as "cafe1" or "db1.de" included, is nullopt.
    [[nodiscard]] static constexpr std::optional<ip_address> parse(std::string_view text) noexcept;

    [[nodiscard]] constexpr const bytes_type& bytes() const noexcept { return bytes_; }

    [[nodiscard]] constexpr bool is_v4() const noexcept {
        for (std::size_t i = 0; i < 10; ++i) {
            if (bytes_[i] != 0) {
                return false;
            }
        }
        return bytes_[10] == 0xff && bytes_[11] == 0xff;
    }

    // Who a connection comes from, for per-source limits: the IPv4 address, or the IPv6 /64 (one
    // machine usually holds a whole /64).
    [[nodiscard]] constexpr ip_address source() const noexcept {
        if (is_v4()) {
            return *this;
        }
        bytes_type prefix = bytes_;
        for (std::size_t i = 8; i < 16; ++i) {
            prefix[i] = 0;
        }
        return ip_address{prefix};
    }

    [[nodiscard]] constexpr auto operator<=>(const ip_address&) const noexcept = default;

private:
    bytes_type bytes_{};
};

namespace detail {

[[nodiscard]] constexpr int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

// Four decimal parts of 0-255 without leading zeros (as inet_pton reads them).
[[nodiscard]] constexpr std::optional<std::array<std::uint8_t, 4>> parse_ipv4(std::string_view text) noexcept {
    std::array<std::uint8_t, 4> out{};
    std::size_t at = 0;
    for (std::size_t part = 0; part < out.size(); ++part) {
        if (part != 0) {
            if (at >= text.size() || text[at] != '.') {
                return std::nullopt;
            }
            ++at;
        }
        const std::size_t start = at;
        unsigned value = 0;
        while (at < text.size() && text[at] >= '0' && text[at] <= '9') {
            value = value * 10 + static_cast<unsigned>(text[at] - '0');
            if (value > 255) {
                return std::nullopt;
            }
            ++at;
        }
        if (at == start || (at - start > 1 && text[start] == '0')) {
            return std::nullopt;
        }
        out[part] = static_cast<std::uint8_t>(value);
    }
    if (at != text.size()) {
        return std::nullopt;
    }
    return out;
}

// RFC 4291 text: up to eight groups of 1-4 hex digits, one "::" for a run of zero groups, and an
// optional dotted IPv4 tail in the last 32 bits.
[[nodiscard]] constexpr std::optional<ip_address::bytes_type> parse_ipv6(std::string_view text) noexcept {
    std::array<std::uint16_t, 8> head{};
    std::array<std::uint16_t, 8> tail{};
    std::size_t heads = 0;
    std::size_t tails = 0;
    bool gap = false;
    const auto push = [&](std::uint16_t group) noexcept {
        if (heads + tails == 8) {
            return false;
        }
        (gap ? tail[tails++] : head[heads++]) = group;
        return true;
    };
    std::size_t at = 0;
    if (text.starts_with("::")) {
        gap = true;
        at = 2;
    } else if (text.empty() || text.front() == ':') {
        return std::nullopt;
    }
    while (at < text.size()) {
        const std::size_t start = at;
        unsigned group = 0;
        while (at < text.size() && at - start < 4 && hex_value(text[at]) >= 0) {
            group = group * 16 + static_cast<unsigned>(hex_value(text[at]));
            ++at;
        }
        if (at < text.size() && text[at] == '.') {
            const auto v4 = parse_ipv4(text.substr(start));
            if (!v4 || !push(static_cast<std::uint16_t>(((*v4)[0] << 8) | (*v4)[1])) || !push(static_cast<std::uint16_t>(((*v4)[2] << 8) | (*v4)[3]))) {
                return std::nullopt;
            }
            at = text.size();
            break;
        }
        if (at == start || (at < text.size() && hex_value(text[at]) >= 0) || !push(static_cast<std::uint16_t>(group))) {
            return std::nullopt;
        }
        if (at == text.size()) {
            break;
        }
        if (text[at] != ':' || ++at == text.size()) {
            return std::nullopt;
        }
        if (text[at] == ':') {
            if (gap) {
                return std::nullopt;
            }
            gap = true;
            ++at;
        }
    }
    if (gap ? heads + tails > 7 : heads != 8) {
        return std::nullopt;
    }
    ip_address::bytes_type out{};
    for (std::size_t i = 0; i < heads; ++i) {
        out[2 * i] = static_cast<std::uint8_t>(head[i] >> 8);
        out[2 * i + 1] = static_cast<std::uint8_t>(head[i] & 0xff);
    }
    for (std::size_t i = 0; i < tails; ++i) {
        const std::size_t group = 8 - tails + i;
        out[2 * group] = static_cast<std::uint8_t>(tail[i] >> 8);
        out[2 * group + 1] = static_cast<std::uint8_t>(tail[i] & 0xff);
    }
    return out;
}

} // namespace detail

constexpr std::optional<ip_address> ip_address::parse(std::string_view text) noexcept {
    constexpr std::size_t kMaxText = 64; // the longest IPv6 text with a zone fits easily
    if (text.size() >= 2 && text.front() == '[' && text.back() == ']') {
        text = text.substr(1, text.size() - 2);
        if (text.find(':') == std::string_view::npos) {
            return std::nullopt; // brackets are for IPv6
        }
    }
    if (text.empty() || text.size() > kMaxText) {
        return std::nullopt;
    }
    if (text.find(':') == std::string_view::npos) {
        const auto v4 = detail::parse_ipv4(text);
        if (!v4) {
            return std::nullopt;
        }
        return ip_address::v4((*v4)[0], (*v4)[1], (*v4)[2], (*v4)[3]);
    }
    if (const auto zone = text.find('%'); zone != std::string_view::npos) {
        if (zone + 1 == text.size()) {
            return std::nullopt;
        }
        text = text.substr(0, zone);
    }
    const auto v6 = detail::parse_ipv6(text);
    if (!v6) {
        return std::nullopt;
    }
    return ip_address{*v6};
}

} // namespace Rhp::net
