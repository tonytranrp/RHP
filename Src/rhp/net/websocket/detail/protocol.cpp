#include <algorithm>
#include <array>
#include <bit>
#include <format>

#include <rhp/net/websocket/detail/protocol.hpp>
#include <rhp/utils/base64.hpp>

namespace Rhp::net::detail::ws {

namespace {

constexpr const char* kWhere = "net.websocket";
constexpr std::string_view kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr std::size_t kKeyBytes = 16;

// SHA-1 (FIPS 180-4) for the upgrade challenge only: it authenticates nothing.
using sha1_digest = std::array<std::byte, 20>;

// Checked through the RFC 6455 accept-key vector in websocket_tests.cpp.
sha1_digest sha1(std::string_view text) {
    std::string padded{text};
    const auto bits = static_cast<std::uint64_t>(text.size()) * 8;
    padded += static_cast<char>(0x80);
    while (padded.size() % 64 != 56) {
        padded += '\0';
    }
    for (int i = 7; i >= 0; --i) {
        padded += static_cast<char>(bits >> (i * 8));
    }
    std::array<std::uint32_t, 5> h{0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
    for (std::size_t block = 0; block < padded.size(); block += 64) {
        std::array<std::uint32_t, 80> w{};
        for (std::size_t i = 0; i < 16; ++i) {
            for (std::size_t j = 0; j < 4; ++j) {
                w[i] = (w[i] << 8) | static_cast<unsigned char>(padded[block + i * 4 + j]);
            }
        }
        for (std::size_t i = 16; i < 80; ++i) {
            w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        auto [a, b, c, d, e] = h;
        for (std::size_t i = 0; i < 80; ++i) {
            std::uint32_t f = 0;
            std::uint32_t k = 0;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5a827999u;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ed9eba1u;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8f1bbcdcu;
            } else {
                f = b ^ c ^ d;
                k = 0xca62c1d6u;
            }
            const auto next = std::rotl(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = std::rotl(b, 30);
            b = a;
            a = next;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
    sha1_digest out{};
    for (std::size_t i = 0; i < h.size(); ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            out[i * 4 + j] = static_cast<std::byte>(h[i] >> (24 - 8 * j));
        }
    }
    return out;
}

[[nodiscard]] bool sendable_status(unsigned status) noexcept {
    // 1004-1006 and 1015 are reserved for local reporting; 1016-2999 are unassigned protocol codes.
    return (status >= 1000 && status <= 1003) || (status >= 1007 && status <= 1014) || (status >= 3000 && status <= 4999);
}

[[nodiscard]] bool valid_utf8(utils::bytes_view text) noexcept {
    for (std::size_t i = 0; i < text.size();) {
        const auto lead = std::to_integer<unsigned>(text[i++]);
        if (lead < 0x80) {
            continue;
        }
        // Continuation bytes, payload bits of the lead byte, smallest code point that length may encode.
        struct sequence {
            unsigned extra;
            std::uint32_t bits;
            std::uint32_t least;
        };
        const sequence seq = lead >= 0xc2 && lead <= 0xdf   ? sequence{1, lead & 0x1fu, 0x80}
                             : lead >= 0xe0 && lead <= 0xef ? sequence{2, lead & 0x0fu, 0x800}
                             : lead >= 0xf0 && lead <= 0xf4 ? sequence{3, lead & 0x07u, 0x10000}
                                                            : sequence{0, 0, 0};
        const auto [extra, bits, least] = seq;
        std::uint32_t code = bits;
        if (extra == 0 || text.size() - i < extra) {
            return false;
        }
        for (unsigned n = 0; n < extra; ++n) {
            const auto next = std::to_integer<unsigned>(text[i++]);
            if ((next & 0xc0) != 0x80) {
                return false;
            }
            code = (code << 6) | (next & 0x3f);
        }
        if (code < least || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool known_opcode(unsigned op) noexcept {
    return op <= 0x2 || (op >= 0x8 && op <= 0xA);
}

} // namespace

result<std::optional<frame_header>> decode_header(utils::bytes_view input, role from) {
    if (input.size() < 2) {
        return std::optional<frame_header>{};
    }
    const auto first = std::to_integer<unsigned>(input[0]);
    const auto second = std::to_integer<unsigned>(input[1]);
    frame_header out;
    out.fin = (first & 0x80) != 0;
    const unsigned op = first & 0x0f;
    const bool masked = (second & 0x80) != 0;
    if ((first & 0x70) != 0 || !known_opcode(op)) {
        return fail(errc::kProtocol, "WebSocket reserved bits or unknown opcode", kWhere);
    }
    out.op = static_cast<opcode>(op);
    if (out.op == opcode::kText) {
        return fail(errc::kProtocol, "RHP WebSocket carries binary messages only", kWhere);
    }
    if (masked != (from == role::kClient)) {
        return fail(errc::kProtocol, "WebSocket clients must mask and servers must not", kWhere);
    }
    std::uint64_t length = second & 0x7f;
    std::size_t at = 2;
    if (length >= 126) {
        const std::size_t width = length == 126 ? 2 : 8;
        if (input.size() < at + width) {
            return std::optional<frame_header>{};
        }
        length = 0;
        for (std::size_t i = 0; i < width; ++i) {
            length = (length << 8) | std::to_integer<std::uint64_t>(input[at + i]);
        }
        at += width;
        if ((width == 2 && length < 126) || (width == 8 && length <= 0xffff)) {
            return fail(errc::kProtocol, "WebSocket length is not minimally encoded", kWhere);
        }
    }
    if (is_control(out.op) && (!out.fin || length > kMaxControlPayload)) {
        return fail(errc::kProtocol, "WebSocket control frames are short and unfragmented", kWhere);
    }
    if (length > kMaxMessage) {
        return fail(errc::kLimitExceeded, "WebSocket frame exceeds 16 MiB", kWhere);
    }
    if (masked) {
        if (input.size() < at + 4) {
            return std::optional<frame_header>{};
        }
        masking_key key{};
        std::ranges::copy(input.subspan(at, 4), key.begin());
        out.mask = key;
        at += 4;
    }
    out.payload = length;
    out.bytes = at;
    return std::optional<frame_header>{out};
}

void encode_frame(utils::byte_buffer& out, opcode op, utils::bytes_view payload, std::optional<masking_key> mask) {
    const auto n = static_cast<std::uint64_t>(payload.size());
    std::array<std::byte, kMaxHeaderBytes> header{};
    std::size_t at = 0;
    header[at++] = static_cast<std::byte>(0x80 | static_cast<unsigned>(op));
    const unsigned mask_bit = mask ? 0x80 : 0;
    if (n < 126) {
        header[at++] = static_cast<std::byte>(mask_bit | static_cast<unsigned>(n));
    } else {
        const std::size_t width = n <= 0xffff ? 2 : 8;
        header[at++] = static_cast<std::byte>(mask_bit | (width == 2 ? 126u : 127u));
        for (std::size_t i = width; i != 0; --i) {
            header[at++] = static_cast<std::byte>(n >> (8 * (i - 1)));
        }
    }
    if (mask) {
        std::ranges::copy(*mask, header.begin() + static_cast<std::ptrdiff_t>(at));
        at += mask->size();
    }
    out.reserve(out.size() + at + payload.size());
    out.append(utils::bytes_view{header.data(), at});
    const auto offset = out.size();
    out.append(payload);
    if (mask) {
        apply_mask(out.mutable_view().subspan(offset), *mask);
    }
}

bool valid_close_payload(utils::bytes_view payload) noexcept {
    if (payload.empty()) {
        return true;
    }
    if (payload.size() < 2) {
        return false;
    }
    const auto status = (std::to_integer<unsigned>(payload[0]) << 8) | std::to_integer<unsigned>(payload[1]);
    return sendable_status(status) && valid_utf8(payload.subspan(2));
}

std::array<std::byte, 2> close_payload(close_code code) noexcept {
    const auto n = static_cast<unsigned>(code);
    return {static_cast<std::byte>(n >> 8), static_cast<std::byte>(n)};
}

std::string accept_key(std::string_view client_key) {
    std::string text{client_key};
    text += kGuid;
    return utils::base64_encode(sha1(text));
}

std::string upgrade_request(std::string_view host, std::string_view key) {
    return std::format("GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", kPath, host, key);
}

std::string upgrade_response(std::string_view client_key) {
    return std::format("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept_key(client_key));
}

result<std::string> accept_upgrade(const http_head& request) {
    const auto key = request.header("sec-websocket-key");
    const bool valid = request.first_line == std::format("GET {} HTTP/1.1", kPath) && !request.header("host").empty() &&
                       http_token(request.header("connection"), "upgrade") && http_token(request.header("upgrade"), "websocket") &&
                       request.header("sec-websocket-version") == "13" && utils::is_base64_of(key, kKeyBytes);
    if (!valid) {
        return fail(errc::kProtocol, "invalid WebSocket upgrade request", kWhere);
    }
    return std::string{key};
}

result<void> check_upgrade_response(const http_head& response, std::string_view key) {
    const auto& status = response.first_line;
    const bool valid = (status == "HTTP/1.1 101" || status.starts_with("HTTP/1.1 101 ")) && http_token(response.header("connection"), "upgrade") &&
                       http_token(response.header("upgrade"), "websocket") && response.header("sec-websocket-accept") == accept_key(key) &&
                       response.header("sec-websocket-extensions").empty() && response.header("sec-websocket-protocol").empty();
    if (!valid) {
        return fail(errc::kProtocol, "invalid WebSocket upgrade response", kWhere);
    }
    return {};
}

} // namespace Rhp::net::detail::ws
