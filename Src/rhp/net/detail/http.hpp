#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>

// HTTP/1.1 message heads (RFC 9112), shared by the WebSocket upgrade and the host's HTTP frontend.
namespace Rhp::net::detail {

inline constexpr std::size_t kMaxHttpHead = 16 * 1024; // request/status line plus every field
inline constexpr std::size_t kMaxHttpFields = 64;

struct http_head {
    std::string first_line;
    std::vector<std::pair<std::string, std::string>> fields; // names lowercased
    std::size_t bytes = 0;                                   // the head's length, blank line included
    std::size_t content_length = 0;

    // The value of a field (names compare case-insensitively); empty when absent.
    [[nodiscard]] std::string_view header(std::string_view name) const noexcept;
};

// The head at the start of `input`: nullopt while incomplete. Refuses obsolete line folding,
// duplicate fields, any Transfer-Encoding and a Content-Length above `max_body`.
[[nodiscard]] result<std::optional<http_head>> parse_http_head(std::string_view input, std::size_t max_body);
// True when the comma-separated field `value` lists `token` (case-insensitively).
[[nodiscard]] bool http_token(std::string_view value, std::string_view token) noexcept;
[[nodiscard]] std::string_view reason_phrase(unsigned status) noexcept;

} // namespace Rhp::net::detail
