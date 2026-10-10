#include <algorithm>
#include <cctype>
#include <charconv>

#include <rhp/net/detail/http.hpp>

namespace Rhp::net::detail {

namespace {

char lower(char c) noexcept {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

bool token_char(unsigned char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           std::string_view{"!#$%&'*+-.^_`|~"}.find(static_cast<char>(c)) != std::string_view::npos;
}

[[nodiscard]] bool equal_nocase(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) { return lower(x) == lower(y); });
}

} // namespace

std::string_view http_head::header(std::string_view name) const noexcept {
    for (const auto& [key, value] : fields) {
        if (equal_nocase(key, name)) {
            return value;
        }
    }
    return {};
}

std::string_view reason_phrase(unsigned status) noexcept {
    switch (status) {
    case 100: return "Continue";
    case 101: return "Switching Protocols";
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 413: return "Content Too Large";
    case 415: return "Unsupported Media Type";
    case 422: return "Unprocessable Content";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "Unknown";
    }
}

bool http_token(std::string_view value, std::string_view token) noexcept {
    while (!value.empty()) {
        const auto comma = value.find(',');
        const auto part = trim(value.substr(0, comma));
        if (equal_nocase(part, token)) {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        value.remove_prefix(comma + 1);
    }
    return false;
}

result<std::optional<http_head>> parse_http_head(std::string_view input, std::size_t max_body) {
    const auto end = input.find("\r\n\r\n");
    if (end == std::string_view::npos) {
        if (input.size() > kMaxHttpHead) {
            return fail(errc::kLimitExceeded, "HTTP headers exceed 16 KiB", "net.http");
        }
        return std::optional<http_head>{};
    }
    if (end + 4 > kMaxHttpHead) {
        return fail(errc::kLimitExceeded, "HTTP headers exceed 16 KiB", "net.http");
    }
    http_head out;
    out.bytes = end + 4;
    auto lines = input.substr(0, end + 2);
    const auto first = lines.find("\r\n");
    out.first_line = lines.substr(0, first);
    if (out.first_line.empty() || std::ranges::any_of(out.first_line, [](unsigned char c) { return c < 32 || c == 127; })) {
        return fail(errc::kProtocol, "invalid HTTP request/status line", "net.http");
    }
    lines.remove_prefix(first + 2);
    while (!lines.empty()) {
        const auto stop = lines.find("\r\n");
        const auto line = lines.substr(0, stop);
        const auto colon = line.find(':');
        if (colon == 0 || colon == std::string_view::npos || !std::ranges::all_of(line.substr(0, colon), token_char)) {
            return fail(errc::kProtocol, "invalid HTTP header name", "net.http");
        }
        std::string key{line.substr(0, colon)};
        std::ranges::transform(key, key.begin(), lower);
        const auto value = trim(line.substr(colon + 1));
        if (std::ranges::any_of(value, [](unsigned char c) { return (c < 32 && c != '\t') || c == 127; }) ||
            std::ranges::any_of(out.fields, [&](const auto& field) { return field.first == key; })) {
            return fail(errc::kProtocol, "invalid or duplicate HTTP header", "net.http");
        }
        if (key == "transfer-encoding") {
            return fail(errc::kProtocol, "HTTP transfer coding is not supported; use Content-Length", "net.http");
        }
        if (key == "content-length") {
            const auto [at, ec] = std::from_chars(value.data(), value.data() + value.size(), out.content_length);
            if (ec != std::errc{} || at != value.data() + value.size() || out.content_length > max_body) {
                return fail(errc::kLimitExceeded, "invalid or excessive HTTP Content-Length", "net.http");
            }
        }
        out.fields.emplace_back(std::move(key), std::string{value});
        if (out.fields.size() > kMaxHttpFields) {
            return fail(errc::kLimitExceeded, "too many HTTP headers", "net.http");
        }
        lines.remove_prefix(stop + 2);
    }
    return std::optional<http_head>{std::move(out)};
}

} // namespace Rhp::net::detail
