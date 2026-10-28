// Pairing formats (decision AL10): the QR link and the host's book of one-time secrets. No
// cryptography beyond the OS random source, so this builds with RHP_ENABLE=OFF too.
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/pairing.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

namespace {

constexpr const char* kLinkWhere = "security.pairing_link";
constexpr const char* kBookWhere = "security.pairing_book";
constexpr std::size_t kFingerprintBytes = 16;
constexpr std::size_t kMaxHostSize = 253;

[[nodiscard]] bool ascii_alpha(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] bool ascii_digit(char c) noexcept {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool hex_digit(char c) noexcept {
    return ascii_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

[[nodiscard]] unsigned hex_value(char c) noexcept {
    return ascii_digit(c) ? static_cast<unsigned>(c - '0') : static_cast<unsigned>((c | 0x20) - 'a' + 10);
}

[[nodiscard]] char lower(char c) noexcept {
    return ascii_alpha(c) ? static_cast<char>(c | 0x20) : c;
}

[[nodiscard]] bool equals_ignoring_case(std::string_view a, std::string_view b) noexcept {
    return std::ranges::equal(a, b, [](char x, char y) { return lower(x) == lower(y); });
}

// ---- base64url (unpadded) ------------------------------------------------------------------------

[[nodiscard]] std::string base64url_encode(std::span<const std::byte> bytes) {
    std::string text = base64_encode(bytes);
    std::ranges::replace(text, '+', '-');
    std::ranges::replace(text, '/', '_');
    while (!text.empty() && text.back() == '=') {
        text.pop_back();
    }
    return text;
}

// Exactly `size` bytes of canonical unpadded base64url, else nullopt. The caller wipes the bytes
// when they are secret.
[[nodiscard]] std::optional<std::vector<std::byte>> base64url_decode(std::string_view text, std::size_t size) {
    if (text.size() != (size * 4 + 2) / 3) {
        return std::nullopt;
    }
    std::string padded;
    padded.reserve(text.size() + 2);
    const utils::scope_guard wipe_padded{[&padded]() noexcept { secure_wipe(padded.data(), padded.size()); }};
    for (const char c : text) {
        if (c == '-') {
            padded += '+';
        } else if (c == '_') {
            padded += '/';
        } else if (ascii_alpha(c) || ascii_digit(c)) {
            padded += c;
        } else {
            return std::nullopt;
        }
    }
    while (padded.size() % 4 != 0) {
        padded += '=';
    }
    auto bytes = base64_decode(padded);
    if (!bytes) {
        return std::nullopt;
    }
    // Canonical: the right size, and the unused low bits of the last character are zero.
    std::string again = base64url_encode(*bytes);
    const bool canonical = bytes->size() == size && again == text;
    secure_wipe(again.data(), again.size());
    if (!canonical) {
        secure_wipe(bytes->data(), bytes->size());
        return std::nullopt;
    }
    return std::move(*bytes);
}

// ---- fields --------------------------------------------------------------------------------------

// A DNS name or IPv4 address: labels of letters, digits and '-' (not at either end), 1..63 each.
[[nodiscard]] bool valid_dns_host(std::string_view host) noexcept {
    if (host.empty() || host.size() > kMaxHostSize) {
        return false;
    }
    std::size_t label = 0;
    char previous = '.';
    for (const char c : host) {
        if (c == '.') {
            if (label == 0 || previous == '-') {
                return false;
            }
            label = 0;
        } else if (ascii_alpha(c) || ascii_digit(c) || c == '-') {
            if ((label == 0 && c == '-') || ++label > 63) {
                return false;
            }
        } else {
            return false;
        }
        previous = c;
    }
    return label != 0 && previous != '-';
}

// An IPv6 address's text (no brackets, no zone): hex digits, colons and an IPv4 tail. The network
// layer parses it for real; this keeps anything else out of a link.
[[nodiscard]] bool valid_ipv6_host(std::string_view host) noexcept {
    if (host.size() < 2 || host.size() > 45 || std::ranges::count(host, ':') < 2) {
        return false;
    }
    return std::ranges::all_of(host, [](char c) { return hex_digit(c) || c == ':' || c == '.'; });
}

[[nodiscard]] bool valid_host(std::string_view host) noexcept {
    return host.find(':') != std::string_view::npos ? valid_ipv6_host(host) : valid_dns_host(host);
}

[[nodiscard]] bool valid_name(std::string_view name) noexcept {
    return name.size() <= pairing_link::kMaxNameSize && std::ranges::none_of(name, [](char c) {
               const auto byte = static_cast<unsigned char>(c);
               return byte < 0x20 || byte == 0x7f;
           });
}

[[nodiscard]] bool valid_fingerprint(std::string_view text) {
    return base64url_decode(text, kFingerprintBytes).has_value();
}

[[nodiscard]] bool unreserved(char c) noexcept {
    return ascii_alpha(c) || ascii_digit(c) || c == '-' || c == '.' || c == '_' || c == '~';
}

[[nodiscard]] std::string percent_encode(std::string_view text) {
    constexpr std::string_view kHex = "0123456789ABCDEF";
    std::string out;
    for (const char c : text) {
        if (unreserved(c)) {
            out += c;
        } else {
            const auto byte = static_cast<unsigned char>(c);
            out += '%';
            out += kHex[byte >> 4];
            out += kHex[byte & 15u];
        }
    }
    return out;
}

// Unreserved characters and %XX escapes only.
[[nodiscard]] std::optional<std::string> percent_decode(std::string_view text) {
    std::string out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '%') {
            if (i + 2 >= text.size() || !hex_digit(text[i + 1]) || !hex_digit(text[i + 2])) {
                return std::nullopt;
            }
            out += static_cast<char>((hex_value(text[i + 1]) << 4) | hex_value(text[i + 2]));
            i += 2;
        } else if (unreserved(c)) {
            out += c;
        } else {
            return std::nullopt;
        }
    }
    return out;
}

[[nodiscard]] std::unexpected<error> bad_link(std::string_view why) {
    return fail(errc::kInvalidArgument, std::format("pairing link: {}", why), kLinkWhere);
}

// a == b in constant time for equal sizes (pairing secrets).
[[nodiscard]] bool equal_constant_time(std::span<const std::byte> a, std::span<const std::byte> b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= std::to_integer<unsigned>(a[i] ^ b[i]);
    }
    return diff == 0;
}

[[nodiscard]] bool expired_at(const pairing_secret& s, std::chrono::steady_clock::time_point now) noexcept {
    return s.expires <= now;
}

} // namespace

// ---- pairing_link --------------------------------------------------------------------------------

result<pairing_link> pairing_link::parse(std::string_view text) {
    constexpr std::string_view kSeparator = "://";
    if (text.size() < kPairingScheme.size() + kSeparator.size() || !equals_ignoring_case(text.substr(0, kPairingScheme.size()), kPairingScheme) ||
        text.substr(kPairingScheme.size(), kSeparator.size()) != kSeparator) {
        return bad_link("not an rhp-pair:// link");
    }
    text.remove_prefix(kPairingScheme.size() + kSeparator.size());
    if (text.find('#') != std::string_view::npos) {
        return bad_link("a fragment is not allowed");
    }
    const auto query_at = text.find('?');
    const std::string_view authority = text.substr(0, query_at);
    const std::string_view query = query_at == std::string_view::npos ? std::string_view{} : text.substr(query_at + 1);
    if (authority.find('/') != std::string_view::npos) {
        return bad_link("a path is not allowed");
    }
    if (authority.find('@') != std::string_view::npos) {
        return bad_link("user information is not allowed");
    }

    pairing_link link;
    std::string_view port_text;
    if (authority.starts_with('[')) {
        const auto close = authority.find(']');
        if (close == std::string_view::npos || authority.substr(close + 1, 1) != ":") {
            return bad_link("an IPv6 host is [address]:port");
        }
        link.host = authority.substr(1, close - 1);
        if (!valid_ipv6_host(link.host)) {
            return bad_link("not an IPv6 address");
        }
        port_text = authority.substr(close + 2);
    } else {
        const auto colon = authority.rfind(':');
        if (colon == std::string_view::npos) {
            return bad_link("the port is missing");
        }
        link.host = authority.substr(0, colon);
        if (!valid_dns_host(link.host)) {
            return bad_link("not a host name or IPv4 address (an IPv6 address goes in brackets)");
        }
        port_text = authority.substr(colon + 1);
    }
    unsigned port = 0;
    const auto [end, ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
    if (port_text.empty() || port_text.size() > 5 || port_text.front() == '0' || ec != std::errc{} || end != port_text.data() + port_text.size() ||
        port > 65535) {
        return bad_link("the port must be 1..65535");
    }
    link.port = static_cast<std::uint16_t>(port);

    bool have_secret = false;
    bool have_fingerprint = false;
    bool have_name = false;
    std::string_view rest = query;
    bool more = !rest.empty();
    while (more) {
        const auto amp = rest.find('&');
        const std::string_view field = rest.substr(0, amp);
        more = amp != std::string_view::npos;
        rest = more ? rest.substr(amp + 1) : std::string_view{};
        const auto eq = field.find('=');
        if (eq == std::string_view::npos) {
            return bad_link("every query field is key=value");
        }
        const std::string_view name = field.substr(0, eq);
        const std::string_view value = field.substr(eq + 1);
        if (name == "secret") {
            if (have_secret) {
                return bad_link("'secret' appears twice");
            }
            have_secret = true;
            auto bytes = base64url_decode(value, kPairingSecretSize);
            if (!bytes) {
                return bad_link("the secret must be 32 bytes of unpadded base64url");
            }
            auto secret = key::from_bytes(*bytes);
            secure_wipe(bytes->data(), bytes->size());
            if (!secret) {
                return std::unexpected{std::move(secret).error()};
            }
            link.secret = std::move(*secret);
        } else if (name == "fp") {
            if (have_fingerprint) {
                return bad_link("'fp' appears twice");
            }
            have_fingerprint = true;
            if (!valid_fingerprint(value)) {
                return bad_link("'fp' must be a key fingerprint (22 characters of unpadded base64url)");
            }
            link.fingerprint = value;
        } else if (name == "name") {
            if (have_name) {
                return bad_link("'name' appears twice");
            }
            have_name = true;
            auto decoded = percent_decode(value);
            if (!decoded || !valid_name(*decoded)) {
                return bad_link("'name' must be percent-encoded, at most 128 bytes, without control characters");
            }
            link.name = std::move(*decoded);
        } else {
            auto shown = percent_encode(name.substr(0, 16));
            return bad_link(std::format("unknown key '{}'", shown));
        }
    }
    if (!have_secret) {
        return bad_link("'secret' is missing");
    }
    if (!have_fingerprint) {
        return bad_link("'fp' is missing");
    }
    return link;
}

result<std::string> pairing_link::to_text() const {
    if (!valid_host(host)) {
        return bad_link("not a host name, IPv4 or IPv6 address");
    }
    if (port == 0) {
        return bad_link("the port must be 1..65535");
    }
    if (secret.bytes().size() != kPairingSecretSize) {
        return bad_link("the secret must be 32 bytes");
    }
    if (!valid_fingerprint(fingerprint)) {
        return bad_link("not a key fingerprint");
    }
    if (!valid_name(name)) {
        return bad_link("the name is too long or has control characters");
    }
    const bool bracket = host.find(':') != std::string::npos;
    std::string text = std::format("{}://{}{}{}:{}?secret=", kPairingScheme, bracket ? "[" : "", host, bracket ? "]" : "", port);
    std::string encoded = base64url_encode(secret.bytes());
    text += encoded;
    secure_wipe(encoded.data(), encoded.size());
    text += "&fp=";
    text += fingerprint;
    if (!name.empty()) {
        text += "&name=";
        text += percent_encode(name);
    }
    return text;
}

// ---- pairing_book --------------------------------------------------------------------------------

result<pairing_secret> pairing_book::issue(clock::duration lifetime, clock::time_point now) {
    if (lifetime <= clock::duration::zero()) {
        return fail(errc::kInvalidArgument, "a pairing secret's lifetime must be positive", kBookWhere);
    }
    auto bytes = platform::random_array<kPairingSecretSize>();
    if (!bytes) {
        return std::unexpected{std::move(bytes).error()};
    }
    const utils::scope_guard wipe{[&bytes]() noexcept { secure_wipe(bytes->data(), bytes->size()); }};
    auto value = key::from_bytes(*bytes);
    if (!value) {
        return std::unexpected{std::move(value).error()};
    }
    pairing_secret secret{.value = std::move(*value), .expires = now + lifetime};

    const std::scoped_lock lock{mutex_};
    std::erase_if(secrets_, [now](const pairing_secret& s) { return expired_at(s, now); });
    if (secrets_.size() >= capacity_) {
        return fail(errc::kLimitExceeded, std::format("{} pairing secrets are already outstanding", secrets_.size()), kBookWhere);
    }
    secrets_.push_back(secret);
    return secret;
}

result<void> pairing_book::consume(std::span<const std::byte> presented, clock::time_point now) {
    const std::scoped_lock lock{mutex_};
    std::size_t match = secrets_.size();
    if (presented.size() == kPairingSecretSize) {
        // Every entry is compared, whatever matched before.
        for (std::size_t i = 0; i < secrets_.size(); ++i) {
            const bool same = equal_constant_time(secrets_[i].value.bytes(), presented);
            match = same ? i : match;
        }
    }
    bool expired = false;
    const bool found = match != secrets_.size();
    if (found) {
        expired = expired_at(secrets_[match], now);
        secrets_.erase(secrets_.begin() + static_cast<std::ptrdiff_t>(match));
    }
    std::erase_if(secrets_, [now](const pairing_secret& s) { return expired_at(s, now); });
    if (!found) {
        return fail(errc::kAuth, "not an outstanding pairing secret", kBookWhere);
    }
    if (expired) {
        return fail(errc::kExpired, "the pairing secret has expired", kBookWhere);
    }
    return {};
}

std::size_t pairing_book::outstanding(clock::time_point now) const {
    const std::scoped_lock lock{mutex_};
    return static_cast<std::size_t>(std::ranges::count_if(secrets_, [now](const pairing_secret& s) { return !expired_at(s, now); }));
}

void pairing_book::clear() {
    const std::scoped_lock lock{mutex_};
    secrets_.clear();
}

} // namespace Rhp::security
