#include <algorithm>
#include <array>
#include <charconv>
#include <format>

#include <monocypher.h>

#include <rhp/platform/random.hpp>
#include <rhp/security/http_auth.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/base64.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::security {

namespace {

constexpr const char* kWhere = "security.http";
constexpr std::string_view kDomain{"rhp/http\0", 9};
constexpr std::string_view kAnswerKeyDomain{"rhp/http-answer-key\0", 20};
constexpr std::string_view kAnswerDomain{"rhp/http-answer\0", 16};
constexpr std::size_t kMacBytes = 32;

using mac = std::array<std::byte, kMacBytes>;

// Streams the request into keyed BLAKE2b: the body is hashed where it lies, never copied.
class transcript_mac {
public:
    transcript_mac(std::span<const std::byte> secret, std::string_view domain) noexcept {
        crypto_blake2b_keyed_init(&ctx_, kMacBytes, reinterpret_cast<const std::uint8_t*>(secret.data()), secret.size());
        bytes(utils::as_bytes(domain));
    }
    transcript_mac(const transcript_mac&) = delete;
    transcript_mac& operator=(const transcript_mac&) = delete;
    ~transcript_mac() { crypto_wipe(&ctx_, sizeof ctx_); }

    void number(std::uint64_t n) noexcept {
        std::array<std::byte, 8> le{};
        utils::store_le<std::uint64_t>(le, n);
        bytes(le);
    }
    void field(std::span<const std::byte> data) noexcept {
        number(data.size());
        bytes(data);
    }
    void field(std::string_view text) noexcept { field(utils::as_bytes(text)); }

    [[nodiscard]] mac finish() noexcept {
        mac out{};
        crypto_blake2b_final(&ctx_, reinterpret_cast<std::uint8_t*>(out.data()));
        return out;
    }

    void bytes(std::span<const std::byte> data) noexcept { crypto_blake2b_update(&ctx_, reinterpret_cast<const std::uint8_t*>(data.data()), data.size()); }

private:

    crypto_blake2b_ctx ctx_{};
};

[[nodiscard]] mac request_mac(std::span<const std::byte> secret, std::string_view name, std::uint64_t seconds, std::string_view nonce, const http_proof& r) noexcept {
    transcript_mac m{secret, kDomain};
    m.number(seconds);
    for (const auto text : {name, nonce, r.method, r.target, r.signature, r.content_type}) {
        m.field(text);
    }
    m.field(r.body);
    if (!r.channel.empty()) {
        // Only bound requests append these; an unbound transcript can't equal a bound one, since
        // the body's length prefix fixes where it ends.
        m.field(r.channel);
        m.field(r.binding);
    }
    return m.finish();
}

[[nodiscard]] http_answer_key answer_key(std::span<const std::byte> secret, std::span<const std::byte> request) noexcept {
    transcript_mac m{secret, kAnswerKeyDomain};
    m.bytes(request);
    return m.finish();
}

[[nodiscard]] mac answer_mac(const http_answer_key& key, const http_answer& a) noexcept {
    transcript_mac m{key, kAnswerDomain};
    m.number(a.status);
    m.field(a.content_type);
    m.field(a.body);
    return m.finish();
}

// Unbound, or tls-exporter with this end's binding present.
[[nodiscard]] bool channel_ok(const http_proof& r) noexcept {
    return r.channel.empty() || (r.channel == kHttpChannelTlsExporter && !r.binding.empty());
}

// The key an unknown name is checked against: the same hashing work, a result that never matches
// anything a client could send (random per process).
[[nodiscard]] std::span<const std::byte> decoy_secret() noexcept {
    static const auto secret = [] {
        auto random = platform::random_array<32>();
        return random ? *random : std::array<std::byte, 32>{};
    }();
    return secret;
}

[[nodiscard]] std::uint64_t unix_seconds(std::chrono::system_clock::time_point t) noexcept {
    const auto s = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
    return static_cast<std::uint64_t>(std::max<std::int64_t>(0, s));
}

// "name,seconds,nonce,mac" after the "RHP " scheme; nullopt unless exactly four nonempty fields.
[[nodiscard]] std::optional<std::array<std::string_view, 4>> split_fields(std::string_view text) noexcept {
    std::array<std::string_view, 4> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto comma = text.find(',');
        const bool last = i + 1 == out.size();
        if (last != (comma == std::string_view::npos)) {
            return std::nullopt;
        }
        out[i] = text.substr(0, comma);
        if (out[i].empty()) {
            return std::nullopt;
        }
        text.remove_prefix(last ? text.size() : comma + 1);
    }
    return out;
}

} // namespace

result<std::string> http_authorization(const psk_identity& identity, const http_proof& request, std::chrono::system_clock::time_point now) {
    if (identity.name.empty() || identity.name.find_first_of(", \t\r\n") != std::string::npos || identity.secret.empty()) {
        return fail(errc::kInvalidArgument, "invalid HTTP identity", kWhere);
    }
    if (!channel_ok(request)) {
        return fail(errc::kInvalidArgument, "X-RHP-Channel must be empty, or tls-exporter on a TLS connection", kWhere);
    }
    auto random = platform::random_array<kHttpNonceBytes>();
    if (!random) {
        return std::unexpected{std::move(random).error()};
    }
    const auto nonce = utils::base64_encode(*random);
    const auto seconds = unix_seconds(now);
    const auto proof = request_mac(identity.secret.bytes(), identity.name, seconds, nonce, request);
    return std::format("RHP {},{},{},{}", identity.name, seconds, nonce, utils::base64_encode(proof));
}

result<http_grant> verify_http_authorization(const keyring& keys, const http_proof& request, std::chrono::system_clock::time_point now) {
    const auto refused = [] { return fail(errc::kAuth, "invalid, expired or untrusted HTTP proof", kWhere); };
    auto text = request.authorization;
    if (!text.starts_with("RHP ") || text.size() > kHttpMaxAuthorization) {
        return refused();
    }
    const auto fields = split_fields(text.substr(4));
    if (!fields) {
        return refused();
    }
    const auto [name, stamp, nonce_text, mac_text] = *fields;
    std::uint64_t seconds = 0;
    const auto [at, ec] = std::from_chars(stamp.data(), stamp.data() + stamp.size(), seconds);
    const auto current = unix_seconds(now);
    const auto skew = static_cast<std::uint64_t>(kHttpSkew.count());
    const bool fresh = ec == std::errc{} && at == stamp.data() + stamp.size() && (seconds > current ? seconds - current : current - seconds) <= skew;
    const auto supplied = utils::base64_decode(mac_text);
    // The canonical encoding only: one nonce has one spelling in the replay cache.
    const bool well_formed = fresh && channel_ok(request) && utils::is_base64_of(nonce_text, kHttpNonceBytes) && supplied && supplied->size() == kMacBytes;
    if (!well_formed) {
        return refused();
    }
    const auto* found = keys.find(name);
    const auto expected = request_mac(found != nullptr ? found->secret.bytes() : decoy_secret(), name, seconds, nonce_text, request);
    const bool matches = crypto_verify32(reinterpret_cast<const std::uint8_t*>(expected.data()), reinterpret_cast<const std::uint8_t*>(supplied->data())) == 0;
    if (!matches || found == nullptr) {
        return refused();
    }
    // Remembered one second past the window, so a proof can't be replayed at its edge.
    const auto expires = std::chrono::system_clock::time_point{std::chrono::seconds{seconds + skew + 1}};
    return http_grant{std::string{name}, found->granted, std::string{nonce_text}, expires, answer_key(found->secret.bytes(), expected), !request.channel.empty()};
}

std::string http_answer_proof(const http_answer_key& key, const http_answer& answer) {
    return utils::base64_encode(answer_mac(key, answer));
}

result<void> verify_http_answer(const psk_identity& identity, std::string_view authorization, const http_answer& answer, std::string_view proof) {
    const auto refused = [] { return fail(errc::kIntegrity, "the HTTP answer's X-RHP-Proof is missing or doesn't match", kWhere); };
    if (!authorization.starts_with("RHP ")) {
        return refused();
    }
    const auto fields = split_fields(authorization.substr(4));
    if (!fields || (*fields)[0] != identity.name) {
        return refused();
    }
    const auto request = utils::base64_decode((*fields)[3]);
    const auto supplied = utils::base64_decode(proof);
    if (!request || request->size() != kMacBytes || !supplied || supplied->size() != kMacBytes) {
        return refused();
    }
    const auto expected = answer_mac(answer_key(identity.secret.bytes(), *request), answer);
    if (crypto_verify32(reinterpret_cast<const std::uint8_t*>(expected.data()), reinterpret_cast<const std::uint8_t*>(supplied->data())) != 0) {
        return refused();
    }
    return {};
}

} // namespace Rhp::security
