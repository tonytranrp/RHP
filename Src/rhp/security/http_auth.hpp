#pragma once

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/keyring.hpp>

// Request authentication for the host's HTTP frontend. HTTP has no handshake, so every request
// carries its own proof instead:
//
//   Authorization: RHP <key-name>,<unix-seconds>,<base64 16-byte nonce>,<base64 MAC>
//   MAC = keyed-BLAKE2b-256(psk, "rhp/http\0" ‖ le64 seconds ‖ for each of key name, nonce,
//         method, target, X-RHP-Signature, Content-Type: le64 length ‖ bytes ‖ le64 body length ‖ body)
//
// The host accepts a proof within kHttpSkew of its clock, once (http_replay_guard). The PSK never
// leaves either end. Unlike the native handshake, the proof is not bound to the TLS channel and
// responses carry no MAC: the HTTP client must check the host's certificate.
namespace Rhp::security {

struct psk_identity;

inline constexpr std::chrono::seconds kHttpSkew{30};
inline constexpr std::size_t kHttpNonceBytes = 16;
inline constexpr std::size_t kHttpMaxAuthorization = 512;

// One request as its proof covers it. Views are valid during the call only.
struct http_proof {
    std::string_view authorization = {}; // the Authorization header (empty when building one)
    std::string_view method = {};
    std::string_view target = {};
    std::string_view signature = {}; // the X-RHP-Signature header, or empty
    std::string_view content_type = {};
    std::span<const std::byte> body = {};
};

struct http_grant {
    std::string identity;
    role granted = role::kObserve;
    std::string nonce;
    std::chrono::system_clock::time_point expires; // the nonce must be remembered until then
};

// Client side: the Authorization header for `request` (its `authorization` field is ignored).
[[nodiscard]] result<std::string> http_authorization(const psk_identity& identity, const http_proof& request,
                                                     std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// Host side: checks the proof against `keys`. Unknown key names cost the same work as known ones,
// so response timing doesn't reveal which names exist. Replays are the caller's to refuse.
[[nodiscard]] result<http_grant> verify_http_authorization(const keyring& keys, const http_proof& request,
                                                           std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// X-RHP-Signature: the script signer's signature value as base64 MessagePack, so every
// Rhp::config<>::signer<...> works over HTTP. Empty for unsigned requests.
[[nodiscard]] result<std::string> http_signature_header(const value& signature);
// The signature value of a header (nil when empty); kBadSignature if it doesn't decode.
[[nodiscard]] result<value> read_http_signature(std::string_view header);

// An authenticator that can also check per-request HTTP proofs (Rhp::host's HTTP listener needs one).
template <class A>
concept http_authenticator = authenticator<A> && requires(const A& a, const http_proof& request, std::chrono::system_clock::time_point now) {
    { a.verify_http(request, now) } -> std::same_as<result<http_grant>>;
};

// Accepted (identity, nonce) pairs until they expire. Each identity has its own quota, so a busy
// low-privilege key can't fill the cache and lock other keys out.
class http_replay_guard {
public:
    explicit http_replay_guard(std::size_t per_identity = 4096) : per_identity_(per_identity) {}

    // kAuth for a replay, kLimitExceeded when this identity's quota is full.
    [[nodiscard]] result<void> admit(const http_grant& grant, std::chrono::system_clock::time_point now = std::chrono::system_clock::now());
    // The earliest moment an entry expires (nothing to prune before then).
    [[nodiscard]] std::optional<std::chrono::system_clock::time_point> next_expiry() const;
    [[nodiscard]] std::size_t size() const noexcept { return seen_.size(); }

private:
    using entry = std::pair<std::string, std::string>; // identity, nonce
    void prune(std::chrono::system_clock::time_point now);

    std::size_t per_identity_;
    std::multimap<std::chrono::system_clock::time_point, entry> by_expiry_;
    std::set<entry> seen_;
    std::map<std::string, std::size_t, std::less<>> counts_;
};

} // namespace Rhp::security
