#pragma once

#include <array>
#include <chrono>
#include <concepts>
#include <cstddef>
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
//   MAC = keyed-BLAKE2b-256(psk, "rhp/http\0" || le64 seconds || for each of key name, nonce,
//         method, target, X-RHP-Signature, Content-Type: le64 length || bytes || le64 body length || body
//         [|| X-RHP-Channel and the channel binding, each as le64 length || bytes, when the header is set])
//
// The host accepts a proof within kHttpSkew of its clock, once (http_replay_guard). The PSK never
// leaves either end.
//
// Channel binding (optional): a client on TLS sends `X-RHP-Channel: tls-exporter` and mixes its
// connection's RFC 9266 exporter value into the MAC; the host mixes in its own. Behind a relay that
// terminates TLS the two differ, so the proof fails, as the native handshake does. A request that
// asks for binding on a connection without TLS is refused.
//
// Answers: every answer to an authenticated request carries
//
//   X-RHP-Proof: base64 keyed-BLAKE2b-256(answer key, "rhp/http-answer\0" || le64 status ||
//                le64 length || Content-Type || le64 length || body)
//   answer key = keyed-BLAKE2b-256(psk, "rhp/http-answer-key\0" || the request's MAC)
//
// so a client (verify_http_answer) knows the answer came unmodified from a holder of the key, for
// this very request. Without binding or a checked certificate, a relay can still read the traffic.
namespace Rhp::security {

struct psk_identity;

inline constexpr std::chrono::seconds kHttpSkew{30};
inline constexpr std::size_t kHttpNonceBytes = 16;
inline constexpr std::size_t kHttpMaxAuthorization = 512;
inline constexpr std::size_t kHttpAnswerKeyBytes = 32;
// The X-RHP-Channel value that binds a request to its TLS connection.
inline constexpr std::string_view kHttpChannelTlsExporter = "tls-exporter";

// The key an answer's X-RHP-Proof is made with (derived per request; never the PSK itself).
using http_answer_key = std::array<std::byte, kHttpAnswerKeyBytes>;

// One request as its proof covers it. Views are valid during the call only.
struct http_proof {
    std::string_view authorization = {}; // the Authorization header (empty when building one)
    std::string_view method = {};
    std::string_view target = {};
    std::string_view signature = {}; // the X-RHP-Signature header, or empty
    std::string_view content_type = {};
    std::span<const std::byte> body = {};
    std::string_view channel = {};           // the X-RHP-Channel header: empty, or kHttpChannelTlsExporter
    std::span<const std::byte> binding = {}; // this end's channel binding (link::channel_binding())
};

struct http_grant {
    std::string identity;
    role granted = role::kObserve;
    std::string nonce;
    std::chrono::system_clock::time_point expires = {}; // the nonce must be remembered until then
    // Signs the answers to this request (X-RHP-Proof); empty when the authenticator derives none.
    std::optional<http_answer_key> answer_key = {};
    bool bound = false; // the proof covered the TLS channel
    scope_set scopes{}; // the identity's scopes (auth_grant::scopes)
};

// What an answer's X-RHP-Proof covers.
struct http_answer {
    unsigned status = 200;
    std::string_view content_type = {};
    std::span<const std::byte> body = {};
};

// Client side: the Authorization header for `request` (its `authorization` field is ignored).
[[nodiscard]] result<std::string> http_authorization(const psk_identity& identity, const http_proof& request,
                                                     std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// Host side: checks the proof against `keys`. Unknown key names cost the same work as known ones,
// so response timing doesn't reveal which names exist. Replays are the caller's to refuse.
[[nodiscard]] result<http_grant> verify_http_authorization(const keyring& keys, const http_proof& request,
                                                           std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

// Host side: the X-RHP-Proof header of an answer.
[[nodiscard]] std::string http_answer_proof(const http_answer_key& key, const http_answer& answer);

// Client side: checks an answer's X-RHP-Proof against the Authorization header its request was
// sent with. kIntegrity when the proof is missing, malformed or doesn't match.
[[nodiscard]] result<void> verify_http_answer(const psk_identity& identity, std::string_view authorization, const http_answer& answer, std::string_view proof);

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
