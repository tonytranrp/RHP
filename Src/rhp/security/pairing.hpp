#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

// Pairing a phone or another device with a host (decision AL10): a QR link carrying a one-time
// secret, or a 6-digit code run through CPace (pairing_cpace.hpp). Either credential only lets its
// session enroll a device key (kEnroll); this file has the formats and the host's book of secrets,
// not the wiring.

inline constexpr std::size_t kPairingSecretSize = 32;
inline constexpr std::string_view kPairingScheme = "rhp-pair";

// rhp-pair://<host>:<port>?secret=<base64url>&fp=<fingerprint>&name=<name>
//
//   host    a DNS name or IPv4 address (letters, digits, '-', '.'), or an IPv6 address in brackets
//           ([::1]; no zone); kept here without the brackets
//   port    1..65535
//   secret  kPairingSecretSize bytes, unpadded base64url (43 characters); required
//   fp      the host's device-key fingerprint (key_fingerprint: 22 characters of unpadded
//           base64url, 16 bytes); required: the client pins the key it names
//   name    the host's display name, percent-encoded UTF-8 (at most 128 bytes, no control
//           characters); optional
//
// Parsing is strict: the scheme (any case), no user info, path or fragment, every key once, and an
// unknown key refuses the link (kInvalidArgument), like an unknown critical option on a certificate:
// hosts, clients and rhp-cli move together with the wire revision, and a link that means more than
// its reader understands must not be half-read. to_text() writes the keys in the order above,
// percent-encoding everything in `name` but RFC 3986's unreserved characters.
struct pairing_link {
    static constexpr std::size_t kMaxNameSize = 128;

    std::string host{};
    std::uint16_t port = 0;
    key secret{}; // kPairingSecretSize bytes, wiped with the link
    std::string fingerprint{};
    std::string name{};

    [[nodiscard]] static result<pairing_link> parse(std::string_view text);
    // kInvalidArgument when a field couldn't be parsed back (the same checks as parse).
    [[nodiscard]] result<std::string> to_text() const;
};

// A one-time pairing secret and when it stops being accepted.
struct pairing_secret {
    key value{}; // kPairingSecretSize random bytes
    std::chrono::steady_clock::time_point expires{};
};

// The host's outstanding pairing secrets: issued for a QR link, each accepted once before it
// expires. Thread-safe. consume() compares the presented bytes with every outstanding secret in
// constant time (no early exit); entries are removed when used or found expired.
class pairing_book {
public:
    using clock = std::chrono::steady_clock;
    static constexpr std::size_t kDefaultCapacity = 8;
    static constexpr clock::duration kDefaultLifetime = std::chrono::minutes{5};

    explicit pairing_book(std::size_t capacity = kDefaultCapacity) noexcept : capacity_(capacity) {}

    // A fresh secret valid for `lifetime` (a copy: the book keeps its own). kInvalidArgument for a
    // lifetime that isn't positive; kLimitExceeded while `capacity` unexpired secrets are out.
    [[nodiscard]] result<pairing_secret> issue(clock::duration lifetime = kDefaultLifetime, clock::time_point now = clock::now());

    // Accepts `presented` once. kAuth when it matches no outstanding secret (or isn't
    // kPairingSecretSize bytes), kExpired when it matches one past its expiry (removed too).
    [[nodiscard]] result<void> consume(std::span<const std::byte> presented, clock::time_point now = clock::now());

    // Unexpired secrets still out.
    [[nodiscard]] std::size_t outstanding(clock::time_point now = clock::now()) const;
    // Forgets every secret (pairing mode ends).
    void clear();

private:
    mutable std::mutex mutex_;
    std::size_t capacity_;
    std::vector<pairing_secret> secrets_;
};

// ---- 6-digit codes over CPace -------------------------------------------------------------------
//
// The host shows a code; the person types it on the device; both run CPace (pairing_cpace.hpp)
// with PRS = pairing_code_prs(code) and CI = pairing_channel_id(tls exporter value), the client as
// initiator. The wire step sends Ya and Yb as 32 bytes each (with ADa / ADb, e.g. the device name
// and the host's key fingerprint) and proves the ISK both ways before kEnroll is accepted.
//
// Binding (the ADB-pairing idea): the TLS exporter of the connection goes into CI, so a CPace run
// relayed between two TLS connections (a TLS-terminating middlebox) has different CIs on its two
// sides and ends with unrelated ISKs. sid can stay empty or carry a host nonce.
//
// Rate limiting is the wiring step's: a code gives an online attacker one guess per CPace run, so
// accept one run per connection and retire the code after 5 failed runs (5 in 10^6).

inline constexpr std::size_t kPairingCodeDigits = 6;
inline constexpr std::string_view kPairingCodeDomain{"rhp/pair-code\0", 14};
inline constexpr std::string_view kPairingChannelDomain{"rhp/pair-ci\0", 12};

// A uniform code of kPairingCodeDigits decimal digits (leading zeros kept), drawn from the OS
// random source by rejection sampling.
[[nodiscard]] result<std::string> generate_pairing_code();
// Exactly kPairingCodeDigits ASCII digits.
[[nodiscard]] bool valid_pairing_code(std::string_view code) noexcept;
// CPace's PRS for a code: kPairingCodeDomain || the digits. kInvalidArgument for anything but a
// valid code (spaces and dashes a person typed are the caller's to strip).
[[nodiscard]] result<key> pairing_code_prs(std::string_view code);
// CPace's CI for a connection: kPairingChannelDomain || its tls-exporter value.
[[nodiscard]] std::vector<std::byte> pairing_channel_id(std::span<const std::byte> channel_binding);

namespace detail {

// The code for one 32-bit draw, or nullopt when the draw is rejected (at or above the largest
// multiple of 10^6 that fits, so every code is equally likely).
[[nodiscard]] std::optional<std::string> pairing_code_from(std::uint32_t draw);

} // namespace detail

} // namespace Rhp::security
