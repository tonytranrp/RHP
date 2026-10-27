#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

#include <rhp/core/result.hpp>
#include <rhp/utils/byte_buffer.hpp>

// Sans-IO stateless cookies of the reliable UDP transport. A listener answers a dialer's first Hello
// with a kCookie packet instead of creating anything; the dialer echoes the cookie in its next Hello,
// and only a Hello with a valid cookie gets a peer, a Welcome and a link. A cookie is a keyed MAC over
// the dialer's address, port and token and the time bucket, so a spoofed source never sees one and
// costs the listener one stateless reply the size of its Hello.
//
// The MAC is SipHash-2-4 (Aumasson and Bernstein, 2012): a keyed 64-bit PRF built for short inputs,
// implemented here because Rhp::net sits below Rhp::security (no keyed BLAKE2b at this layer) and
// needs nothing heavier for a 64-bit tag that lives two minutes.
namespace Rhp::net::detail::rudp {

using cookie_key = std::array<std::byte, 16>;

// SipHash-2-4 of `data` under `key`.
[[nodiscard]] std::uint64_t siphash24(const cookie_key& key, utils::bytes_view data) noexcept;

// Who a Hello came from, as its cookie covers it.
struct hello_source {
    std::array<std::uint8_t, 16> address{}; // IPv6, or IPv4-mapped
    std::uint16_t port = 0;
    std::uint64_t token = 0;
};

// The listener's secrets: a fresh random one every kCookiePeriod. A cookie made under the current or
// the previous one is accepted, so one lives between one and two periods.
class cookie_jar {
public:
    using time_point = std::chrono::steady_clock::time_point;
    static constexpr std::chrono::seconds kCookiePeriod{120};

    // kInvalidArgument when the OS random source fails.
    [[nodiscard]] static result<cookie_jar> make(time_point now);

    // The cookie for a Hello from `from` now.
    [[nodiscard]] std::uint64_t issue(time_point now, const hello_source& from);
    // Whether `cookie` is one this jar issued to `from` within the last two periods.
    [[nodiscard]] bool valid(time_point now, const hello_source& from, std::uint64_t cookie);

private:
    cookie_jar() = default;

    // Moves to the period `now` is in, drawing new secrets for the periods that passed.
    void rotate(time_point now);
    [[nodiscard]] static std::uint64_t mac(const cookie_key& key, std::uint64_t bucket, const hello_source& from) noexcept;

    time_point origin_{};
    std::uint64_t bucket_ = 0; // periods since origin_
    cookie_key current_{};
    cookie_key previous_{};
};

} // namespace Rhp::net::detail::rudp
