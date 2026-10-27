#pragma once

#include <concepts>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

#include <rhp/core/result.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>

namespace Rhp::net {

// Tag: this endpoint may speak plaintext to non-loopback peers (no TLS), as long as they are local:
// private (RFC 1918, RFC 4193) or link-local addresses (ip_address::is_local); anyone else still
// needs TLS. Only on networks you trust: frames are still authenticated (keyed MAC) but anyone on the
// path can read them.
struct insecure_lan_t {
    explicit constexpr insecure_lan_t() = default;
};
inline constexpr insecure_lan_t insecure_lan{};

// Tag: TLS on every connection of this endpoint, loopback included.
struct require_tls_t {
    explicit constexpr require_tls_t() = default;
};
inline constexpr require_tls_t require_tls{};

// When a host or client wraps a connection in TLS (Rhp::config<>::tls<...>):
//   kAuto     over a network transport (TCP) to or from a non-loopback address, unless the endpoint
//             says insecure_lan and the peer's address is local; a host also accepts TLS from anyone
//             who offers it
//   kRequire  always (Rhp::net::require_tls); a host refuses plaintext
enum class tls_mode : std::uint8_t {
    kAuto,
    kRequire
};

// Where a host or client meets its peer, and which side waits. There is no default port.
//
//   Rhp::endpoint::listen("127.0.0.1", 7777)     // host waits (or a client in reverse mode)
//   Rhp::endpoint::dial("127.0.0.1", 7777)       // client connects
//   Rhp::endpoint::listen("0.0.0.0", 7777)                         // TLS for every non-loopback peer
//   Rhp::endpoint::dial("10.0.0.5", 7777)                           // TLS (not a loopback address)
//   Rhp::endpoint::listen("127.0.0.1", 7777, Rhp::net::require_tls) // TLS even on loopback
//   Rhp::endpoint::listen("0.0.0.0", 7777, Rhp::net::insecure_lan)  // plaintext allowed
//
// For the in-process loopback transport, host + port only name the channel ("game", 1).
struct endpoint {
    enum class mode : std::uint8_t {
        kListen,
        kDial
    };

    mode direction = mode::kDial;
    std::string host;
    std::uint16_t port = 0;
    bool insecure_lan = false;
    tls_mode tls = tls_mode::kAuto;

    [[nodiscard]] static endpoint listen(std::string_view host, std::uint16_t port) { return {mode::kListen, std::string{host}, port, false, tls_mode::kAuto}; }
    [[nodiscard]] static endpoint listen(std::string_view host, std::uint16_t port, insecure_lan_t) { return {mode::kListen, std::string{host}, port, true, tls_mode::kAuto}; }
    [[nodiscard]] static endpoint listen(std::string_view host, std::uint16_t port, require_tls_t) { return {mode::kListen, std::string{host}, port, false, tls_mode::kRequire}; }
    [[nodiscard]] static endpoint dial(std::string_view host, std::uint16_t port) { return {mode::kDial, std::string{host}, port, false, tls_mode::kAuto}; }
    [[nodiscard]] static endpoint dial(std::string_view host, std::uint16_t port, insecure_lan_t) { return {mode::kDial, std::string{host}, port, true, tls_mode::kAuto}; }
    [[nodiscard]] static endpoint dial(std::string_view host, std::uint16_t port, require_tls_t) { return {mode::kDial, std::string{host}, port, false, tls_mode::kRequire}; }

    // The same address with the other direction (a host listening here is dialed with this).
    [[nodiscard]] endpoint reversed() const { return {direction == mode::kListen ? mode::kDial : mode::kListen, host, port, insecure_lan, tls}; }
    [[nodiscard]] endpoint with_port(std::uint16_t p) const { return {direction, host, p, insecure_lan, tls}; }

    [[nodiscard]] bool operator==(const endpoint&) const = default;
};

// True for a literal loopback address or "localhost": 127.0.0.0/8, ::1 (bracketed or not) and
// IPv4-mapped 127.x. Names that merely resolve to loopback don't count.
[[nodiscard]] constexpr bool is_loopback_host(std::string_view host) noexcept {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    if (host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1") {
        return true;
    }
    if (host.starts_with("::ffff:") || host.starts_with("::FFFF:")) {
        host.remove_prefix(7);
    }
    // Dotted IPv4 with four numeric parts whose first one is 127.
    if (!host.starts_with("127.")) {
        return false;
    }
    int dots = 0;
    bool digit = false;
    for (const char c : host) {
        if (c == '.') {
            if (!digit) {
                return false;
            }
            ++dots;
            digit = false;
        } else if (c >= '0' && c <= '9') {
            digit = true;
        } else {
            return false;
        }
    }
    return dots == 3 && digit;
}

using accept_fn = std::function<void(std::unique_ptr<link> accepted)>;
using connect_fn = std::function<void(result<std::unique_ptr<link>> connected)>;

// A transport says whether it reaches other machines: `static constexpr bool network = ...;`.
// true (TCP, WebSocket, reliable UDP, a game network's sockets): the TLS address rules of
// tls_mode::kAuto apply - TLS to and from non-loopback addresses unless the endpoint says
// insecure_lan. false (in-process, IPC, a cable): plaintext is accepted. Required, because a
// transport that forgot it would otherwise speak plaintext over the network.
template <class T>
concept declares_network = requires {
    requires std::same_as<std::remove_cv_t<decltype(T::network)>, bool>;
    typename std::bool_constant<T::network>; // a constant expression
};

// Transport policy for Rhp::config<>::transport<...>. All of it runs on the io_context's thread:
//   listen() binds now (errors return at once) and calls on_accept for every new link;
//   dial() connects asynchronously and calls on_connect exactly once (unless the context dies).
template <class T>
concept transport = declares_network<T> && requires(io_context& io, const endpoint& ep, accept_fn on_accept, connect_fn on_connect) {
    { T::name } -> std::convertible_to<std::string_view>;
    { T::listen(io, ep, std::move(on_accept)) } -> std::same_as<result<std::unique_ptr<listener>>>;
    { T::dial(io, ep, std::move(on_connect)) } -> std::same_as<void>;
};

template <transport T>
inline constexpr bool is_network_v = T::network;

// A transport as function pointers, so sessions, hosts and clients stay out of templates.
struct transport_ops {
    std::string_view name;
    result<std::unique_ptr<listener>> (*listen)(io_context& io, const endpoint& ep, accept_fn on_accept) = nullptr;
    void (*dial)(io_context& io, const endpoint& ep, connect_fn on_connect) = nullptr;
    bool network = false;
};

template <transport T>
inline constexpr transport_ops transport_ops_for{T::name, &T::listen, &T::dial, T::network};

} // namespace Rhp::net

namespace Rhp {
using net::endpoint;
} // namespace Rhp

template <>
struct std::formatter<Rhp::net::endpoint> : std::formatter<std::string_view> {
    auto format(const Rhp::net::endpoint& ep, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{} {}:{}{}{}", ep.direction == Rhp::net::endpoint::mode::kListen ? "listen" : "dial", ep.host, ep.port,
                              ep.insecure_lan ? " (insecure_lan)" : "", ep.tls == Rhp::net::tls_mode::kRequire ? " (tls)" : "");
    }
};
