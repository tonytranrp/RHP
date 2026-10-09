#pragma once

#include <concepts>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>

namespace Rhp::net {

// Tag: this endpoint may use a non-loopback address without TLS (TLS arrives in Stage 5). Without
// it, a TCP listen or dial outside 127.0.0.0/8 and ::1 fails with kForbidden.
struct insecure_lan_t {
    explicit constexpr insecure_lan_t() = default;
};
inline constexpr insecure_lan_t insecure_lan{};

// Where a host or client meets its peer, and which side waits. There is no default port.
//
//   Rhp::endpoint::listen("127.0.0.1", 7777)     // host waits (or a client in reverse mode)
//   Rhp::endpoint::dial("127.0.0.1", 7777)       // client connects
//   Rhp::endpoint::listen("0.0.0.0", 7777, Rhp::net::insecure_lan)
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

    [[nodiscard]] static endpoint listen(std::string_view host, std::uint16_t port) { return {mode::kListen, std::string{host}, port, false}; }
    [[nodiscard]] static endpoint listen(std::string_view host, std::uint16_t port, insecure_lan_t) { return {mode::kListen, std::string{host}, port, true}; }
    [[nodiscard]] static endpoint dial(std::string_view host, std::uint16_t port) { return {mode::kDial, std::string{host}, port, false}; }
    [[nodiscard]] static endpoint dial(std::string_view host, std::uint16_t port, insecure_lan_t) { return {mode::kDial, std::string{host}, port, true}; }

    // The same address with the other direction (a host listening here is dialed with this).
    [[nodiscard]] endpoint reversed() const { return {direction == mode::kListen ? mode::kDial : mode::kListen, host, port, insecure_lan}; }
    [[nodiscard]] endpoint with_port(std::uint16_t p) const { return {direction, host, p, insecure_lan}; }

    [[nodiscard]] bool operator==(const endpoint&) const = default;
};

using accept_fn = std::function<void(std::unique_ptr<link> accepted)>;
using connect_fn = std::function<void(result<std::unique_ptr<link>> connected)>;

// Transport policy for Rhp::config<>::transport<...>. All of it runs on the io_context's thread:
//   listen() binds now (errors return at once) and calls on_accept for every new link;
//   dial() connects asynchronously and calls on_connect exactly once (unless the context dies).
template <class T>
concept transport = requires(io_context& io, const endpoint& ep, accept_fn on_accept, connect_fn on_connect) {
    { T::name } -> std::convertible_to<std::string_view>;
    { T::listen(io, ep, std::move(on_accept)) } -> std::same_as<result<std::unique_ptr<listener>>>;
    { T::dial(io, ep, std::move(on_connect)) } -> std::same_as<void>;
};

// A transport as function pointers, so sessions, hosts and clients stay out of templates.
struct transport_ops {
    std::string_view name;
    result<std::unique_ptr<listener>> (*listen)(io_context& io, const endpoint& ep, accept_fn on_accept) = nullptr;
    void (*dial)(io_context& io, const endpoint& ep, connect_fn on_connect) = nullptr;
};

template <transport T>
inline constexpr transport_ops transport_ops_for{T::name, &T::listen, &T::dial};

} // namespace Rhp::net

namespace Rhp {
using net::endpoint;
} // namespace Rhp

template <>
struct std::formatter<Rhp::net::endpoint> : std::formatter<std::string_view> {
    auto format(const Rhp::net::endpoint& ep, std::format_context& ctx) const {
        return std::format_to(ctx.out(), "{} {}:{}{}", ep.direction == Rhp::net::endpoint::mode::kListen ? "listen" : "dial", ep.host, ep.port,
                              ep.insecure_lan ? " (insecure_lan)" : "");
    }
};
