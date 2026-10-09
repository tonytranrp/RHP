#pragma once

#include <memory>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>

namespace Rhp::net {

// TCP over Asio (IPv4 and IPv6; TCP_NODELAY on every socket). The transport itself is plaintext:
// it binds or dials a non-loopback address only when the endpoint carries Rhp::net::insecure_lan
// or requires TLS (which hosts and clients layer on top; `network` says the TLS address rules
// apply); anything else fails with kForbidden. Port 0 listens on a free port (listener::port()).
struct tcp {
    static constexpr std::string_view name = "tcp";
    static constexpr bool network = true;

    static result<std::unique_ptr<listener>> listen(io_context& io, const endpoint& ep, accept_fn on_accept);
    static void dial(io_context& io, const endpoint& ep, connect_fn on_connect);
};

static_assert(transport<tcp>);

} // namespace Rhp::net
