#pragma once

#include <rhp/net/endpoint.hpp>

namespace Rhp::net {

// RFC 6455 binary stream over TCP, upgrading /rhp. TLS supplied by the session
// is carried inside binary frames; this is a ws tunnel, not a wss listener.
struct websocket {
    static constexpr std::string_view name = "websocket";
    static constexpr bool network = true;

    static result<std::unique_ptr<listener>> listen(io_context& io, const endpoint& ep, accept_fn on_accept);
    static void dial(io_context& io, const endpoint& ep, connect_fn on_connect);
};

static_assert(transport<websocket>);

} // namespace Rhp::net
