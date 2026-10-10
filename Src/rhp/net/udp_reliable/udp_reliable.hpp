#pragma once

#include <rhp/net/endpoint.hpp>

namespace Rhp::net {

// Ordered byte stream over UDP: 480-byte fragments, a 64-packet selective-ACK
// window, congestion backoff and bounded retransmission. Sessions still provide
// authentication/resume; their TLS records run over this reliable stream.
struct udp_reliable {
    static constexpr std::string_view name = "udp_reliable";
    static constexpr bool network = true;

    static result<std::unique_ptr<listener>> listen(io_context& io, const endpoint& ep, accept_fn on_accept);
    static void dial(io_context& io, const endpoint& ep, connect_fn on_connect);
};

static_assert(transport<udp_reliable>);

} // namespace Rhp::net
