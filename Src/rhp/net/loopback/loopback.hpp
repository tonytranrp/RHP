#pragma once

#include <memory>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>

namespace Rhp::net {

// In-process transport: a host and clients in the same program (tests, tools embedding a host,
// an engine console) with no sockets. The endpoint's host + port name a process-wide channel;
// listening on a name that is already listening fails with kAlreadyLoaded, dialing a name nobody
// listens on fails with kNotFound. Both ends may run on different io_contexts and threads.
struct loopback {
    static constexpr std::string_view name = "loopback";
    static constexpr bool network = false; // in-process

    static result<std::unique_ptr<listener>> listen(io_context& io, const endpoint& ep, accept_fn on_accept);
    static void dial(io_context& io, const endpoint& ep, connect_fn on_connect);
};

static_assert(transport<loopback>);

} // namespace Rhp::net
