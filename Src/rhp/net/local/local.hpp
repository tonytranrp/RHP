#pragma once

#include <rhp/net/endpoint.hpp>

namespace Rhp::net {

// AF_UNIX pathname (or @abstract-name on Linux/Android); a named pipe on Windows. endpoint.host is
// the pathname/pipe name, endpoint.port must be zero. Authentication is unchanged.
struct local_ipc {
    static constexpr std::string_view name = "local_ipc";
    static constexpr bool network = false;

    static result<std::unique_ptr<listener>> listen(io_context& io, const endpoint& ep, accept_fn on_accept);
    static void dial(io_context& io, const endpoint& ep, connect_fn on_connect);
};

static_assert(transport<local_ipc>);

} // namespace Rhp::net
