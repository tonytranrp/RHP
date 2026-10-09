#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>

#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp {

struct client_options {
    // How long connect() (or the first call) waits for the handshake.
    std::chrono::milliseconds connect_timeout{10'000};
    // How long a call waits for its reply; 0 = until the reply or the session ends (the
    // heartbeat ends a session whose host stopped answering).
    std::chrono::milliseconds request_timeout{0};
    // Every print() line the host sends this client (its own requests' and the identity's
    // broadcasts), with the request it belongs to (0 = none). On the network thread (the calling
    // thread with io<zero_threads>): keep it short and never call the client from it.
    std::function<void(std::uint64_t request, std::string_view line)> on_output{};
    // Every rhp.emit(value), with its request and module. Same thread rules as on_output.
    std::function<void(std::uint64_t request, module_id module, const value& v)> on_emit{};
};

} // namespace Rhp

namespace Rhp::client_detail {

struct setup {
    net::endpoint ep;
    net::transport_ops transport;
    wire::codec_ops codec;
    std::function<std::unique_ptr<security::client_handshake>()> begin_handshake;
    Rhp::limits limits{};
    bool io_thread = true; // false: the calling thread runs the network while it waits
    client_options options;
};

class engine;

struct engine_deleter {
    void operator()(engine* e) const noexcept;
};

using engine_ptr = std::unique_ptr<engine, engine_deleter>;

[[nodiscard]] engine_ptr make_engine(setup s);
// Dials (once) and waits for the handshake.
[[nodiscard]] result<void> connect(engine& e);
// Sends one request and waits for its kResult body (or the kError it gets).
[[nodiscard]] result<value> request(engine& e, wire::op code, value body);
// Asks the host to stop every request of this client in flight. Any thread; doesn't wait.
void cancel(engine& e) noexcept;
// Closes the session (the host reverts this identity if it was its last session) and waits briefly
// for the close to go out.
void close(engine& e) noexcept;
void run_io(engine& e, std::stop_token stop);

struct session_info {
    bool connected = false;
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::string host_platform;
};
[[nodiscard]] session_info info(const engine& e);

} // namespace Rhp::client_detail
