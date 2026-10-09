#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>

#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/wire/codec.hpp>

namespace Rhp {

struct host_options {
    // Responses kept per session for idempotent retries (by the client's idempotency key).
    std::size_t idempotency_cache = 256;
    // Messages the network thread may queue for pump() before it holds them back itself.
    std::size_t inbox_capacity = 4096;
};

} // namespace Rhp

namespace Rhp::host_detail {

// Everything the engine needs from a config, type-erased so the engine compiles once (host.cpp).
struct setup {
    net::endpoint ep;
    net::transport_ops transport;
    wire::codec_ops codec;
    std::function<std::unique_ptr<security::host_handshake>()> begin_handshake;
    Rhp::limits limits{};
    bool io_thread = true; // false: pump() polls the network
    std::function<bool(log_level)> log_enabled;
    std::function<void(log_level, std::string_view)> log;
    script::clock_fn clock;
    host_options options;
};

using installer = result<void> (*)(script::sandbox& box);

template <script::installable L>
result<void> install_into(script::sandbox& box) {
    return box.install<L>();
}

class engine;

struct engine_deleter {
    void operator()(engine* e) const noexcept;
};

using engine_ptr = std::unique_ptr<engine, engine_deleter>;

// Starts listening (errors are kept and reported by listening()).
[[nodiscard]] engine_ptr make_engine(setup s);
[[nodiscard]] result<void> listening(const engine& e);
[[nodiscard]] std::uint16_t port(const engine& e) noexcept;
result<void> install(engine& e, std::string_view name, installer fn);
void pump(engine& e);
// The network loop (the io_runner's body); returns once `stop` is signalled.
void run_io(engine& e, std::stop_token stop);
[[nodiscard]] std::size_t sessions(const engine& e) noexcept;
[[nodiscard]] std::size_t identities(const engine& e) noexcept;

} // namespace Rhp::host_detail
