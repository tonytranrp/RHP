#pragma once

// Private to the host engine's sources and gateway.cpp (not installed): the HTTP frontend and the engine's side of it.

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/security/http_auth.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::host_detail {

// Who sent one HTTP request.
struct http_peer {
    std::string address;
    bool tls = false;
};

// What the gateway asks of the engine. Called on the I/O thread only.
class gateway_sink {
public:
    [[nodiscard]] virtual bool accepting() const noexcept = 0;
    // The host's clock (config<>::clock) for idle expiry: steady_clock plus the offset pump() last
    // sampled, so the network thread never calls the user's clock. (Proof freshness and the replay
    // window stay on the system clock: real clients sign with real time.)
    [[nodiscard]] virtual std::chrono::steady_clock::time_point steady_now() const noexcept = 0;
    // True when steady_now() isn't std::chrono::steady_clock: the gateway then can't sleep until a
    // deadline and re-checks it on a short period instead.
    [[nodiscard]] virtual bool custom_clock() const noexcept = 0;
    // The unauthenticated-connection budget native handshakes use too.
    [[nodiscard]] virtual bool acquire_handshake() noexcept = 0;
    virtual void release_handshake() noexcept = 0;
    [[nodiscard]] virtual result<security::http_grant> authorize(const security::http_proof& request) = 0;
    // An identity's first request opens its logical session; it ends with close_http.
    [[nodiscard]] virtual session_id open_http(const security::http_grant& grant, const http_peer& peer) = 0;
    virtual void close_http(session_id session, std::string_view identity, const error& why) = 0;
    // False when the pump's queue is full.
    [[nodiscard]] virtual bool submit_http(session_id session, std::uint64_t req, wire::op code, value body, const http_peer& peer) = 0;
    // One request (`target`), or with target 0 every request numbered up to `upto`.
    virtual void cancel_http(session_id session, std::uint64_t target, std::uint64_t upto) = 0;
    virtual void refused(std::string peer, error why) = 0;

protected:
    gateway_sink() = default;
    ~gateway_sink() = default;
    gateway_sink(const gateway_sink&) = default;
    gateway_sink& operator=(const gateway_sink&) = default;
};

// REST over HTTP/1.1 into the host dispatcher. HTTP has logical sessions: one per identity, kept
// across connections and ended after `limits.gateway_idle_ms` without requests in flight.
class http_gateway {
public:
    http_gateway(net::io_context& io, Rhp::limits limits, gateway_sink& sink, bool require_binding = false);
    ~http_gateway();

    http_gateway(const http_gateway&) = delete;
    http_gateway& operator=(const http_gateway&) = delete;

    [[nodiscard]] result<void> listen(session::channel_policy policy);
    [[nodiscard]] std::uint16_t port() const noexcept;
    // The pump's reply for an HTTP session (other ops, such as print, are not forwarded).
    void reply(session_id session, wire::op code, std::uint64_t req, const value& body);
    void stop();

private:
    struct impl;
    std::unique_ptr<impl> impl_;
};

} // namespace Rhp::host_detail
