#pragma once

// Private to host.cpp and gateway.cpp (not installed): the HTTP frontend and the engine's side of it.

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
    // The unauthenticated-connection budget native handshakes use too.
    [[nodiscard]] virtual bool acquire_handshake() noexcept = 0;
    virtual void release_handshake() noexcept = 0;
    [[nodiscard]] virtual result<security::http_grant> authorize(const security::http_proof& request) = 0;
    // An identity's first request opens its logical session; it ends with close_http.
    [[nodiscard]] virtual session_id open_http(const security::http_grant& grant, const http_peer& peer) = 0;
    virtual void close_http(session_id session, std::string_view identity, const error& why) = 0;
    // False when the pump's queue is full.
    [[nodiscard]] virtual bool submit_http(session_id session, std::uint64_t req, wire::op code, value body) = 0;
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
    http_gateway(net::io_context& io, Rhp::limits limits, gateway_sink& sink);
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
