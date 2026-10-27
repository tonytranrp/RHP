#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>

#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/net/address.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>

namespace Rhp::session {

// Admission control for connections that haven't authenticated yet, one per accepting side (a host's
// listener and its HTTP gateway share one; a listening client has its own):
//   - at most limits.pending_handshakes at once, and at most limits.handshakes_per_source from one
//     source (net::ip_address::source(): an IPv4 address or an IPv6 /64; a link without an IP address
//     counts toward the first only);
//   - a connection that has sent nothing within limits.first_byte_ms is closed;
//   - a new connection that finds a cap full takes the place of the oldest connection under that cap
//     that has sent nothing; when every one of them has sent something, the new one is refused.
// So silent connections can't hold the slots a real client (or a client resuming its session) needs.
// Everything happens on the io_context's thread.
class admission {
public:
    using ticket = std::uint64_t; // 0 is never handed out
    // Closes a connection the admission gave up on: its slot went to a newer one (called from inside
    // that one's admit()), or it sent nothing in time (from a timer). Its ticket is already released.
    using close_fn = std::function<void(const error& why)>;

    admission(net::io_context& io, const Rhp::limits& limits);
    ~admission();

    admission(const admission&) = delete;
    admission& operator=(const admission&) = delete;

    // A slot for `link`, which comes back wrapped so its first byte is noticed (wrap it first, before
    // TLS: the TLS handshake's first record counts). kLimitExceeded when a cap is full of connections
    // that have sent something; `link` is then left as it was, for the caller to close.
    [[nodiscard]] result<ticket> admit(std::unique_ptr<net::link>& link, close_fn close);

    // The connection authenticated, was handed to the session it resumed, or closed: its slot is free.
    // Unknown tickets (0, released, or given up on) are ignored.
    void release(ticket t) noexcept;

    // Connections holding a slot.
    [[nodiscard]] std::size_t pending() const noexcept { return pending_.size(); }

private:
    using clock = std::chrono::steady_clock;

    struct entry {
        std::optional<net::ip_address> source;
        std::shared_ptr<bool> heard; // set by the watched link's first byte
        clock::time_point deadline;  // first_byte_ms after it arrived
        close_fn close;
    };

    // The oldest connection that has sent nothing (from `source`, when given) gives up its slot.
    [[nodiscard]] bool make_room(const std::optional<net::ip_address>& source, const error& why);
    // Removes an entry; its close function is returned to be called once the books are straight.
    close_fn take(std::map<ticket, entry>::iterator it);
    void arm_timer();
    void on_timer();

    net::io_context& io_;
    std::uint32_t total_cap_ = 0;
    std::uint32_t source_cap_ = 0;
    std::chrono::milliseconds first_byte_{};
    std::map<ticket, entry> pending_; // oldest first
    std::map<net::ip_address, std::uint32_t> per_source_;
    ticket last_ = 0;
    net::io_context::timer timer_;
    std::optional<clock::time_point> armed_;
};

} // namespace Rhp::session
