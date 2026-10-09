#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <variant>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::session {

enum class state : std::uint8_t {
    kHandshaking,
    kReady,
    kClosed
};

struct options {
    Rhp::limits limits{}; // max_frame, heartbeat_ms / heartbeat_misses, handshake_timeout_ms
    wire::codec_ops codec{};
    wire::decode_limits decode{};
    std::string platform;                      // this side's OS name, sent in the handshake
    std::size_t max_unacked_bytes = 64u << 20; // a peer that stops acking past this is dropped
};

class session;

// The layer above (host or client). Every call happens on the session's io_context thread.
class handler {
public:
    // The handshake finished: identity(), granted() and id() are set.
    virtual void on_ready(session& s) = 0;
    // A sequenced message, in order, exactly once.
    virtual void on_message(session& s, wire::op code, value body) = 0;
    // The session ended (peer gone, heartbeat lost, protocol or auth failure, close()). Called
    // once, from a posted handler: the session may be destroyed inside this call, never inside the
    // other two.
    virtual void on_closed(session& s, const error& why) = 0;

protected:
    handler() = default;
    ~handler() = default;
    handler(const handler&) = default;
    handler& operator=(const handler&) = default;
};

// One authenticated, reliable conversation over a link.
//
// Frames: CRC32C on every frame; after the handshake a keyed MAC (the authenticator's per-direction
// keys) on every frame. Requests and replies are sequenced: cumulative acks, a resend window, a
// nack (with the last good seq) when a corrupt frame arrives or a gap shows, duplicates dropped.
// Control frames (ping, pong, ack, nack, session errors) are unsequenced. A ping goes out every
// heartbeat_ms; heartbeat_misses intervals without any frame from the peer end the session.
//
// Not thread-safe: every member is called on the io_context's thread.
class session final : private net::link_handler {
public:
    // Host side: waits for the client's hello; `id` goes out in the welcome.
    session(net::io_context& io, std::unique_ptr<net::link> link, std::unique_ptr<security::host_handshake> handshake, handler& h, options opts,
            session_id id);
    // Client side: sends hello once started; the host's welcome names the session.
    session(net::io_context& io, std::unique_ptr<net::link> link, std::unique_ptr<security::client_handshake> handshake, handler& h, options opts);
    ~session();

    session(const session&) = delete;
    session& operator=(const session&) = delete;

    void start();

    // Sends a sequenced message (`code` is a request or reply op). Fails with kTransport unless
    // ready, kLimitExceeded if the encoded payload exceeds max_frame.
    result<void> send(wire::op code, const value& body);

    // Tells the peer why (best effort), then closes. on_closed follows (with `why`).
    void close(error why);

    [[nodiscard]] session_id id() const noexcept { return id_; }
    [[nodiscard]] state current() const noexcept { return state_; }
    [[nodiscard]] bool ready() const noexcept { return state_ == state::kReady; }
    [[nodiscard]] const std::string& identity() const noexcept { return identity_; }
    [[nodiscard]] role granted() const noexcept { return granted_; }
    [[nodiscard]] const std::string& peer() const noexcept { return peer_; }
    [[nodiscard]] const std::string& peer_platform() const noexcept { return peer_platform_; }

    struct counters {
        std::uint64_t sent = 0;       // sequenced frames sent (first time)
        std::uint64_t received = 0;   // sequenced frames delivered
        std::uint64_t resent = 0;     // sequenced frames sent again (nack or ack timeout)
        std::uint64_t duplicates = 0; // sequenced frames dropped as already delivered
        std::uint64_t crc_errors = 0;
        std::uint64_t nacks_sent = 0;
    };
    [[nodiscard]] const counters& stats() const noexcept { return stats_; }

private:
    struct unacked_frame {
        std::uint64_t seq = 0;
        utils::byte_buffer bytes;
    };

    // net::link_handler
    void on_bytes(utils::bytes_view data) override;
    void on_closed(const error& why) override;

    void handle(const wire::frame_view& frame);
    void handle_handshake(const wire::frame_view& frame);
    void host_handshake_step(const wire::frame_view& frame);
    void client_handshake_step(const wire::frame_view& frame);
    void become_ready();

    [[nodiscard]] result<value> decode(utils::bytes_view payload) const;
    // The Rhp::error a peer's kError frame carries, or `fallback` if it doesn't decode.
    [[nodiscard]] error peer_error(utils::bytes_view payload, error fallback) const;
    // Encodes and writes one frame; sequenced ones are kept until acked.
    result<void> write(wire::op code, std::uint64_t seq, utils::bytes_view payload, bool sealed);
    result<void> write_value(wire::op code, const value& body, bool sealed);
    void write_control(wire::op code, std::uint64_t ack_value);
    void acknowledge(std::uint64_t ack);
    void resend_after(std::uint64_t ack);
    void send_ack_if_due();
    void send_nack();
    void heartbeat();

    // Sends an unsequenced error frame (best effort), then shuts down.
    void fail_with(error why);
    void shutdown(error why);

    net::io_context& io_;
    std::unique_ptr<net::link> link_;
    std::variant<std::unique_ptr<security::host_handshake>, std::unique_ptr<security::client_handshake>> handshake_;
    handler& handler_;
    options opts_;
    bool host_side_;

    state state_ = state::kHandshaking;
    session_id id_;
    std::string identity_;
    role granted_ = role::kObserve;
    std::string peer_;
    std::string peer_platform_;
    std::unique_ptr<wire::frame_sealer> outgoing_;
    std::unique_ptr<wire::frame_sealer> incoming_;
    bool challenged_ = false; // host: hello answered; client: response sent

    wire::frame_decoder decoder_;
    std::uint64_t next_seq_ = 1;   // next sequenced frame we send
    std::uint64_t expected_ = 1;   // next sequenced frame we deliver
    std::uint64_t ack_sent_ = 0;   // highest ack we have told the peer
    std::uint64_t nacked_at_ = 0;  // expected_ when we last nacked (one nack per gap)
    std::uint64_t peer_acked_ = 0; // highest ack the peer sent us
    std::deque<unacked_frame> unacked_;
    std::size_t unacked_bytes_ = 0;
    int bad_magic_strikes_ = 0;

    net::io_context::timer handshake_timer_;
    net::io_context::timer heartbeat_timer_;
    bool heard_since_tick_ = false;
    std::uint32_t misses_ = 0;
    std::uint64_t acked_at_last_tick_ = 0;

    counters stats_;
    bool closed_ = false;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

} // namespace Rhp::session
