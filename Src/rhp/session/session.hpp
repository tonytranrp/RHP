#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

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
    kDetached, // the link is gone; waiting (limits.resume_ms) to continue on a new one
    kClosed
};

struct options {
    Rhp::limits limits{}; // max_frame, heartbeat_ms / heartbeat_misses, handshake_timeout_ms, resume_ms
    wire::codec_ops codec{};
    wire::decode_limits decode{};
    std::string platform;                      // this side's OS name, sent in the handshake
    std::size_t max_unacked_bytes = 64u << 20; // a peer that stops acking past this is dropped
    // A standalone ack waits this long for an outgoing frame to carry it (a reply usually does), so
    // a call and its reply are two frames instead of four. 0 acks every read at once. Acks still go
    // at once for the 8th unacknowledged frame, a frame that asks for one, and a duplicate.
    std::uint32_t ack_delay_ms = 5;
    // A lost link (or a dead heartbeat) detaches the session for limits.resume_ms instead of ending
    // it. The side that dialed brings a new link (resume()); the other side waits for it to arrive
    // (handler::resume_target).
    bool resumable = false;
    // Host side that dialed (reverse mode): open with an unsealed ping, so the side that accepted -
    // which speaks first in the handshake - learns from the first byte that this link is plaintext
    // (a TLS dialer opens with its ClientHello). Handshaking sessions ignore pings.
    bool speaks_first = false;
};

class session;

// The layer above (host or client). Every call happens on the session's io_context thread.
class handler {
public:
    // The handshake finished: identity(), granted() and id() are set.
    virtual void on_ready(session& s) = 0;
    // A sequenced message, in order, exactly once.
    virtual void on_message(session& s, wire::op code, value body) = 0;
    // The session ended (peer gone, heartbeat lost, protocol or auth failure, close(), not resumed
    // in time). Called once, from a posted handler: the session may be destroyed inside this call,
    // never inside the others. A connection that only carried a resume for another session ends
    // with errc::kOk.
    virtual void on_closed(session& s, const error& why) = 0;

    // A resumable session lost its link. The dialing side should dial again and call
    // s.resume(new_link) (again if that link fails too) until on_resumed or on_closed.
    virtual void on_detached(session& s, const error& why) {
        (void)s;
        (void)why;
    }
    // The session continues on a new link; whatever was unacknowledged has been resent.
    virtual void on_resumed(session& s) { (void)s; }
    // A new connection's first frame asks to resume session `id`: the session it means, if this
    // side has it (it then verifies the request with that session's keys). Not called during
    // another session's callbacks.
    virtual session* resume_target(session& fresh, session_id id) {
        (void)fresh;
        (void)id;
        return nullptr;
    }

protected:
    handler() = default;
    ~handler() = default;
    handler(const handler&) = default;
    handler& operator=(const handler&) = default;
};

// One authenticated, reliable conversation, over one link at a time.
//
// Frames: CRC32C on every frame except on encrypted (TLS) links; after the handshake a keyed MAC
// (the authenticator's per-direction keys) on every frame. Requests and replies are sequenced:
// cumulative acks, a resend window, a nack (with the last good seq) when a corrupt frame arrives or
// a gap shows, duplicates dropped. Control frames (ping, pong, ack, nack) are not acked or resent;
// they carry their own counter in `seq`, so a replayed one is dropped. A session error is an
// unsequenced kError. A ping goes out every heartbeat_ms; heartbeat_misses intervals without any
// frame from the peer end the session (or detach a resumable one).
//
// Resume (options.resumable): a lost link detaches the session; sends keep queueing. The dialing
// side calls resume(link), which sends a sealed kResume {session, proof} (bound to the new link) with the next control counter;
// the other side's new connection hands its link to the session it names, which answers with a
// sealed kWelcome. Both then resend what the other hasn't acknowledged, so every request and reply
// is delivered exactly once. Not resumed within limits.resume_ms: the session ends with the lost link's
// error code, "(not resumed within N ms)".
//
// Not thread-safe: every member is called on the io_context's thread.
class session final {
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

    // Sends a sequenced message (`code` is a request or reply op; kInvalidArgument otherwise). Ready
    // or detached (it waits for the resume); kTransport otherwise, kLimitExceeded if the encoded
    // payload exceeds max_frame, and kTransport when the peer has left more than
    // options::max_unacked_bytes unacknowledged (the session is then dropped).
    result<void> send(wire::op code, const value& body);

    // Tells the peer why (best effort), then closes. on_closed follows (with `why`).
    void close(error why);

    // Detached, dialing side: continue on `link` (a fresh connection to the same peer). If it fails
    // as well, on_detached is called again.
    void resume(std::unique_ptr<net::link> link);

    [[nodiscard]] session_id id() const noexcept { return id_; }
    [[nodiscard]] state current() const noexcept { return state_; }
    [[nodiscard]] bool ready() const noexcept { return state_ == state::kReady; }
    // Ready, or detached and still allowed to resume: send() works.
    [[nodiscard]] bool usable() const noexcept { return state_ == state::kReady || state_ == state::kDetached; }
    [[nodiscard]] const std::string& identity() const noexcept { return identity_; }
    [[nodiscard]] role granted() const noexcept { return granted_; }
    [[nodiscard]] const std::string& peer() const noexcept { return peer_; }
    [[nodiscard]] const std::string& peer_platform() const noexcept { return peer_platform_; }
    // The current link is encrypted (TLS).
    [[nodiscard]] bool encrypted() const noexcept { return link_ != nullptr && link_->encrypted(); }
    // This connection only carried a resume: its link went to the session it named.
    [[nodiscard]] bool handed_over() const noexcept { return handed_over_; }

    struct counters {
        std::uint64_t sent = 0;       // sequenced frames sent (first time)
        std::uint64_t received = 0;   // sequenced frames delivered
        std::uint64_t resent = 0;     // sequenced frames sent again (nack, ack timeout, resume)
        std::uint64_t duplicates = 0; // sequenced frames dropped as already delivered
        std::uint64_t crc_errors = 0;
        std::uint64_t nacks_sent = 0;
        std::uint64_t resumes = 0; // times the session continued on a new link
    };
    [[nodiscard]] const counters& stats() const noexcept { return stats_; }

private:
    using handshake_state = std::variant<std::unique_ptr<security::host_handshake>, std::unique_ptr<security::client_handshake>>;

    session(net::io_context& io, std::unique_ptr<net::link> link, handshake_state handshake, handler& h, options opts, bool host_side, session_id id);

    struct unacked_frame {
        std::uint64_t seq = 0;
        wire::op code = wire::op::kResult;
        utils::byte_buffer payload;
    };

    // Receives a link's callbacks and forwards them to whichever session owns the link now, so a
    // link can move from a fresh connection's session to the one it resumes.
    struct link_port;

    void on_bytes(utils::bytes_view data);
    void on_link_closed(const error& why);
    void receive(utils::bytes_view data);

    void handle(const wire::frame_view& frame);
    void handle_control(const wire::frame_view& frame);
    void deliver(const wire::frame_view& frame);
    // The frame carries a MAC that verifies under the peer's key.
    [[nodiscard]] bool mac_ok(const wire::frame_view& frame) const;
    void handle_handshake(const wire::frame_view& frame);
    void host_handshake_step(const wire::frame_view& frame);
    void host_hello(const value& body);
    void host_response(const value& body);
    void client_handshake_step(const wire::frame_view& frame);
    void client_challenge(const wire::frame_view& frame);
    void client_welcome(const wire::frame_view& frame);
    void become_ready();

    // Resume: the fresh connection's side, the resumed session's side, the dialer's side.
    void request_resume(const wire::frame_view& frame);
    [[nodiscard]] result<void> adopt(session& fresh, const wire::frame_view& frame);
    void handle_resume_reply(const wire::frame_view& frame);
    [[nodiscard]] bool sealed_control(const wire::frame_view& frame) const;
    void enter_resumed(const wire::frame_view& frame);
    void finish_resumed();
    void detach(error why);
    // A sealed kResume or kWelcome {session, proof over `label` and the link's channel binding}.
    [[nodiscard]] result<void> write_resume_frame(wire::op code, std::string_view label);
    void send_resume();
    // Detached: the link a resume was tried on is given up (it failed, timed out, or carried
    // something wrong); the dialing side tries another. Never ends the session.
    void lose_resume_link(error why);
    [[nodiscard]] bool resume_proof_ok(std::string_view label, std::span<const std::byte> binding, const value::bytes& proof) const;
    void retire_link();
    void attach(std::unique_ptr<net::link> link, std::unique_ptr<link_port> port);

    [[nodiscard]] result<value> decode(utils::bytes_view payload) const;
    // The Rhp::error a peer's kError frame carries, or `fallback` if it doesn't decode.
    [[nodiscard]] error peer_error(utils::bytes_view payload, error fallback) const;
    // Encodes one frame and writes it (when there is a link).
    result<void> write_frame(wire::op code, std::uint64_t seq, utils::bytes_view payload, bool sealed);
    // A handshake or control frame, or a session-ending kError: written now (nothing while detached).
    result<void> write_unsequenced(wire::op code, std::uint64_t seq, utils::bytes_view payload, bool sealed);
    // A sequenced frame (always sealed): kept in the resend window until acked, sent from there.
    result<void> queue_sequenced(wire::op code, std::uint64_t seq, utils::byte_buffer&& payload);
    result<void> write_value(wire::op code, const value& body, bool sealed);
    void write_control(wire::op code);
    void acknowledge(std::uint64_t ack);
    void resend_after(std::uint64_t ack);
    void send_ack_if_due();
    void send_nack();
    void heartbeat();
    void start_heartbeat();

    // Sends an unsequenced error frame (best effort), then shuts down.
    void fail_with(error why);
    void shutdown(error why);

    // A link that was replaced or lost, kept until it is surely not inside one of its own callbacks.
    struct retired_link {
        std::unique_ptr<link_port> port;
        std::unique_ptr<net::link> link; // destroyed first
    };

    net::io_context& io_;
    std::unique_ptr<link_port> port_;
    std::unique_ptr<net::link> link_; // destroyed before port_
    std::vector<retired_link> retired_;
    handshake_state handshake_;
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
    bool challenged_ = false;  // host: hello answered; client: response sent
    bool heard_ = false;       // a frame has arrived (a resume request must be the first)
    bool resuming_ = false;   // detached, dialing side: a resume is under way on the current link
    bool resume_pending_ = false; // ... but the link's TLS isn't up yet: kResume goes once it is
    bool handed_over_ = false; // this connection's link went to the session it resumed

    wire::frame_decoder decoder_;
    std::uint64_t next_seq_ = 1;    // next sequenced frame we send
    std::uint64_t expected_ = 1;    // next sequenced frame we deliver
    std::uint64_t ack_sent_ = 0;    // highest ack we have told the peer
    std::uint64_t nacked_at_ = 0;   // expected_ when we last nacked (one nack per gap)
    std::uint64_t peer_acked_ = 0;  // highest ack the peer sent us
    std::uint64_t control_out_ = 0; // counter of the control frames we send (in their `seq`)
    std::uint64_t control_in_ = 0;  // highest control counter received
    std::deque<unacked_frame> unacked_;
    std::size_t unacked_bytes_ = 0;
    int bad_magic_strikes_ = 0;

    net::io_context::timer handshake_timer_;
    net::io_context::timer heartbeat_timer_;
    net::io_context::timer ack_timer_;
    bool ack_now_ = false;       // the next send_ack_if_due acks at once (requested, or a duplicate)
    bool ack_timer_armed_ = false;
    net::io_context::timer resume_timer_;
    bool heard_since_tick_ = false;
    std::uint32_t misses_ = 0;
    std::uint64_t acked_at_last_tick_ = 0;

    counters stats_;
    bool closed_ = false;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
};

} // namespace Rhp::session
