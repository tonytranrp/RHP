#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <utility>
#include <variant>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/session/session.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::session {

namespace {

constexpr int kMaxBadMagic = 3;

[[nodiscard]] std::chrono::milliseconds ms(std::uint32_t n) noexcept {
    return std::chrono::milliseconds{n};
}

} // namespace

session::session(net::io_context& io, std::unique_ptr<net::link> link, std::unique_ptr<security::host_handshake> handshake, handler& h, options opts,
                 session_id id)
    : io_(io),
      link_(std::move(link)),
      handshake_(std::move(handshake)),
      handler_(h),
      opts_(std::move(opts)),
      host_side_(true),
      id_(id),
      peer_(link_->peer()),
      decoder_(opts_.limits.max_frame),
      handshake_timer_(io),
      heartbeat_timer_(io) {}

session::session(net::io_context& io, std::unique_ptr<net::link> link, std::unique_ptr<security::client_handshake> handshake, handler& h, options opts)
    : io_(io),
      link_(std::move(link)),
      handshake_(std::move(handshake)),
      handler_(h),
      opts_(std::move(opts)),
      host_side_(false),
      peer_(link_->peer()),
      decoder_(opts_.limits.max_frame),
      handshake_timer_(io),
      heartbeat_timer_(io) {}

session::~session() {
    *alive_ = false;
    handshake_timer_.cancel();
    heartbeat_timer_.cancel();
    link_.reset(); // aborts: no callbacks after this
}

void session::start() {
    link_->start(*this);
    if (opts_.limits.handshake_timeout_ms != 0) {
        handshake_timer_.start(ms(opts_.limits.handshake_timeout_ms), [this] {
            if (state_ == state::kHandshaking) {
                fail_with(make_error(errc::kTimeout, std::format("no handshake within {} ms", opts_.limits.handshake_timeout_ms), peer_));
            }
        });
    }
    if (!host_side_) {
        auto& hs = std::get<std::unique_ptr<security::client_handshake>>(handshake_);
        auto auth = hs->hello();
        if (!auth) {
            shutdown(std::move(auth).error());
            return;
        }
        const wire::hello hello{wire::kProtocolRevision, opts_.platform, std::move(*auth)};
        if (auto sent = write_value(wire::op::kHello, Rhp::to_value(hello), false); !sent) {
            shutdown(std::move(sent).error());
        }
    }
}

// ---- receiving ----------------------------------------------------------------------------------------

void session::on_bytes(utils::bytes_view data) {
    if (closed_) {
        return;
    }
    decoder_.feed(data);
    while (!closed_) {
        const wire::decode_result r = decoder_.next();
        switch (r.status) {
        case wire::decode_status::kNeedMore: send_ack_if_due(); return;
        case wire::decode_status::kBadMagic:
            // Before the handshake the peer has proven nothing: one strike. After it, a few
            // (garbage between frames can be a corrupted header; the decoder resynchronizes).
            if (state_ != state::kReady || ++bad_magic_strikes_ >= kMaxBadMagic) {
                fail_with(make_error(errc::kProtocol, "the peer is not speaking the RHP protocol", peer_));
            }
            continue;
        case wire::decode_status::kTooLarge:
            fail_with(make_error(errc::kLimitExceeded, std::format("a {}-byte frame exceeds the {}-byte limit", r.frame.header.length, opts_.limits.max_frame), peer_));
            return;
        case wire::decode_status::kBadRevision:
            fail_with(make_error(errc::kProtocolRevisionMismatch,
                                 std::format("the peer speaks protocol revision {}, this side {}", r.frame.header.revision, wire::kProtocolRevision), peer_));
            return;
        case wire::decode_status::kBadCrc:
            ++stats_.crc_errors;
            if (state_ == state::kReady) {
                send_nack();
            } else {
                fail_with(make_error(errc::kIntegrity, "a handshake frame failed its CRC", peer_));
            }
            continue;
        case wire::decode_status::kFrame: handle(r.frame); continue;
        }
    }
}

void session::on_closed(const error& why) {
    shutdown(why.code == errc::kOk ? make_error(errc::kTransport, "the link closed", peer_) : why);
}

void session::handle(const wire::frame_view& frame) {
    heard_since_tick_ = true;
    if (state_ != state::kReady) {
        handle_handshake(frame);
        return;
    }
    if (!wire::has(frame.header.flags, wire::frame_flag::kMac) || !incoming_->verify(frame.sealed, frame.mac.first<wire::kMacSize>())) {
        fail_with(make_error(errc::kAuth, std::format("a {} frame failed its MAC check", frame.header.code), peer_));
        return;
    }
    acknowledge(frame.header.ack);

    const wire::op code = frame.header.code;
    if (!wire::is_known(static_cast<std::uint16_t>(code)) || wire::is_handshake(code)) {
        fail_with(make_error(errc::kProtocol, std::format("unexpected op {} on a ready session", static_cast<std::uint16_t>(code)), peer_));
        return;
    }
    if (wire::has(frame.header.flags, wire::frame_flag::kAckRequested)) {
        ack_sent_ = 0; // forces an ack at the end of this read
    }
    if (!wire::is_sequenced(code) || frame.header.seq == 0) {
        switch (code) {
        case wire::op::kPing: write_control(wire::op::kPong, expected_ - 1); return;
        case wire::op::kPong:
        case wire::op::kAck: return;
        case wire::op::kNack: resend_after(frame.header.ack); return;
        case wire::op::kError: {
            // seq 0: the peer is closing the session and says why.
            shutdown(peer_error(frame.payload, make_error(errc::kProtocol, "the peer closed the session", peer_)));
            return;
        }
        default: fail_with(make_error(errc::kProtocol, std::format("{} frame without a sequence number", code), peer_)); return;
        }
    }

    if (frame.header.seq < expected_) {
        ++stats_.duplicates;
        ack_sent_ = 0; // our ack may have been lost: repeat it
        return;
    }
    if (frame.header.seq > expected_) {
        send_nack(); // a frame before this one was lost to corruption
        return;
    }
    auto body = decode(frame.payload);
    if (!body) {
        fail_with(std::move(body).error());
        return;
    }
    ++expected_;
    ++stats_.received;
    handler_.on_message(*this, code, std::move(*body));
}

void session::handle_handshake(const wire::frame_view& frame) {
    if (frame.header.code == wire::op::kError) {
        shutdown(peer_error(frame.payload, make_error(errc::kAuth, "the peer refused the handshake", peer_)));
        return;
    }
    if (host_side_) {
        host_handshake_step(frame);
    } else {
        client_handshake_step(frame);
    }
}

void session::host_handshake_step(const wire::frame_view& frame) {
    auto& hs = *std::get<std::unique_ptr<security::host_handshake>>(handshake_);
    auto body = decode(frame.payload);
    if (!body) {
        fail_with(std::move(body).error());
        return;
    }
    if (frame.header.code == wire::op::kHello && !challenged_) {
        auto hello = Rhp::from_value<wire::hello>(*body);
        if (!hello) {
            fail_with(std::move(hello).error());
            return;
        }
        if (hello->revision != wire::kProtocolRevision) {
            fail_with(make_error(errc::kProtocolRevisionMismatch, std::format("the client speaks protocol revision {}, the host {}", hello->revision, wire::kProtocolRevision),
                                 peer_));
            return;
        }
        peer_platform_ = hello->platform;
        auto auth = hs.challenge(hello->auth);
        if (!auth) {
            fail_with(std::move(auth).error());
            return;
        }
        challenged_ = true;
        const wire::challenge challenge{wire::kProtocolRevision, opts_.platform, std::move(*auth)};
        if (auto sent = write_value(wire::op::kChallenge, Rhp::to_value(challenge), false); !sent) {
            fail_with(std::move(sent).error());
        }
        return;
    }
    if (frame.header.code == wire::op::kResponse && challenged_) {
        auto response = Rhp::from_value<wire::response>(*body);
        if (!response) {
            fail_with(std::move(response).error());
            return;
        }
        auto grant = hs.verify(response->auth);
        if (!grant) {
            fail_with(std::move(grant).error());
            return;
        }
        identity_ = std::move(grant->identity);
        granted_ = grant->granted;
        outgoing_ = std::move(grant->outgoing);
        incoming_ = std::move(grant->incoming);
        const wire::welcome welcome{id_, identity_, granted_, opts_.limits.heartbeat_ms, opts_.platform};
        if (auto sent = write_value(wire::op::kWelcome, Rhp::to_value(welcome), true); !sent) {
            fail_with(std::move(sent).error());
            return;
        }
        become_ready();
        return;
    }
    fail_with(make_error(errc::kProtocol, std::format("unexpected {} during the handshake", frame.header.code), peer_));
}

void session::client_handshake_step(const wire::frame_view& frame) {
    auto& hs = *std::get<std::unique_ptr<security::client_handshake>>(handshake_);
    if (frame.header.code == wire::op::kChallenge && !challenged_) {
        auto body = decode(frame.payload);
        if (!body) {
            fail_with(std::move(body).error());
            return;
        }
        auto challenge = Rhp::from_value<wire::challenge>(*body);
        if (!challenge) {
            fail_with(std::move(challenge).error());
            return;
        }
        if (challenge->revision != wire::kProtocolRevision) {
            fail_with(make_error(errc::kProtocolRevisionMismatch,
                                 std::format("the host speaks protocol revision {}, the client {}", challenge->revision, wire::kProtocolRevision), peer_));
            return;
        }
        peer_platform_ = challenge->platform;
        auto auth = hs.respond(challenge->auth);
        if (!auth) {
            fail_with(std::move(auth).error());
            return;
        }
        auto grant = hs.finish();
        if (!grant) {
            fail_with(std::move(grant).error());
            return;
        }
        identity_ = std::move(grant->identity);
        outgoing_ = std::move(grant->outgoing);
        incoming_ = std::move(grant->incoming);
        challenged_ = true;
        if (auto sent = write_value(wire::op::kResponse, Rhp::to_value(wire::response{std::move(*auth)}), false); !sent) {
            fail_with(std::move(sent).error());
        }
        return;
    }
    if (frame.header.code == wire::op::kWelcome && challenged_) {
        // The first frame under the agreed keys: it proves the host derived them too.
        if (!wire::has(frame.header.flags, wire::frame_flag::kMac) || !incoming_->verify(frame.sealed, frame.mac.first<wire::kMacSize>())) {
            fail_with(make_error(errc::kAuth, "the host's welcome failed its MAC check", peer_));
            return;
        }
        auto body = decode(frame.payload);
        if (!body) {
            fail_with(std::move(body).error());
            return;
        }
        auto welcome = Rhp::from_value<wire::welcome>(*body);
        if (!welcome) {
            fail_with(std::move(welcome).error());
            return;
        }
        id_ = welcome->session;
        identity_ = std::move(welcome->identity);
        granted_ = welcome->granted;
        become_ready();
        return;
    }
    fail_with(make_error(errc::kProtocol, std::format("unexpected {} during the handshake", frame.header.code), peer_));
}

void session::become_ready() {
    state_ = state::kReady;
    handshake_timer_.cancel();
    handshake_ = std::unique_ptr<security::host_handshake>{}; // secrets of the handshake go now
    if (opts_.limits.heartbeat_ms != 0) {
        heartbeat_timer_.start(ms(opts_.limits.heartbeat_ms), [this] { heartbeat(); });
    }
    handler_.on_ready(*this);
}

error session::peer_error(utils::bytes_view payload, error fallback) const {
    if (auto body = decode(payload)) {
        if (auto err = Rhp::from_value<error>(*body)) {
            return std::move(*err);
        }
    }
    return fallback;
}

result<value> session::decode(utils::bytes_view payload) const {
    auto v = opts_.codec.decode(payload, opts_.decode);
    if (!v) {
        v.error().where = std::format("{} ({})", peer_, v.error().where);
    }
    return v;
}

// ---- sending ------------------------------------------------------------------------------------------

result<void> session::write(wire::op code, std::uint64_t seq, utils::bytes_view payload, bool sealed) {
    wire::frame_header header;
    header.code = code;
    header.seq = seq;
    header.ack = expected_ - 1;
    utils::byte_buffer bytes;
    bytes.reserve(wire::kHeaderSize + payload.size() + wire::kCrcSize + (sealed ? wire::kMacSize : 0));
    if (auto ok = wire::encode_frame(header, payload, bytes, sealed ? outgoing_.get() : nullptr, opts_.limits.max_frame); !ok) {
        return ok;
    }
    ack_sent_ = header.ack;
    if (seq != 0) {
        unacked_bytes_ += bytes.size();
        unacked_.push_back({seq, bytes});
        if (unacked_bytes_ > opts_.max_unacked_bytes) {
            fail_with(make_error(errc::kLimitExceeded, std::format("the peer left {} bytes unacknowledged", unacked_bytes_), peer_));
            return Rhp::fail(errc::kTransport, "session closed", peer_);
        }
    }
    link_->send(std::move(bytes));
    return {};
}

result<void> session::write_value(wire::op code, const value& body, bool sealed) {
    utils::byte_buffer payload;
    if (auto encoded = opts_.codec.encode(body, payload); !encoded) {
        return encoded;
    }
    return write(code, 0, payload.view(), sealed);
}

result<void> session::send(wire::op code, const value& body) {
    if (state_ != state::kReady || closed_) {
        return Rhp::fail(errc::kTransport, "the session is not ready", peer_);
    }
    if (!wire::is_sequenced(code)) {
        return Rhp::fail(errc::kInvalidArgument, std::format("{} is not a request or reply op", code), "session.send");
    }
    utils::byte_buffer payload;
    if (auto encoded = opts_.codec.encode(body, payload); !encoded) {
        return encoded;
    }
    if (auto ok = write(code, next_seq_, payload.view(), true); !ok) {
        return ok;
    }
    ++next_seq_;
    ++stats_.sent;
    return {};
}

void session::write_control(wire::op code, std::uint64_t ack_value) {
    (void)ack_value; // the header's ack is always expected_ - 1
    (void)write(code, 0, {}, state_ == state::kReady);
}

void session::acknowledge(std::uint64_t ack) {
    // An ack beyond what we sent is a confused (or hostile) peer: never let it stall later acks.
    if (ack >= next_seq_) {
        ack = next_seq_ - 1;
    }
    if (ack <= peer_acked_) {
        return;
    }
    peer_acked_ = ack;
    while (!unacked_.empty() && unacked_.front().seq <= ack) {
        unacked_bytes_ -= unacked_.front().bytes.size();
        unacked_.pop_front();
    }
}

void session::resend_after(std::uint64_t ack) {
    acknowledge(ack);
    for (const unacked_frame& f : unacked_) {
        if (f.seq > ack) {
            link_->send(f.bytes);
            ++stats_.resent;
        }
    }
}

void session::send_ack_if_due() {
    if (state_ == state::kReady && !closed_ && expected_ - 1 != ack_sent_) {
        write_control(wire::op::kAck, expected_ - 1);
    }
}

void session::send_nack() {
    if (nacked_at_ == expected_) {
        return; // already asked for this gap; the heartbeat resend covers a lost nack
    }
    nacked_at_ = expected_;
    ++stats_.nacks_sent;
    write_control(wire::op::kNack, expected_ - 1);
}

void session::heartbeat() {
    if (closed_ || state_ != state::kReady) {
        return;
    }
    if (heard_since_tick_) {
        misses_ = 0;
    } else if (++misses_ >= opts_.limits.heartbeat_misses && opts_.limits.heartbeat_misses != 0) {
        fail_with(make_error(errc::kTimeout, std::format("no frame from the peer for {} heartbeats", misses_), peer_));
        return;
    }
    heard_since_tick_ = false;
    // Nothing acked for a whole interval: the peer may have lost a frame or our nack answer.
    if (!unacked_.empty() && peer_acked_ == acked_at_last_tick_) {
        resend_after(peer_acked_);
    }
    acked_at_last_tick_ = peer_acked_;
    nacked_at_ = 0; // allow a fresh nack for a gap that is still open
    write_control(wire::op::kPing, expected_ - 1);
    if (!closed_) {
        heartbeat_timer_.start(ms(opts_.limits.heartbeat_ms), [this] { heartbeat(); });
    }
}

// ---- closing ------------------------------------------------------------------------------------------

void session::fail_with(error why) {
    if (closed_) {
        return;
    }
    if (why.where.empty()) {
        why.where = peer_;
    }
    // Tell the peer (unsequenced kError), sealed once both sides have keys.
    utils::byte_buffer payload;
    if (opts_.codec.encode(Rhp::to_value(why), payload)) {
        (void)write(wire::op::kError, 0, payload.view(), state_ == state::kReady);
    }
    shutdown(std::move(why));
}

void session::close(error why) {
    if (why.code == errc::kOk) {
        why = make_error(errc::kCancelled, "closed", peer_);
    }
    fail_with(std::move(why));
}

void session::shutdown(error why) {
    if (closed_) {
        return;
    }
    closed_ = true;
    state_ = state::kClosed;
    handshake_timer_.cancel();
    heartbeat_timer_.cancel();
    link_->close(); // writes what is queued (the error frame), then closes
    io_.post([this, alive = std::weak_ptr<bool>{alive_}, why = std::move(why)] {
        if (const auto still = alive.lock(); still != nullptr && *still) {
            handler_.on_closed(*this, why);
        }
    });
}

} // namespace Rhp::session
