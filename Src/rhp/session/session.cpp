#include <algorithm>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <string_view>
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
// Before the handshake the peer is anonymous: its frames may only be this big.
constexpr std::uint32_t kHandshakeMaxFrame = 16u * 1024u;
// Replaced links kept around (they may still be inside a callback when replaced).
constexpr std::size_t kMaxRetired = 4;
// One resume attempt (a new link and its kResume) gets at most this long before the next is tried.
constexpr std::uint32_t kResumeAttemptMs = 2'000;
constexpr std::string_view kResumeLabel = "rhp/resume";
constexpr std::string_view kResumedLabel = "rhp/resumed";
// A longer key name in a hello isn't kept for reports (it can't be a real one).
constexpr std::size_t kMaxOfferedKey = 256;

[[nodiscard]] std::chrono::milliseconds ms(std::uint32_t n) noexcept {
    return std::chrono::milliseconds{n};
}

// What a resume proof is a MAC over: label || the connection's channel binding.
[[nodiscard]] utils::byte_buffer resume_transcript(std::string_view label, std::span<const std::byte> binding) {
    utils::byte_buffer what;
    what.append(label);
    what.append(binding);
    return what;
}

[[nodiscard]] wire::mac_bytes resume_proof(const wire::frame_sealer& sealer, std::string_view label, std::span<const std::byte> binding) {
    return sealer.seal(resume_transcript(label, binding).view());
}

// Runs `fn` later on `io`'s thread, unless the session `alive` belongs to is gone by then.
template <std::invocable F>
void post_guarded(net::io_context& io, const std::shared_ptr<bool>& alive_flag, F work) {
    io.post([alive = std::weak_ptr<bool>{alive_flag}, fn = std::move(work)] {
        if (const auto still = alive.lock(); still != nullptr && *still) {
            fn();
        }
    });
}

} // namespace

struct session::link_port final : net::link_handler {
    session* owner = nullptr;

    void on_bytes(utils::bytes_view data) override {
        if (owner != nullptr) {
            owner->on_bytes(data);
        }
    }

    void on_closed(const error& why) override {
        if (owner != nullptr) {
            owner->on_link_closed(why);
        }
    }
};

session::session(net::io_context& io, std::unique_ptr<net::link> link, std::unique_ptr<security::host_handshake> handshake, handler& h, options opts,
                 session_id id)
    : session(io, std::move(link), handshake_state{std::move(handshake)}, h, std::move(opts), true, id) {}

session::session(net::io_context& io, std::unique_ptr<net::link> link, std::unique_ptr<security::client_handshake> handshake, handler& h, options opts)
    : session(io, std::move(link), handshake_state{std::move(handshake)}, h, std::move(opts), false, session_id{}) {}

session::session(net::io_context& io, std::unique_ptr<net::link> link, handshake_state handshake, handler& h, options opts, bool host_side, session_id id)
    : io_(io),
      port_(std::make_unique<link_port>()),
      link_(std::move(link)),
      handshake_(std::move(handshake)),
      handler_(h),
      opts_(std::move(opts)),
      host_side_(host_side),
      id_(id),
      peer_(link_->peer()),
      decoder_(std::min(kHandshakeMaxFrame, opts_.limits.max_frame)),
      handshake_timer_(io),
      heartbeat_timer_(io),
      ack_timer_(io),
      resume_timer_(io) {
    port_->owner = this;
}

session::~session() {
    *alive_ = false;
    handshake_timer_.cancel();
    heartbeat_timer_.cancel();
    ack_timer_.cancel();
    resume_timer_.cancel();
    link_.reset(); // aborts: no callbacks after this
    retired_.clear();
}

void session::start() {
    link_->start(*port_);
    if (opts_.limits.handshake_timeout_ms != 0) {
        handshake_timer_.start(ms(opts_.limits.handshake_timeout_ms), [this] {
            if (state_ == state::kHandshaking) {
                fail_with(make_error(errc::kTimeout, std::format("no handshake within {} ms", opts_.limits.handshake_timeout_ms), peer_));
            }
        });
    }
    if (host_side_ && opts_.speaks_first) {
        (void)write_unsequenced(wire::op::kPing, 0, utils::bytes_view{}, false);
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
    // An exception (out of memory decoding what a peer sent, a handler that threw) ends this
    // session, not the network thread every other session shares.
    try {
        receive(data);
    } catch (const std::exception& e) {
        try {
            shutdown(make_error(errc::kLimitExceeded, std::format("receiving failed: {}", e.what()), peer_));
        } catch (...) { // can't even build the error: the link still closes below
            closed_ = true;
            if (link_ != nullptr) {
                link_->close();
            }
        }
    }
}

void session::receive(utils::bytes_view data) {
    if (closed_) {
        return;
    }
    if (resume_pending_ && link_ != nullptr && !link_->channel_binding().empty()) {
        // The resume link's TLS just came up (an empty on_bytes says so): now the proof can name it.
        resume_pending_ = false;
        send_resume();
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

void session::on_link_closed(const error& why) {
    if (closed_) {
        return;
    }
    const error lost = why.code == errc::kOk ? make_error(errc::kTransport, "the link closed", peer_) : why;
    if (state_ == state::kDetached) {
        lose_resume_link(lost); // the link a resume was tried on failed too: try again
        return;
    }
    if (state_ == state::kReady && opts_.resumable && opts_.limits.resume_ms != 0) {
        detach(lost);
        return;
    }
    shutdown(lost);
}

void session::handle(const wire::frame_view& frame) {
    heard_since_tick_ = true;
    const bool first = !heard_;
    heard_ = true;
    if (wire::has(frame.header.flags, wire::frame_flag::kCrcOmitted) && !encrypted()) {
        fail_with(make_error(errc::kProtocol, "a frame without a CRC on an unencrypted link", peer_));
        return;
    }
    if (state_ == state::kDetached) {
        handle_resume_reply(frame);
        return;
    }
    if (state_ != state::kReady) {
        if (first && frame.header.code == wire::op::kResume) {
            request_resume(frame);
            return;
        }
        handle_handshake(frame);
        return;
    }
    if (!mac_ok(frame)) {
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
        ack_now_ = true;
    }
    if (!wire::is_sequenced(code) || frame.header.seq == 0) {
        handle_control(frame);
        return;
    }
    deliver(frame);
}

// Ready: an unsequenced frame, or a sequenced op without a sequence number.
void session::handle_control(const wire::frame_view& frame) {
    const wire::op code = frame.header.code;
    if (!wire::is_sequenced(code)) {
        // Control frames carry their own counter in `seq`: a replayed one (say, a captured nack
        // that would make us resend the whole window) is dropped.
        if (frame.header.seq <= control_in_) {
            return;
        }
        control_in_ = frame.header.seq;
    }
    switch (code) {
    case wire::op::kPing: write_control(wire::op::kPong); return;
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

// Ready: a sequenced frame, delivered once and in order.
void session::deliver(const wire::frame_view& frame) {
    if (frame.header.seq < expected_) {
        ++stats_.duplicates;
        ack_sent_ = 0; // our ack may have been lost: repeat it
        ack_now_ = true;
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
    handler_.on_message(*this, frame.header.code, std::move(*body));
}

bool session::mac_ok(const wire::frame_view& frame) const {
    return incoming_ != nullptr && wire::has(frame.header.flags, wire::frame_flag::kMac) && incoming_->verify(frame.sealed, frame.mac.first<wire::kMacSize>());
}

void session::handle_handshake(const wire::frame_view& frame) {
    if (frame.header.code == wire::op::kPing && frame.header.seq == 0) {
        return; // a dialing host's opening nudge (options::speaks_first)
    }
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
    // Decoded before the op is looked at: an undecodable frame reports that, whatever its op.
    auto body = decode(frame.payload);
    if (!body) {
        fail_with(std::move(body).error());
        return;
    }
    if (frame.header.code == wire::op::kHello && !challenged_) {
        host_hello(*body);
        return;
    }
    if (frame.header.code == wire::op::kResponse && challenged_) {
        host_response(*body);
        return;
    }
    fail_with(make_error(errc::kProtocol, std::format("unexpected {} during the handshake", frame.header.code), peer_));
}

void session::host_hello(const value& body) {
    auto hello = Rhp::from_value<wire::hello>(body);
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
    if (const value* key = hello->auth.find("key"); key != nullptr) {
        if (const std::string* name = key->get_if<std::string>(); name != nullptr && name->size() <= kMaxOfferedKey) {
            offered_key_ = *name;
        }
    }
    auto& hs = *std::get<std::unique_ptr<security::host_handshake>>(handshake_);
    hs.bind_channel(link_->channel_binding());
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
}

void session::host_response(const value& body) {
    auto response = Rhp::from_value<wire::response>(body);
    if (!response) {
        fail_with(std::move(response).error());
        return;
    }
    auto grant = std::get<std::unique_ptr<security::host_handshake>>(handshake_)->verify(response->auth);
    if (!grant) {
        fail_with(std::move(grant).error());
        return;
    }
    identity_ = std::move(grant->identity);
    granted_ = grant->granted;
    scopes_ = std::move(grant->scopes);
    outgoing_ = std::move(grant->outgoing);
    incoming_ = std::move(grant->incoming);
    host_key_ = std::move(grant->host_key);
    const wire::welcome welcome{id_, identity_, granted_, opts_.limits.heartbeat_ms, opts_.platform, host_key_};
    if (auto sent = write_value(wire::op::kWelcome, Rhp::to_value(welcome), true); !sent) {
        fail_with(std::move(sent).error());
        return;
    }
    become_ready();
}

void session::client_handshake_step(const wire::frame_view& frame) {
    if (frame.header.code == wire::op::kChallenge && !challenged_) {
        client_challenge(frame);
        return;
    }
    if (frame.header.code == wire::op::kWelcome && challenged_) {
        client_welcome(frame);
        return;
    }
    fail_with(make_error(errc::kProtocol, std::format("unexpected {} during the handshake", frame.header.code), peer_));
}

void session::client_challenge(const wire::frame_view& frame) {
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
    auto& hs = *std::get<std::unique_ptr<security::client_handshake>>(handshake_);
    hs.bind_channel(link_->channel_binding());
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
    host_key_ = std::move(grant->host_key);
    outgoing_ = std::move(grant->outgoing);
    incoming_ = std::move(grant->incoming);
    challenged_ = true;
    if (auto sent = write_value(wire::op::kResponse, Rhp::to_value(wire::response{std::move(*auth)}), false); !sent) {
        fail_with(std::move(sent).error());
    }
}

void session::client_welcome(const wire::frame_view& frame) {
    // The first frame under the agreed keys: it proves the host derived them too.
    if (!mac_ok(frame)) {
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
    // The handshake checked the host's key itself; the welcome, sealed under the agreed keys, must name the same one.
    if (welcome->host_key != host_key_) {
        fail_with(make_error(errc::kAuth, "the host's welcome names another device key than its handshake proved", peer_));
        return;
    }
    id_ = welcome->session;
    identity_ = std::move(welcome->identity);
    granted_ = welcome->granted;
    become_ready();
}

void session::become_ready() {
    state_ = state::kReady;
    decoder_.set_max_payload(opts_.limits.max_frame);
    handshake_timer_.cancel();
    handshake_ = std::unique_ptr<security::host_handshake>{}; // secrets of the handshake go now
    start_heartbeat();
    handler_.on_ready(*this);
}

// ---- resume -------------------------------------------------------------------------------------------

bool session::sealed_control(const wire::frame_view& frame) const {
    return mac_ok(frame) && frame.header.seq > control_in_;
}

// A fresh connection (no handshake yet) whose first frame asks to continue another session.
void session::request_resume(const wire::frame_view& frame) {
    auto body = decode(frame.payload);
    if (!body) {
        fail_with(std::move(body).error());
        return;
    }
    auto request = Rhp::from_value<wire::resume>(*body);
    if (!request) {
        fail_with(std::move(request).error());
        return;
    }
    session* target = handler_.resume_target(*this, request->session);
    if (target == nullptr || target == this) {
        fail_with(make_error(errc::kNotFound, std::format("no session {} to resume", request->session), peer_));
        return;
    }
    if (auto adopted = target->adopt(*this, frame); !adopted) {
        fail_with(std::move(adopted).error());
        return;
    }
    // The link is the other session's now; this one ends without a word.
    handed_over_ = true;
    closed_ = true;
    state_ = state::kClosed;
    handshake_timer_.cancel();
    post_guarded(io_, alive_, [this, id = request->session] { handler_.on_closed(*this, make_error(errc::kOk, std::format("resumed session {}", id), peer_)); });
}

// This session takes over `fresh`'s link, if `frame` (its first) is a valid resume request for it.
result<void> session::adopt(session& fresh, const wire::frame_view& frame) {
    if (closed_ || !opts_.resumable || (state_ != state::kReady && state_ != state::kDetached) || incoming_ == nullptr) {
        return fail(errc::kNotFound, std::format("session {} can't be resumed", id_), fresh.peer_);
    }
    if (!sealed_control(frame)) {
        return fail(errc::kAuth, "the resume request failed its MAC check", fresh.peer_);
    }
    auto body = decode(frame.payload);
    auto request = body ? Rhp::from_value<wire::resume>(*body) : result<wire::resume>{std::unexpected{body.error()}};
    if (!request || !resume_proof_ok(kResumeLabel, fresh.link_->channel_binding(), request->proof)) {
        return fail(errc::kAuth, "the resume request isn't bound to this connection (a relay in between?)", fresh.peer_);
    }
    // Not inside any callback of this session's own links: they can go now.
    retired_.clear();
    if (link_ != nullptr) {
        port_->owner = nullptr;
        link_.reset();
    }
    attach(std::move(fresh.link_), std::move(fresh.port_));
    resume_pending_ = false;
    enter_resumed(frame);
    if (auto sent = write_resume_frame(wire::op::kWelcome, kResumedLabel); !sent) {
        fail_with(std::move(sent).error());
        return {};
    }
    finish_resumed();
    return {};
}

void session::resume(std::unique_ptr<net::link> link) {
    if (closed_ || state_ != state::kDetached || link == nullptr) {
        return; // dropping `link` aborts it
    }
    if (link_ != nullptr) {
        retire_link();
    }
    attach(std::move(link), std::make_unique<link_port>());
    resuming_ = true;
    // One attempt gets a bounded time; a dial that connects but never answers doesn't eat the window.
    const std::uint32_t attempt = opts_.limits.handshake_timeout_ms == 0 ? kResumeAttemptMs : std::min(opts_.limits.handshake_timeout_ms, kResumeAttemptMs);
    handshake_timer_.start(ms(attempt), [this] {
        if (state_ == state::kDetached && resuming_) {
            lose_resume_link(make_error(errc::kTimeout, "the resume attempt got no answer", peer_));
        }
    });
    // Under TLS the proof names the new connection, whose binding exists once its handshake is done
    // (the link then reports an empty on_bytes); the request goes out then.
    resume_pending_ = link_->encrypted() && link_->channel_binding().empty();
    link_->start(*port_);
    if (!resume_pending_ && resuming_) {
        send_resume();
    }
}

// Detached, dialing side: the answer to our kResume (anything else is a stray handshake frame).
void session::handle_resume_reply(const wire::frame_view& frame) {
    if (!resuming_) {
        return;
    }
    if (frame.header.code == wire::op::kError) {
        // Unsealed, so anyone on the path could have sent it: give up this link, not the session
        // (a host that really dropped it lets the window run out).
        lose_resume_link(peer_error(frame.payload, make_error(errc::kNotFound, "the peer refused to resume the session", peer_)));
        return;
    }
    if (frame.header.code != wire::op::kWelcome) {
        return; // e.g. the hello of a reverse-mode client's new connection
    }
    if (!sealed_control(frame)) {
        lose_resume_link(make_error(errc::kAuth, "the resume answer failed its MAC check", peer_));
        return;
    }
    auto body = decode(frame.payload);
    auto answer = body ? Rhp::from_value<wire::resume>(*body) : result<wire::resume>{std::unexpected{body.error()}};
    if (!answer || answer->session != id_) {
        lose_resume_link(make_error(errc::kProtocol, "the resume answer names another session", peer_));
        return;
    }
    if (!resume_proof_ok(kResumedLabel, link_->channel_binding(), answer->proof)) {
        lose_resume_link(make_error(errc::kAuth, "the resume answer isn't bound to this connection (a relay in between?)", peer_));
        return;
    }
    enter_resumed(frame);
    finish_resumed();
}

// Both sides, once the resume frame checked out: ready on the new link, with the peer's ack taken.
void session::enter_resumed(const wire::frame_view& frame) {
    control_in_ = frame.header.seq;
    state_ = state::kReady;
    resuming_ = false;
    resume_timer_.cancel();
    handshake_timer_.cancel();
    acknowledge(frame.header.ack);
}

// ... then resend what the peer hasn't acknowledged and carry on.
void session::finish_resumed() {
    resend_after(peer_acked_);
    ++stats_.resumes;
    start_heartbeat();
    handler_.on_resumed(*this);
}

bool session::resume_proof_ok(std::string_view label, std::span<const std::byte> binding, const value::bytes& proof) const {
    if (incoming_ == nullptr || proof.size() != wire::kMacSize) {
        return false;
    }
    return incoming_->verify(resume_transcript(label, binding).view(), std::span<const std::byte, wire::kMacSize>{proof.data(), wire::kMacSize});
}

result<void> session::write_resume_frame(wire::op code, std::string_view label) {
    const wire::mac_bytes proof = resume_proof(*outgoing_, label, link_->channel_binding());
    utils::byte_buffer payload;
    if (auto encoded = opts_.codec.encode(Rhp::to_value(wire::resume{id_, value::bytes(proof.begin(), proof.end())}), payload); !encoded) {
        return encoded;
    }
    (void)write_frame(code, ++control_out_, payload.view(), true);
    return {};
}

void session::send_resume() {
    if (auto sent = write_resume_frame(wire::op::kResume, kResumeLabel); !sent) {
        shutdown(std::move(sent).error());
    }
}

void session::lose_resume_link(error why) {
    if (closed_ || state_ != state::kDetached) {
        return;
    }
    resuming_ = false;
    resume_pending_ = false;
    handshake_timer_.cancel();
    retire_link();
    post_guarded(io_, alive_, [this, why = std::move(why)] {
        if (state_ == state::kDetached && !resuming_) {
            handler_.on_detached(*this, why);
        }
    });
}

void session::detach(error why) {
    state_ = state::kDetached;
    resuming_ = false;
    heartbeat_timer_.cancel();
    ack_timer_.cancel();
    ack_timer_armed_ = false;
    retire_link();
    resume_timer_.start(ms(opts_.limits.resume_ms), [this, why] {
        if (state_ == state::kDetached && !closed_) {
            shutdown(make_error(why.code, std::format("{} (not resumed within {} ms)", why.message, opts_.limits.resume_ms), peer_));
        }
    });
    // Posted: the dialing side may dial (and call resume()) right away, outside this link's callback.
    post_guarded(io_, alive_, [this, why = std::move(why)] {
        if (state_ == state::kDetached) {
            handler_.on_detached(*this, why);
        }
    });
}

void session::retire_link() {
    if (link_ == nullptr) {
        return;
    }
    port_->owner = nullptr; // its last callbacks go nowhere
    link_->close();
    if (retired_.size() >= kMaxRetired) {
        retired_.erase(retired_.begin());
    }
    retired_.push_back(retired_link{std::move(port_), std::move(link_)});
}

void session::attach(std::unique_ptr<net::link> link, std::unique_ptr<link_port> port) {
    link_ = std::move(link);
    port_ = std::move(port);
    port_->owner = this;
    peer_ = link_->peer();
    decoder_ = wire::frame_decoder{opts_.limits.max_frame};
    heard_since_tick_ = true;
    misses_ = 0;
    nacked_at_ = 0;
}

// ---- decoding helpers ---------------------------------------------------------------------------------

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

result<void> session::write_frame(wire::op code, std::uint64_t seq, utils::bytes_view payload, bool sealed) {
    if (link_ == nullptr) {
        return {};
    }
    wire::frame_header header;
    header.code = code;
    header.seq = seq;
    header.ack = expected_ - 1;
    if (link_->encrypted()) {
        header.flags = header.flags | wire::frame_flag::kCrcOmitted;
    }
    utils::byte_buffer bytes;
    if (auto ok = wire::encode_frame(header, payload, bytes, sealed ? outgoing_.get() : nullptr, opts_.limits.max_frame); !ok) {
        return ok;
    }
    ack_sent_ = header.ack;
    link_->send(std::move(bytes));
    return {};
}

result<void> session::write_unsequenced(wire::op code, std::uint64_t seq, utils::bytes_view payload, bool sealed) {
    if (auto ok = wire::check_payload(code, payload.size(), opts_.limits.max_frame); !ok) {
        return ok;
    }
    if (state_ == state::kDetached) {
        return {};
    }
    return write_frame(code, seq, payload, sealed);
}

result<void> session::queue_sequenced(wire::op code, std::uint64_t seq, utils::byte_buffer&& payload) {
    if (auto ok = wire::check_payload(code, payload.size(), opts_.limits.max_frame); !ok) {
        return ok;
    }
    unacked_frame f;
    f.seq = seq;
    f.code = code;
    f.payload = std::move(payload);
    unacked_bytes_ += f.payload.size() + wire::kHeaderSize;
    unacked_.push_back(std::move(f));
    if (unacked_bytes_ > opts_.max_unacked_bytes) {
        fail_with(make_error(errc::kLimitExceeded, std::format("the peer left {} bytes unacknowledged", unacked_bytes_), peer_));
        return Rhp::fail(errc::kTransport, "session closed", peer_);
    }
    if (state_ == state::kDetached) {
        return {}; // goes out (from the resend window) once the session resumes
    }
    return write_frame(code, seq, unacked_.back().payload.view(), true);
}

result<void> session::write_value(wire::op code, const value& body, bool sealed) {
    utils::byte_buffer payload;
    if (auto encoded = opts_.codec.encode(body, payload); !encoded) {
        return encoded;
    }
    return write_unsequenced(code, 0, payload.view(), sealed);
}

result<void> session::send(wire::op code, const value& body) {
    if (!usable() || closed_) {
        return Rhp::fail(errc::kTransport, "the session is not ready", peer_);
    }
    if (!wire::is_sequenced(code)) {
        return Rhp::fail(errc::kInvalidArgument, std::format("{} is not a request or reply op", code), "session.send");
    }
    utils::byte_buffer payload;
    if (auto encoded = opts_.codec.encode(body, payload); !encoded) {
        return encoded;
    }
    if (auto ok = queue_sequenced(code, next_seq_, std::move(payload)); !ok) {
        return ok;
    }
    ++next_seq_;
    ++stats_.sent;
    return {};
}

void session::write_control(wire::op code) {
    const bool sealed = state_ == state::kReady;
    (void)write_unsequenced(code, sealed ? ++control_out_ : 0, utils::bytes_view{}, sealed);
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
        unacked_bytes_ -= unacked_.front().payload.size() + wire::kHeaderSize;
        unacked_.pop_front();
    }
}

void session::resend_after(std::uint64_t ack) {
    acknowledge(ack);
    if (state_ != state::kReady) {
        return;
    }
    for (const unacked_frame& f : unacked_) {
        if (f.seq > ack) {
            // Encoded again: the ack, and whether the link wants a CRC, may have changed.
            (void)write_frame(f.code, f.seq, f.payload.view(), true);
            ++stats_.resent;
        }
    }
}

void session::send_ack_if_due() {
    if (state_ != state::kReady || closed_ || expected_ - 1 == ack_sent_) {
        return;
    }
    constexpr std::uint64_t kAckEvery = 8; // frames received without telling the peer
    if (ack_now_ || opts_.ack_delay_ms == 0 || expected_ - 1 - ack_sent_ >= kAckEvery) {
        ack_now_ = false;
        write_control(wire::op::kAck);
        return;
    }
    // Every frame we send carries the ack: when the timer fires, there is usually nothing left to do.
    if (!ack_timer_armed_) {
        ack_timer_armed_ = true;
        ack_timer_.start(ms(opts_.ack_delay_ms), [this] {
            ack_timer_armed_ = false;
            if (state_ == state::kReady && !closed_ && expected_ - 1 != ack_sent_) {
                write_control(wire::op::kAck);
            }
        });
    }
}

void session::send_nack() {
    if (nacked_at_ == expected_) {
        return; // already asked for this gap; the heartbeat resend covers a lost nack
    }
    nacked_at_ = expected_;
    ++stats_.nacks_sent;
    write_control(wire::op::kNack);
}

void session::start_heartbeat() {
    if (opts_.limits.heartbeat_ms != 0) {
        heard_since_tick_ = true;
        misses_ = 0;
        heartbeat_timer_.start(ms(opts_.limits.heartbeat_ms), [this] { heartbeat(); });
    }
}

void session::heartbeat() {
    if (closed_ || state_ != state::kReady) {
        return;
    }
    if (heard_since_tick_) {
        misses_ = 0;
    } else if (++misses_ >= opts_.limits.heartbeat_misses && opts_.limits.heartbeat_misses != 0) {
        error dead = make_error(errc::kTimeout, std::format("no frame from the peer for {} heartbeats", misses_), peer_);
        if (opts_.resumable && opts_.limits.resume_ms != 0) {
            detach(std::move(dead)); // a half-open link: drop it and wait for a new one
        } else {
            fail_with(std::move(dead));
        }
        return;
    }
    heard_since_tick_ = false;
    // Nothing acked for a whole interval: the peer may have lost a frame or our nack answer.
    if (!unacked_.empty() && peer_acked_ == acked_at_last_tick_) {
        resend_after(peer_acked_);
    }
    acked_at_last_tick_ = peer_acked_;
    nacked_at_ = 0; // allow a fresh nack for a gap that is still open
    write_control(wire::op::kPing);
    if (!closed_) {
        heartbeat_timer_.start(ms(opts_.limits.heartbeat_ms), [this] { heartbeat(); });
    }
}

// ---- closing ------------------------------------------------------------------------------------------

void session::fail_with(error why) {
    if (closed_) {
        return;
    }
    if (state_ == state::kDetached) {
        lose_resume_link(std::move(why)); // garbage on a resume link: try another link
        return;
    }
    if (why.where.empty()) {
        why.where = peer_;
    }
    // Tell the peer (unsequenced kError), sealed once both sides have keys.
    (void)write_value(wire::op::kError, Rhp::to_value(why), state_ == state::kReady);
    shutdown(std::move(why));
}

void session::close(error why) {
    if (why.code == errc::kOk) {
        why = make_error(errc::kCancelled, "closed", peer_);
    }
    if (state_ == state::kDetached) {
        shutdown(std::move(why)); // nobody to tell
        return;
    }
    fail_with(std::move(why));
}

void session::shutdown(error why) {
    if (closed_) {
        return;
    }
    closed_ = true;
    state_ = state::kClosed;
    resuming_ = false;
    resume_pending_ = false;
    handshake_timer_.cancel();
    heartbeat_timer_.cancel();
    ack_timer_.cancel();
    ack_timer_armed_ = false;
    resume_timer_.cancel();
    if (link_ != nullptr) {
        link_->close(); // writes what is queued (the error frame), then closes
    }
    post_guarded(io_, alive_, [this, why = std::move(why)] { handler_.on_closed(*this, why); });
}

} // namespace Rhp::session
