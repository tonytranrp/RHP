// The host engine on its network thread: sessions (accept, reverse-mode dials, resume, requests,
// cancels, closes), the HTTP gateway's sink, and the replies pump() hands back.

#include <rhp/host/detail/engine_impl.hpp>

namespace Rhp::host_detail {

std::size_t approx_size(const value& v) noexcept {
    switch (v.type()) {
    case value::kind::kString: return v.get_if<std::string>()->size() + 8;
    case value::kind::kBytes: return v.get_if<value::bytes>()->size() + 8;
    case value::kind::kArray: {
        std::size_t n = 8;
        for (const value& item : *v.get_if<value::array>()) {
            n += approx_size(item);
        }
        return n;
    }
    case value::kind::kMap: {
        std::size_t n = 8;
        for (const auto& [k, item] : *v.get_if<value::map>()) {
            n += approx_size(k) + approx_size(item);
        }
        return n;
    }
    default: return 16;
    }
}

namespace {

[[nodiscard]] bool final_reply(wire::op code, std::uint64_t req) noexcept {
    return req != 0 && (code == wire::op::kResult || code == wire::op::kError);
}

} // namespace

void engine::start_gateway() {
    if (!setup_.options.gateway) {
        return;
    }
    const auto& ep = *setup_.options.gateway;
    if (ep.direction != net::endpoint::mode::kListen) {
        gateway_error_ = make_error(errc::kInvalidArgument, "the HTTP listener must listen", "host.gateway");
        return;
    }
    if (!setup_.http_auth) {
        gateway_error_ = make_error(errc::kDisabled, "the authenticator can't check HTTP proofs (Rhp::security::http_authenticator)", "host.gateway");
        return;
    }
    if (ep.insecure_lan && setup_.hardening != hardening::kDev) {
        gateway_error_ = make_error(errc::kForbidden, std::format("{}: insecure_lan is refused at hardening {}; use TLS", ep, setup_.hardening), "host.gateway");
        return;
    }
    if (setup_.hardening == hardening::kProduction && !setup_.options.http_require_binding) {
        gateway_error_ =
            make_error(errc::kForbidden, "at hardening production the HTTP gateway needs http_require_binding (proofs bound to the TLS channel)", "host.gateway");
        return;
    }
    auto policy = session::channel_policy::make(ep, true, setup_.tls, setup_.options.tls);
    if (!policy) {
        gateway_error_ = std::move(policy).error();
        return;
    }
    gateway_ = std::make_unique<http_gateway>(io_, setup_.limits, static_cast<gateway_sink&>(*this), admission_, setup_.options.http_require_binding);
    if (auto ok = gateway_->listen(std::move(*policy)); !ok) {
        gateway_error_ = std::move(ok).error();
        gateway_.reset();
        return;
    }
    gateway_port_ = gateway_->port();
}

std::chrono::steady_clock::time_point engine::steady_now() const noexcept {
    return std::chrono::steady_clock::now() + std::chrono::nanoseconds{clock_offset_ns_.load(std::memory_order_relaxed)};
}

void engine::sample_clock() noexcept {
    if (setup_.custom_clock && setup_.clock) {
        const auto offset = std::chrono::duration_cast<std::chrono::nanoseconds>(setup_.clock() - std::chrono::steady_clock::now());
        clock_offset_ns_.store(offset.count(), std::memory_order_relaxed);
    }
}

result<security::http_grant> engine::authorize(const security::http_proof& request) {
    return setup_.http_auth(request, std::chrono::system_clock::now());
}

session_id engine::open_http(const security::http_grant& grant, const http_peer& peer) {
    const session_id id = session_ids_.next();
    http_sessions_[id] = grant.identity;
    register_session(id, grant.identity, grant.granted, peer.address, "http", peer.tls);
    return id;
}

void engine::close_http(session_id id, std::string_view name, const error& why) {
    if (http_sessions_.erase(id) == 0) {
        return;
    }
    unregister_session(id, name, "http", why);
}

bool engine::submit_http(session_id id, std::uint64_t req, wire::op code, value body, const http_peer& peer) {
    inbound in;
    in.session = id;
    in.peer = peer.address; // a logical session has many callers: each request names its own
    in.req = req;
    in.arrival = req; // one logical session: request numbers are the arrival order
    in.code = code;
    in.body = std::move(body);
    return to_pump(std::move(in));
}

void engine::cancel_http(session_id id, std::uint64_t target, std::uint64_t upto) {
    const auto session = http_sessions_.find(id);
    if (session == http_sessions_.end()) {
        return;
    }
    if (const auto identity = io_identities_.find(session->second); identity != io_identities_.end()) {
        const std::scoped_lock lock{identity->second.relay->mutex};
        identity->second.relay->cancel(id, target, upto);
    }
}

void engine::accept(std::unique_ptr<net::link> link) {
    if (stopping_) {
        park(std::move(link));
        return;
    }
    if (!is_enabled()) {
        log(log_level::kInfo, "refusing {}: the host is disabled", link->peer());
        refused(link->peer(), make_error(errc::kDisabled, "the host is disabled", "host"), {});
        park(std::move(link));
        return;
    }
    const session_id id = session_ids_.next();
    auto ticket = admission_.admit(link, [this, id](const error& why) { drop_unauthenticated(id, why); });
    if (!ticket) {
        log(log_level::kWarn, "refusing {}: {}", link->peer(), ticket.error());
        refused(link->peer(), std::move(ticket).error(), {});
        park(std::move(link));
        return;
    }
    std::string peer = link->peer();
    auto wrapped = policy_.wrap(std::move(link));
    if (!wrapped) {
        admission_.release(*ticket);
        log(log_level::kWarn, "refusing {}: {}", peer, wrapped.error());
        refused(std::move(peer), std::move(wrapped).error(), {});
        return;
    }
    start_session(id, std::move(*wrapped), false, *ticket);
}

void engine::drop_unauthenticated(session_id id, const error& why) {
    if (const auto it = sessions_.find(id); it != sessions_.end()) {
        it->second.ticket = 0; // the admission has let go of it already
        it->second.s->close(why);
    }
}

void engine::refused(std::string peer, error why, std::string key) {
    if (setup_.events == nullptr || !setup_.events->wants(event::kind_of<event::auth_failed>)) {
        return;
    }
    inbound in;
    in.what = inbound::kind::kAuthFailed;
    in.identity = std::move(key);
    in.peer = std::move(peer);
    in.reason = std::move(why);
    (void)to_pump(std::move(in));
}

void engine::park(std::unique_ptr<net::link> link) {
    link->close();
    closing_links_.push_back(std::move(link));
    if (closing_links_.size() > 64) {
        closing_links_.pop_front();
    }
}

void engine::start_session(session_id id, std::unique_ptr<net::link> link, bool dialed, session::admission::ticket ticket) {
    auto handshake = setup_.begin_handshake();
    io_session rec;
    session::options opts = session_options_;
    opts.speaks_first = dialed;
    rec.s = std::make_unique<session::session>(io_, std::move(link), std::move(handshake), static_cast<session::handler&>(*this), std::move(opts), id);
    rec.ticket = ticket;
    session::session& s = *rec.s;
    sessions_.emplace(id, std::move(rec));
    open_sessions_.store(sessions_.size(), std::memory_order_release);
    s.start();
}

void engine::apply_enabled(bool on) {
    if (stopping_ || on == serving_) {
        return;
    }
    serving_ = on;
    if (on) {
        if (reverse_ && !outgoing_ && !dialing_) {
            redial_timer_.cancel();
            attempts_ = 0;
            dial_out();
        }
        return;
    }
    redial_timer_.cancel();
    const error why = make_error(errc::kDisabled, "the host was disabled", "host");
    for (auto& [id, rec] : sessions_) {
        rec.s->close(why); // on_closed follows (posted): identities revert as on any disconnect
    }
    if (gateway_) {
        gateway_->close_all(why);
    }
}

void engine::dial_out(session_id resume_id) {
    if (resume_id.value() == 0) {
        dialing_ = true;
    }
    setup_.transport.dial(io_, policy_.transport_endpoint(), [this, resume_id](result<std::unique_ptr<net::link>> dialed) {
        auto link = policy_.wrap(std::move(dialed));
        if (resume_id.value() != 0) {
            const auto it = sessions_.find(resume_id);
            if (it == sessions_.end() || it->second.s->current() != session::state::kDetached) {
                return; // resumed or gone meanwhile (a disabled host closed it); a link we got is dropped
            }
            if (!link) {
                log(log_level::kDebug, "dialing {} to resume session {} failed: {}", setup_.ep, resume_id, link.error());
                redial(resume_id);
                return;
            }
            it->second.s->resume(std::move(*link));
            return;
        }
        dialing_ = false;
        if (stopping_ || !is_enabled()) {
            if (link) {
                park(std::move(*link)); // set_enabled(true) dials again
            }
            return;
        }
        if (!link) {
            log(log_level::kDebug, "dialing {} failed: {}", setup_.ep, link.error());
            redial();
            return;
        }
        outgoing_ = session_ids_.next();
        start_session(outgoing_, std::move(*link), true, 0);
    });
}

void engine::redial(session_id resume_id) {
    const auto delay = session::backoff_delay(setup_.limits, attempts_, rng_, false);
    ++attempts_;
    redial_timer_.start(delay, [this, resume_id] { dial_out(resume_id); });
}

void engine::on_detached(session::session& s, const error& why) {
    log(log_level::kInfo, "session {} ({}) lost its link ({}); it may resume within {} ms", s.id(), s.identity(), why, setup_.limits.resume_ms);
    if (reverse_ && s.id() == outgoing_ && !stopping_ && is_enabled()) {
        attempts_ = 0;
        redial(s.id());
    }
}

void engine::on_resumed(session::session& s) {
    if (s.id() == outgoing_) {
        attempts_ = 0;
    }
    log(log_level::kInfo, "session {} ({}) resumed from {}{}", s.id(), s.identity(), s.peer(), s.encrypted() ? " over TLS" : "");
    if (setup_.events != nullptr && setup_.events->wants(event::kind_of<event::session_resumed>)) {
        inbound in;
        in.what = inbound::kind::kResumed;
        in.session = s.id();
        in.identity = s.identity();
        in.peer = s.peer();
        in.tls = s.encrypted();
        (void)to_pump(std::move(in));
    }
}

session::session* engine::resume_target(session::session& fresh, session_id id) {
    if (!is_enabled() || reverse_) {
        return nullptr;
    }
    const auto it = sessions_.find(id);
    if (it == sessions_.end() || !it->second.ready || it->second.s.get() == &fresh) {
        return nullptr;
    }
    return it->second.s.get();
}

void engine::on_ready(session::session& s) {
    auto it = sessions_.find(s.id());
    if (it == sessions_.end()) {
        return;
    }
    admission_.release(std::exchange(it->second.ticket, 0));
    if (s.id() == outgoing_) {
        attempts_ = 0;
    }
    it->second.ready = true;
    it->second.identity = s.identity();
    log(log_level::kInfo, "session {} from {} ({}) authenticated as {} ({})", s.id(), s.peer(), s.peer_platform(), s.identity(), s.granted());
    register_session(s.id(), s.identity(), s.granted(), s.peer(), s.peer_platform(), s.encrypted());
}

void engine::on_message(session::session& s, wire::op code, value body) {
    auto it = sessions_.find(s.id());
    if (it == sessions_.end()) {
        return;
    }
    io_session& rec = it->second;
    if (!wire::is_request(code)) {
        s.close(make_error(errc::kProtocol, std::format("a client may not send {}", code), "host"));
        return;
    }
    auto env = wire::take_envelope(std::move(body));
    if (!env) {
        s.close(std::move(env).error());
        return;
    }
    const std::uint64_t arrival = ++rec.arrivals;
    if (code == wire::op::kCancel) {
        // Applied here, through the relay: never queued for pump() (which may be stuck in the
        // very script it stops) and never answered, so its idempotency key is ignored.
        cancel_from_network(s, env->body, arrival);
        return;
    }
    if (env->idem != 0 && env->req != 0) {
        if (rec.req_idem.contains(env->req)) {
            s.close(make_error(errc::kProtocol, std::format("request id {} is already in flight", env->req), "host"));
            return;
        }
        if (const auto found = rec.idem.find(env->idem); found != rec.idem.end()) {
            idem_entry& entry = found->second;
            if (entry.done) {
                // A retry of something already answered: answer again, don't run it again.
                (void)send_reply(rec, entry.code, env->req, entry.body);
            } else {
                entry.reqs.push_back(env->req);
                rec.req_idem[env->req] = env->idem;
            }
            return;
        }
        if (rec.req_idem.size() >= kMaxInFlight) {
            s.close(make_error(errc::kLimitExceeded, std::format("more than {} requests in flight", kMaxInFlight), "host"));
            return;
        }
        rec.idem[env->idem].reqs.push_back(env->req);
        rec.req_idem[env->req] = env->idem;
    }
    inbound in;
    in.what = inbound::kind::kRequest;
    in.session = s.id();
    in.code = code;
    in.req = env->req;
    in.arrival = arrival;
    in.body = std::move(env->body);
    if (setup_.verify && (code == wire::op::kExec || code == wire::op::kLoad || code == wire::op::kReload)) {
        // The pump decodes the same body: same source, same signature.
        const value* source = in.body.find("source");
        if (const std::string* text = source != nullptr ? source->get_if<std::string>() : nullptr) {
            const value* signature = in.body.find("signature");
            in.signer = setup_.verify(*text, signature != nullptr ? *signature : value{});
        }
    }
    if (!to_pump(std::move(in))) {
        s.close(make_error(errc::kLimitExceeded, "the host is not keeping up with this session's requests", "host"));
    }
}

void engine::on_closed(session::session& s, const error& why) {
    const session_id id = s.id();
    auto it = sessions_.find(id);
    if (it == sessions_.end()) {
        return;
    }
    const bool was_ready = it->second.ready;
    const std::string identity = it->second.identity;
    admission_.release(it->second.ticket);
    if (was_ready) {
        log(log_level::kInfo, "session {} ({}) ended: {}", id, identity, why);
        unregister_session(id, identity, s.peer(), why);
    } else if (!s.handed_over()) { // (a connection that only carried a resume: its link went to that session)
        log(log_level::kInfo, "connection from {} closed before authenticating: {}", s.peer(), why);
        refused(s.peer(), why, s.offered_key());
    }
    sessions_.erase(it); // allowed inside on_closed
    open_sessions_.store(sessions_.size(), std::memory_order_release);
    if (reverse_ && id == outgoing_) {
        outgoing_ = {};
        if (!stopping_ && is_enabled()) {
            redial();
        }
    }
}

void engine::register_session(session_id id, const std::string& identity, role granted, std::string peer, std::string platform, bool tls) {
    io_identity& ident = io_identities_[identity];
    if (ident.relay == nullptr) {
        ident.relay = std::make_shared<cancel_relay>();
    }
    ++ident.sessions;
    ready_sessions_.fetch_add(1, std::memory_order_acq_rel);
    inbound in;
    in.what = inbound::kind::kOpened;
    in.session = id;
    in.identity = identity;
    in.granted = granted;
    in.relay = ident.relay;
    in.peer = std::move(peer);
    in.platform = std::move(platform);
    in.tls = tls;
    (void)to_pump(std::move(in));
}

void engine::unregister_session(session_id id, std::string_view identity, std::string peer, const error& why) {
    ready_sessions_.fetch_sub(1, std::memory_order_acq_rel);
    if (auto ident = io_identities_.find(identity); ident != io_identities_.end()) {
        {
            const std::scoped_lock lock{ident->second.relay->mutex};
            ident->second.relay->end(id);
        }
        if (--ident->second.sessions == 0) {
            // The identity's last session; pump() reverts the rest. Its relay stays on the
            // enforce timer until pump() has let go of the sandbox.
            orphans_.push_back(ident->second.relay);
            io_identities_.erase(ident);
        }
        arm_enforce();
    }
    inbound in;
    in.what = inbound::kind::kClosed;
    in.session = id;
    in.identity = std::string{identity};
    in.peer = std::move(peer);
    in.reason = why;
    (void)to_pump(std::move(in));
}

void engine::cancel_from_network(session::session& s, const value& body, std::uint64_t arrival) {
    auto request = Rhp::from_value<wire::cancel_request>(body);
    if (!request) {
        return;
    }
    const auto ident = io_identities_.find(s.identity());
    if (ident == io_identities_.end()) {
        return;
    }
    {
        const std::scoped_lock lock{ident->second.relay->mutex};
        ident->second.relay->cancel(s.id(), request->target, arrival);
    }
    arm_enforce();
}

void engine::enforce_cancels() {
    enforce_armed_ = false;
    bool recorded = false;
    for (auto& [name, ident] : io_identities_) {
        const std::scoped_lock lock{ident.relay->mutex};
        ident.relay->enforce(false);
        recorded = recorded || !ident.relay->cancels.empty();
    }
    std::erase_if(orphans_, [](const std::shared_ptr<cancel_relay>& relay) {
        const std::scoped_lock lock{relay->mutex};
        relay->enforce(false);
        return relay->box == nullptr;
    });
    if (recorded || !orphans_.empty()) {
        arm_enforce();
    }
}

void engine::arm_enforce() {
    if (!enforce_armed_) {
        enforce_armed_ = true;
        enforce_timer_.start(kEnforceInterval, [this] { enforce_cancels(); });
    }
}

bool engine::to_pump(inbound in) {
    if (inbox_backlog_.empty() && inbox_.try_push(std::move(in))) {
        return true;
    }
    if (inbox_backlog_.size() >= kMaxBacklog && (in.what == inbound::kind::kRequest || in.what == inbound::kind::kAuthFailed)) {
        return false;
    }
    inbox_backlog_.push_back(std::move(in));
    inbox_backlog_waiting_.store(true, std::memory_order_release);
    flush_inbox_backlog();
    return true;
}

void engine::flush_inbox_backlog() {
    while (!inbox_backlog_.empty()) {
        if (!inbox_.try_push(std::move(inbox_backlog_.front()))) {
            return;
        }
        inbox_backlog_.pop_front();
        inbox_backlog_waiting_.store(!inbox_backlog_.empty(), std::memory_order_release);
    }
}

void engine::drain_outbox() {
    flush_inbox_backlog();
    while (auto item = outbox_.try_pop()) {
        if (http_sessions_.contains(item->session)) {
            gateway_->reply(item->session, item->code, item->req, item->body);
            continue;
        }
        const auto it = sessions_.find(item->session);
        if (it == sessions_.end() || !it->second.ready) {
            continue;
        }
        io_session& rec = it->second;
        if (final_reply(item->code, item->req)) {
            if (const auto key = rec.req_idem.find(item->req); key != rec.req_idem.end()) {
                const std::uint64_t idem = key->second;
                idem_entry& entry = rec.idem[idem];
                entry.done = true;
                entry.code = item->code;
                entry.body = std::move(item->body);
                for (const std::uint64_t req : entry.reqs) {
                    rec.req_idem.erase(req);
                    (void)send_reply(rec, entry.code, req, entry.body);
                }
                entry.reqs.clear();
                // Keep the answer for retries, within the cache's entry and byte budgets. A reply
                // too big to keep is remembered as such: a retry is refused, never run twice.
                entry.bytes = approx_size(entry.body);
                if (entry.bytes > setup_.options.idempotency_bytes) {
                    entry.code = wire::op::kError;
                    entry.body = Rhp::to_value(make_error(errc::kLimitExceeded, "the reply to this request was too large to keep for a retry", "host"));
                    entry.bytes = approx_size(entry.body);
                }
                rec.idem_bytes += entry.bytes;
                rec.idem_done.push_back(idem);
                while (!rec.idem_done.empty() &&
                       (rec.idem_done.size() > setup_.options.idempotency_cache || rec.idem_bytes > setup_.options.idempotency_bytes)) {
                    if (const auto old = rec.idem.find(rec.idem_done.front()); old != rec.idem.end()) {
                        rec.idem_bytes -= old->second.bytes;
                        rec.idem.erase(old);
                    }
                    rec.idem_done.pop_front();
                }
                continue;
            }
        }
        (void)send_reply(rec, item->code, item->req, item->body);
    }
}

bool engine::send_reply(io_session& rec, wire::op code, std::uint64_t req, const value& body) {
    auto sent = rec.s->send(code, wire::envelope_value(req, 0, body));
    if (!sent && sent.error().code == errc::kLimitExceeded && final_reply(code, req)) {
        // Too big for one frame: the request still gets an answer.
        (void)rec.s->send(wire::op::kError, wire::envelope_value(req, 0, Rhp::to_value(sent.error())));
    }
    return sent.has_value();
}

} // namespace Rhp::host_detail
