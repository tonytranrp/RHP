#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/session/session.hpp>
#include <rhp/utils/spsc_ring.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::host_detail {

namespace {

// Shared by the network thread and the pump thread for one identity: the only way the network
// reaches a sandbox (cancel, which is thread-safe on the sandbox). `box` is cleared, under the
// mutex, before the sandbox is destroyed.
struct cancel_relay {
    std::mutex mutex;
    script::sandbox* box = nullptr;
    session_id running_session; // the network request inside a sandbox call right now
    std::uint64_t running_req = 0;
    std::map<std::pair<std::uint64_t, std::uint64_t>, request_id> suspended; // (session, req) → sandbox request

    // Under the mutex. target 0 = everything of `session`.
    void cancel(session_id session, std::uint64_t target) noexcept {
        if (box == nullptr) {
            return;
        }
        if (running_session == session && (target == 0 || running_req == target)) {
            box->cancel();
        }
        for (const auto& [key, id] : suspended) {
            if (key.first == session.value() && (target == 0 || key.second == target)) {
                box->cancel(id);
            }
        }
    }

    void cancel_all() noexcept {
        if (box == nullptr) {
            return;
        }
        box->cancel();
        for (const auto& [key, id] : suspended) {
            box->cancel(id);
        }
    }
};

// Network thread → pump thread.
struct inbound {
    enum class kind : std::uint8_t {
        kOpened,
        kRequest,
        kClosed
    };

    kind what = kind::kRequest;
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::shared_ptr<cancel_relay> relay;
    wire::op code = wire::op::kExec;
    std::uint64_t req = 0;
    value body;
    bool cancelled = false; // a later cancel in the same batch covers it
};

// Pump thread → network thread.
struct outbound {
    session_id session;
    wire::op code = wire::op::kResult;
    std::uint64_t req = 0;
    value body;
};

[[nodiscard]] bool final_reply(wire::op code, std::uint64_t req) noexcept {
    return req != 0 && (code == wire::op::kResult || code == wire::op::kError);
}

[[nodiscard]] wire::revert_summary summarize(const script::revert_report& r) {
    return {r.undone, r.irreversible, r.failures, r.deferred};
}

[[nodiscard]] wire::module_status describe(const script::module_info& m) {
    wire::module_status s;
    s.id = m.id;
    s.name = m.name;
    s.state = std::string{script::to_string(m.state)};
    s.scratch = m.scratch;
    s.effects = m.effects;
    s.irreversible_effects = m.irreversible_effects;
    s.revision = m.revision;
    s.source_hash = m.source_hash;
    s.revisions = m.revisions;
    s.reloading = m.reloading;
    s.dependencies = m.dependencies;
    s.fault = m.fault;
    return s;
}

} // namespace

class engine final : private session::handler {
public:
    explicit engine(setup s)
        : setup_(std::move(s)),
          inbox_(setup_.options.inbox_capacity),
          outbox_(setup_.options.inbox_capacity) {
        session_options_.limits = setup_.limits;
        session_options_.codec = setup_.codec;
        session_options_.platform = std::string{platform::kOsName};
        if (setup_.ep.direction != net::endpoint::mode::kListen) {
            listen_error_ = make_error(errc::kInvalidArgument, "a Stage 3 host listens; reverse mode (a host that dials) arrives in Stage 4", "host");
            return;
        }
        auto listener = setup_.transport.listen(io_, setup_.ep, [this](std::unique_ptr<net::link> link) { accept(std::move(link)); });
        if (!listener) {
            listen_error_ = std::move(listener).error();
            log(log_level::kError, std::format("host can't listen ({}): {}", setup_.ep, *listen_error_));
            return;
        }
        listener_ = std::move(*listener);
        log(log_level::kInfo, std::format("host listening on {} over {} (port {})", setup_.ep, setup_.transport.name, listener_->port()));
    }

    // The network is stopped (or never ran on another thread) when this runs.
    ~engine() {
        listener_.reset();
        sessions_.clear(); // aborts the links: no callbacks after this
        for (auto& [name, id] : identities_) {
            teardown(id);
        }
        identities_.clear();
    }

    engine(const engine&) = delete;
    engine& operator=(const engine&) = delete;

    [[nodiscard]] result<void> listening() const {
        if (listen_error_) {
            return fail(*listen_error_);
        }
        return {};
    }

    [[nodiscard]] std::uint16_t port() const noexcept { return listener_ != nullptr ? static_cast<std::uint16_t>(listener_->port()) : std::uint16_t{0}; }
    [[nodiscard]] std::size_t ready_sessions() const noexcept { return ready_sessions_.load(std::memory_order_acquire); }
    [[nodiscard]] std::size_t identity_count() const noexcept { return identity_count_.load(std::memory_order_acquire); }

    result<void> install(std::string_view name, installer fn) {
        for (const auto& [n, f] : installers_) {
            if (n == name) {
                return fail(errc::kAlreadyLoaded, std::format("a lib named '{}' is already installed", name), "host.install");
            }
        }
        installers_.emplace_back(std::string{name}, fn);
        for (auto& [identity, id] : identities_) {
            if (auto ok = fn(*id.box); !ok) {
                log(log_level::kWarn, std::format("install {} into identity {}: {}", name, identity, ok.error()));
            }
        }
        return {};
    }

    void run_io(std::stop_token stop) { io_.run(std::move(stop)); }

    // ---- pump thread ---------------------------------------------------------------------------------

    void pump() {
        if (!setup_.io_thread) {
            io_.poll();
        }
        std::vector<inbound> batch;
        while (auto item = inbox_.try_pop()) {
            batch.push_back(std::move(*item));
        }
        process(batch);
        for (auto& [name, id] : identities_) {
            id.box->pump();
        }
        flush_outbox();
        if (!setup_.io_thread) {
            io_.poll();
        }
    }

private:
    struct pending_reply {
        session_id session;
        std::uint64_t req = 0;
        wire::op code = wire::op::kExec;
        module_id module;
    };

    struct identity_runtime {
        std::string name;
        role granted = role::kObserve;
        std::unique_ptr<script::sandbox> box;
        std::shared_ptr<cancel_relay> relay;
        std::set<session_id> sessions;
        std::map<request_id, pending_reply> waiting; // suspended network requests
        session_id current_session;                  // the network request inside a sandbox call
        std::uint64_t current_req = 0;
    };

    struct pump_session {
        std::string identity;
        role granted = role::kObserve;
    };

    // ---- network thread: sessions ----------------------------------------------------------------------

    struct idem_entry {
        bool done = false;
        std::vector<std::uint64_t> reqs; // requests waiting for this result (retries included)
        wire::op code = wire::op::kResult;
        value body;
    };

    struct io_session {
        std::unique_ptr<session::session> s;
        bool ready = false;
        std::string identity;
        std::map<std::uint64_t, std::uint64_t> req_idem; // in-flight req → idempotency key
        std::map<std::uint64_t, idem_entry> idem;
        std::deque<std::uint64_t> idem_done; // completed keys, oldest first (evicted past the cache size)
    };

    struct io_identity {
        std::size_t sessions = 0;
        std::shared_ptr<cancel_relay> relay;
    };

    void accept(std::unique_ptr<net::link> link) {
        if (pending_handshakes_ >= setup_.limits.pending_handshakes) {
            log(log_level::kWarn, std::format("refusing {}: {} handshakes already pending", link->peer(), pending_handshakes_));
            link->close();
            closing_links_.push_back(std::move(link)); // dies once the next connection arrives or the host does
            if (closing_links_.size() > 64) {
                closing_links_.pop_front();
            }
            return;
        }
        const session_id id = session_ids_.next();
        auto handshake = setup_.begin_handshake();
        io_session rec;
        rec.s = std::make_unique<session::session>(io_, std::move(link), std::move(handshake), static_cast<session::handler&>(*this), session_options_, id);
        session::session& s = *rec.s;
        sessions_.emplace(id, std::move(rec));
        ++pending_handshakes_;
        s.start();
    }

    void on_ready(session::session& s) override {
        --pending_handshakes_;
        auto it = sessions_.find(s.id());
        if (it == sessions_.end()) {
            return;
        }
        it->second.ready = true;
        it->second.identity = s.identity();
        io_identity& ident = io_identities_[s.identity()];
        if (ident.relay == nullptr) {
            ident.relay = std::make_shared<cancel_relay>();
        }
        ++ident.sessions;
        ready_sessions_.fetch_add(1, std::memory_order_acq_rel);
        log(log_level::kInfo, std::format("session {} from {} ({}) authenticated as {} ({})", s.id(), s.peer(), s.peer_platform(), s.identity(), s.granted()));
        inbound in;
        in.what = inbound::kind::kOpened;
        in.session = s.id();
        in.identity = s.identity();
        in.granted = s.granted();
        in.relay = ident.relay;
        to_pump(std::move(in));
    }

    void on_message(session::session& s, wire::op code, value body) override {
        auto it = sessions_.find(s.id());
        if (it == sessions_.end()) {
            return;
        }
        io_session& rec = it->second;
        if (!wire::is_request(code)) {
            s.close(make_error(errc::kProtocol, std::format("a client may not send {}", code), "host"));
            return;
        }
        auto env = Rhp::from_value<wire::envelope>(body);
        if (!env) {
            s.close(std::move(env).error());
            return;
        }
        if (code == wire::op::kCancel) {
            cancel_from_network(s, env->body);
        }
        if (env->idem != 0 && env->req != 0) {
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
            rec.idem[env->idem].reqs.push_back(env->req);
            rec.req_idem[env->req] = env->idem;
        }
        inbound in;
        in.what = inbound::kind::kRequest;
        in.session = s.id();
        in.code = code;
        in.req = env->req;
        in.body = std::move(env->body);
        to_pump(std::move(in));
    }

    void on_closed(session::session& s, const error& why) override {
        const session_id id = s.id();
        auto it = sessions_.find(id);
        if (it == sessions_.end()) {
            return;
        }
        const bool was_ready = it->second.ready;
        const std::string identity = it->second.identity;
        if (was_ready) {
            log(log_level::kInfo, std::format("session {} ({}) ended: {}", id, identity, why));
            ready_sessions_.fetch_sub(1, std::memory_order_acq_rel);
            if (auto ident = io_identities_.find(identity); ident != io_identities_.end() && --ident->second.sessions == 0) {
                // The identity's last session: stop whatever it runs now; pump() reverts the rest.
                {
                    const std::scoped_lock lock{ident->second.relay->mutex};
                    ident->second.relay->cancel_all();
                }
                io_identities_.erase(ident);
            }
            inbound in;
            in.what = inbound::kind::kClosed;
            in.session = id;
            in.identity = identity;
            to_pump(std::move(in));
        } else {
            --pending_handshakes_;
            log(log_level::kInfo, std::format("connection from {} closed before authenticating: {}", s.peer(), why));
        }
        sessions_.erase(it); // allowed inside on_closed
    }

    void cancel_from_network(session::session& s, const value& body) {
        auto request = Rhp::from_value<wire::cancel_request>(body);
        if (!request) {
            return;
        }
        const auto ident = io_identities_.find(s.identity());
        if (ident == io_identities_.end()) {
            return;
        }
        const std::scoped_lock lock{ident->second.relay->mutex};
        ident->second.relay->cancel(s.id(), request->target);
    }

    void to_pump(inbound in) {
        if (inbox_backlog_.empty() && inbox_.try_push(std::move(in))) {
            return;
        }
        inbox_backlog_.push_back(std::move(in));
        flush_inbox_backlog();
    }

    void flush_inbox_backlog() {
        while (!inbox_backlog_.empty()) {
            if (!inbox_.try_push(std::move(inbox_backlog_.front()))) {
                return;
            }
            inbox_backlog_.pop_front();
        }
    }

    // The pump's replies, on the network thread.
    void drain_outbox() {
        flush_inbox_backlog();
        while (auto item = outbox_.try_pop()) {
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
                    rec.idem_done.push_back(idem);
                    while (rec.idem_done.size() > setup_.options.idempotency_cache) {
                        rec.idem.erase(rec.idem_done.front());
                        rec.idem_done.pop_front();
                    }
                    continue;
                }
            }
            (void)send_reply(rec, item->code, item->req, item->body);
        }
    }

    bool send_reply(io_session& rec, wire::op code, std::uint64_t req, const value& body) {
        auto sent = rec.s->send(code, Rhp::to_value(wire::envelope{req, 0, body}));
        if (!sent && sent.error().code == errc::kLimitExceeded && final_reply(code, req)) {
            // Too big for one frame: the request still gets an answer.
            (void)rec.s->send(wire::op::kError, Rhp::to_value(wire::envelope{req, 0, Rhp::to_value(sent.error())}));
        }
        return sent.has_value();
    }

    // ---- pump thread: requests ---------------------------------------------------------------------------

    void process(std::vector<inbound>& batch) {
        // A cancel stops requests of its session that were queued before it and haven't started:
        // walk back from each cancel (requests sent after it are left alone).
        std::set<std::pair<std::uint64_t, std::uint64_t>> targets;
        std::set<std::uint64_t> whole_sessions;
        for (auto it = batch.rbegin(); it != batch.rend(); ++it) {
            if (it->what != inbound::kind::kRequest) {
                continue;
            }
            if (it->code == wire::op::kCancel) {
                if (auto c = Rhp::from_value<wire::cancel_request>(it->body)) {
                    if (c->target == 0) {
                        whole_sessions.insert(it->session.value());
                    } else {
                        targets.emplace(it->session.value(), c->target);
                    }
                }
                continue;
            }
            it->cancelled = whole_sessions.contains(it->session.value()) || targets.contains({it->session.value(), it->req});
        }
        for (inbound& in : batch) {
            switch (in.what) {
            case inbound::kind::kOpened: opened(in); break;
            case inbound::kind::kClosed: closed(in); break;
            case inbound::kind::kRequest:
                if (in.cancelled) {
                    reply_error(in.session, in.req, make_error(errc::kCancelled, "cancelled before it started", std::string{wire::to_string(in.code)}));
                    break;
                }
                request(in);
                break;
            }
        }
    }

    void opened(inbound& in) {
        pump_sessions_[in.session] = pump_session{in.identity, in.granted};
        auto it = identities_.find(in.identity);
        if (it == identities_.end()) {
            identity_runtime rt;
            rt.name = in.identity;
            rt.granted = in.granted;
            rt.relay = in.relay;
            rt.box = std::make_unique<script::sandbox>(sandbox_options_for(in.identity, in.granted));
            for (const auto& [name, fn] : installers_) {
                if (auto ok = fn(*rt.box); !ok) {
                    log(log_level::kWarn, std::format("install {} into identity {}: {}", name, in.identity, ok.error()));
                }
            }
            {
                const std::scoped_lock lock{rt.relay->mutex};
                rt.relay->box = rt.box.get();
            }
            it = identities_.emplace(in.identity, std::move(rt)).first;
            identity_count_.store(identities_.size(), std::memory_order_release);
            log(log_level::kInfo, std::format("identity {} ({}) has a sandbox", in.identity, in.granted));
        }
        it->second.sessions.insert(in.session);
    }

    void closed(const inbound& in) {
        pump_sessions_.erase(in.session);
        const auto it = identities_.find(in.identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        rt.sessions.erase(in.session);
        std::erase_if(rt.waiting, [&](const auto& entry) { return entry.second.session == in.session; });
        {
            const std::scoped_lock lock{rt.relay->mutex};
            std::erase_if(rt.relay->suspended, [&](const auto& entry) { return entry.first.first == in.session.value(); });
        }
        if (rt.sessions.empty()) {
            teardown(rt);
            identities_.erase(it);
            identity_count_.store(identities_.size(), std::memory_order_release);
        }
    }

    // Disconnect = revert: the identity's last session is gone.
    void teardown(identity_runtime& rt) {
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->box = nullptr;
            rt.relay->suspended.clear();
        }
        const script::revert_report report = rt.box->revert_all();
        rt.box.reset();
        log(log_level::kInfo, std::format("identity {} reverted: {} effects undone, {} irreversible, {} failures", rt.name, report.undone, report.irreversible,
                                          report.failures.size()));
    }

    script::sandbox_options sandbox_options_for(const std::string& identity, role granted) {
        script::sandbox_options o;
        o.caller_role = granted;
        o.limits = setup_.limits;
        o.identity = identity;
        o.clock = setup_.clock;
        o.on_output = [this, identity](request_id r, module_id, std::string_view line) {
            log(log_level::kDebug, std::format("[{}] {}", identity, line));
            route(identity, r, wire::op::kOutput, value{line});
        };
        o.on_emit = [this, identity](request_id r, module_id mod, const value& v) {
            route(identity, r, wire::op::kEmit, Rhp::to_value(wire::emit_message{mod, v}));
        };
        o.on_result = [this, identity](request_id r, const result<script::value_list>& res) { finished(identity, r, res); };
        return o;
    }

    // print / emit: to the request that caused it, else to every session of the identity.
    void route(const std::string& identity, request_id r, wire::op code, value body) {
        const auto it = identities_.find(identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        if (rt.current_session) {
            to_network({rt.current_session, code, rt.current_req, std::move(body)});
            return;
        }
        if (const auto w = rt.waiting.find(r); w != rt.waiting.end()) {
            to_network({w->second.session, code, w->second.req, std::move(body)});
            return;
        }
        for (const session_id s : rt.sessions) {
            to_network({s, code, 0, body});
        }
    }

    // A suspended network request finished (sandbox on_result).
    void finished(const std::string& identity, request_id r, const result<script::value_list>& res) {
        const auto it = identities_.find(identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        const auto w = rt.waiting.find(r);
        if (w == rt.waiting.end()) {
            return; // a timer or event request, or its session is gone
        }
        const pending_reply p = w->second;
        rt.waiting.erase(w);
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->suspended.erase({p.session.value(), p.req});
        }
        if (!res) {
            reply_error(p.session, p.req, res.error());
            return;
        }
        switch (p.code) {
        case wire::op::kLoad: reply(p.session, p.req, Rhp::to_value(p.module)); return;
        case wire::op::kReload:
        case wire::op::kRollback: {
            const auto info = rt.box->status(p.module);
            reply(p.session, p.req, Rhp::to_value(info ? info->revision : revision_id{}));
            return;
        }
        default: reply(p.session, p.req, value{value::array(res->begin(), res->end())}); return;
        }
    }

    void reply(session_id s, std::uint64_t req, value body) { to_network({s, wire::op::kResult, req, std::move(body)}); }

    void reply_error(session_id s, std::uint64_t req, const error& err) { to_network({s, wire::op::kError, req, Rhp::to_value(err)}); }

    void to_network(outbound out) { outbox_backlog_.push_back(std::move(out)); }

    void flush_outbox() {
        bool pushed = false;
        while (!outbox_backlog_.empty()) {
            if (!outbox_.try_push(std::move(outbox_backlog_.front()))) {
                break;
            }
            outbox_backlog_.pop_front();
            pushed = true;
        }
        if (pushed || !outbox_backlog_.empty()) {
            io_.post([this] { drain_outbox(); });
        } else {
            io_.post([this] { flush_inbox_backlog(); });
        }
    }

    [[nodiscard]] result<module_id> resolve(script::sandbox& box, const wire::module_ref& ref) {
        if (ref.id) {
            return ref.id;
        }
        return box.find(ref.name);
    }

    // Runs one sandbox operation as network request (session, req); a request that suspends is
    // answered from on_result later.
    template <class Op>
    void run_tracked(identity_runtime& rt, const inbound& in, module_id module, Op&& op) {
        const request_id before = rt.box->last_request();
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->running_session = in.session;
            rt.relay->running_req = in.req;
        }
        rt.current_session = in.session;
        rt.current_req = in.req;
        auto outcome = op();
        rt.current_session = {};
        rt.current_req = 0;
        const request_id after = rt.box->last_request();
        const bool suspended = outcome && after != before && rt.box->pending(after);
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->running_session = {};
            rt.relay->running_req = 0;
            if (suspended) {
                rt.relay->suspended[{in.session.value(), in.req}] = after;
            }
        }
        if (suspended) {
            rt.waiting[after] = pending_reply{in.session, in.req, in.code, module};
            return;
        }
        if (!outcome) {
            reply_error(in.session, in.req, outcome.error());
            return;
        }
        reply(in.session, in.req, std::move(*outcome));
    }

    void request(const inbound& in) {
        const auto ps = pump_sessions_.find(in.session);
        if (ps == pump_sessions_.end()) {
            return; // the session ended before its request ran
        }
        const auto need = wire::required_role(in.code);
        if (!need) {
            reply_error(in.session, in.req, make_error(errc::kProtocol, std::format("{} is not a request", in.code), "host"));
            return;
        }
        if (!allows(ps->second.granted, *need)) {
            reply_error(in.session, in.req,
                        make_error(errc::kForbidden, std::format("{} needs role {}, {} has {}", in.code, *need, ps->second.identity, ps->second.granted),
                                   std::string{wire::to_string(in.code)}));
            return;
        }
        const auto it = identities_.find(ps->second.identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        script::sandbox& box = *rt.box;

        const auto bad_request = [&](const error& err) { reply_error(in.session, in.req, err); };

        switch (in.code) {
        case wire::op::kExec: {
            auto m = Rhp::from_value<wire::exec_request>(in.body);
            if (!m) {
                return bad_request(m.error());
            }
            run_tracked(rt, in, {}, [&]() -> result<value> {
                auto r = box.exec(m->source, m->chunk);
                if (!r) {
                    return std::unexpected{std::move(r).error()};
                }
                return value{value::array(r->begin(), r->end())};
            });
            return;
        }
        case wire::op::kLoad: {
            auto m = Rhp::from_value<wire::load_request>(in.body);
            if (!m) {
                return bad_request(m.error());
            }
            // The module id is only known once load() returns: track it through `loaded`.
            module_id loaded;
            const request_id before = box.last_request();
            run_tracked(rt, in, {}, [&]() -> result<value> {
                auto r = box.load(m->name, m->source);
                if (!r) {
                    return std::unexpected{std::move(r).error()};
                }
                loaded = *r;
                return Rhp::to_value(*r);
            });
            if (const request_id after = box.last_request(); after != before) {
                if (const auto w = rt.waiting.find(after); w != rt.waiting.end()) {
                    w->second.module = loaded;
                }
            }
            return;
        }
        case wire::op::kCall: {
            auto m = Rhp::from_value<wire::call_request>(in.body);
            if (!m) {
                return bad_request(m.error());
            }
            auto mod = resolve(box, m->module);
            if (!mod) {
                return bad_request(mod.error());
            }
            run_tracked(rt, in, *mod, [&]() -> result<value> {
                auto r = box.call(*mod, m->function, m->args);
                if (!r) {
                    return std::unexpected{std::move(r).error()};
                }
                return value{value::array(r->begin(), r->end())};
            });
            return;
        }
        case wire::op::kReload:
        case wire::op::kRollback: {
            module_id target;
            std::optional<wire::reload_request> reload;
            std::optional<wire::rollback_request> rollback;
            if (in.code == wire::op::kReload) {
                auto m = Rhp::from_value<wire::reload_request>(in.body);
                if (!m) {
                    return bad_request(m.error());
                }
                reload = std::move(*m);
            } else {
                auto m = Rhp::from_value<wire::rollback_request>(in.body);
                if (!m) {
                    return bad_request(m.error());
                }
                rollback = std::move(*m);
            }
            auto mod = resolve(box, reload ? reload->module : rollback->module);
            if (!mod) {
                return bad_request(mod.error());
            }
            target = *mod;
            run_tracked(rt, in, target, [&]() -> result<value> {
                auto r = reload ? box.reload(target, reload->source) : box.rollback(target, static_cast<std::size_t>(rollback->steps));
                if (!r) {
                    return std::unexpected{std::move(r).error()};
                }
                return Rhp::to_value(*r);
            });
            return;
        }
        case wire::op::kUnload:
        case wire::op::kRevert:
        case wire::op::kStatus: {
            wire::module_ref ref;
            bool forced = false;
            if (in.code == wire::op::kUnload) {
                auto m = Rhp::from_value<wire::unload_request>(in.body);
                if (!m) {
                    return bad_request(m.error());
                }
                ref = std::move(m->module);
                forced = m->force;
            } else {
                auto m = Rhp::from_value<wire::module_request>(in.body);
                if (!m) {
                    return bad_request(m.error());
                }
                ref = std::move(m->module);
            }
            auto mod = resolve(box, ref);
            if (!mod) {
                return bad_request(mod.error());
            }
            if (in.code == wire::op::kStatus) {
                const auto info = box.status(*mod);
                if (!info) {
                    return bad_request(make_error(errc::kNotFound, std::format("no module {}", *mod), "status"));
                }
                return reply(in.session, in.req, Rhp::to_value(describe(*info)));
            }
            auto r = in.code == wire::op::kRevert ? box.revert(*mod) : forced ? box.unload(*mod, script::force)
                                                                              : box.unload(*mod);
            if (!r) {
                return bad_request(r.error());
            }
            return reply(in.session, in.req, Rhp::to_value(summarize(*r)));
        }
        case wire::op::kCheckpoint:
        case wire::op::kRevertTo: {
            auto m = Rhp::from_value<wire::tag_request>(in.body);
            if (!m) {
                return bad_request(m.error());
            }
            if (in.code == wire::op::kCheckpoint) {
                auto r = box.checkpoint(m->tag);
                if (!r) {
                    return bad_request(r.error());
                }
                return reply(in.session, in.req, value{});
            }
            auto r = box.revert_to(m->tag);
            if (!r) {
                return bad_request(r.error());
            }
            return reply(in.session, in.req, Rhp::to_value(summarize(*r)));
        }
        case wire::op::kRevertAll: {
            // The panic button: every module of every identity.
            script::revert_report total;
            for (auto& [name, other] : identities_) {
                total += other.box->revert_all();
            }
            log(log_level::kWarn, std::format("revert_all by {}: {} effects undone", ps->second.identity, total.undone));
            return reply(in.session, in.req, Rhp::to_value(summarize(total)));
        }
        case wire::op::kList: {
            value::array modules;
            for (const script::module_info& m : box.list()) {
                modules.push_back(Rhp::to_value(describe(m)));
            }
            return reply(in.session, in.req, value{std::move(modules)});
        }
        case wire::op::kDescribe: return reply(in.session, in.req, value{box.stubs()});
        case wire::op::kCancel: return; // handled on the network thread and in process()
        default:
            return bad_request(make_error(errc::kInvalidArgument, std::format("{} arrives in a later stage", in.code), std::string{wire::to_string(in.code)}));
        }
    }

    // Thread-safe: both threads log.
    void log(log_level level, std::string_view message) {
        if (!setup_.log || !setup_.log_enabled) {
            return;
        }
        const std::scoped_lock lock{log_mutex_};
        if (setup_.log_enabled(level)) {
            setup_.log(level, message);
        }
    }

    setup setup_;
    session::options session_options_;
    std::vector<std::pair<std::string, installer>> installers_;
    std::mutex log_mutex_;

    // Network thread. io_ is declared first so it is destroyed last.
    net::io_context io_;
    std::unique_ptr<net::listener> listener_;
    std::optional<error> listen_error_;
    std::map<session_id, io_session> sessions_;
    std::map<std::string, io_identity, std::less<>> io_identities_;
    id_generator<session_id> session_ids_;
    std::size_t pending_handshakes_ = 0;
    std::deque<std::unique_ptr<net::link>> closing_links_;
    std::deque<inbound> inbox_backlog_;
    std::atomic<std::size_t> ready_sessions_{0};

    // Crossing threads.
    utils::spsc_ring<inbound> inbox_;   // network → pump
    utils::spsc_ring<outbound> outbox_; // pump → network

    // Pump thread.
    std::map<session_id, pump_session> pump_sessions_;
    std::map<std::string, identity_runtime, std::less<>> identities_;
    std::deque<outbound> outbox_backlog_;
    std::atomic<std::size_t> identity_count_{0};
};

// ---- the C++ wall --------------------------------------------------------------------------------------

void engine_deleter::operator()(engine* e) const noexcept {
    delete e;
}

engine_ptr make_engine(setup s) {
    return engine_ptr{new engine{std::move(s)}};
}

result<void> listening(const engine& e) {
    return e.listening();
}

std::uint16_t port(const engine& e) noexcept {
    return e.port();
}

result<void> install(engine& e, std::string_view name, installer fn) {
    return e.install(name, fn);
}

void pump(engine& e) {
    e.pump();
}

void run_io(engine& e, std::stop_token stop) {
    e.run_io(std::move(stop));
}

std::size_t sessions(const engine& e) noexcept {
    return e.ready_sessions();
}

std::size_t identities(const engine& e) noexcept {
    return e.identity_count();
}

} // namespace Rhp::host_detail
