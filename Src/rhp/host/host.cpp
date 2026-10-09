#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <format>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/event/hub.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/session/session.hpp>
#include <rhp/utils/scope_guard.hpp>
#include <rhp/utils/spsc_ring.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::host_detail {

namespace {

// What one session asked to stop. Cancels are recorded, not only forwarded to the sandbox, so one
// that lands before its request starts, just before the sandbox's run scope opens, or just after
// the request suspends still takes effect.
struct session_cancels {
    bool dead = false;            // the session ended: none of its requests may run
    std::uint64_t upto = 0;       // cancel-all: every request that arrived at or before this one
    std::set<std::uint64_t> reqs; // single cancels, by the client's request id
};

// Shared by the network thread and the pump thread for one identity: the only way the network
// reaches a sandbox (cancel, which is thread-safe on the sandbox). `box` is cleared, under the
// mutex, before the sandbox is destroyed (or once the identity has no session left).
struct cancel_relay {
    struct suspended_request {
        request_id id;
        std::uint64_t arrival = 0;
        bool pinned = false; // runs in a pinned module: its session ending doesn't stop it
    };

    std::mutex mutex;
    script::sandbox* box = nullptr;
    // The network request inside a sandbox call right now.
    session_id running_session;
    std::uint64_t running_req = 0;
    std::uint64_t running_arrival = 0;
    bool running_pinned = false;
    std::map<std::pair<std::uint64_t, std::uint64_t>, suspended_request> suspended; // (session, req) → sandbox request
    std::map<std::uint64_t, session_cancels> cancels;                               // by session

    // Everything below: under the mutex. A request of a pinned module isn't stopped by its session
    // ending (the module is meant to outlive it), only by an explicit cancel.
    [[nodiscard]] bool covers(session_id session, std::uint64_t req, std::uint64_t arrival, bool pinned = false) const {
        const auto it = cancels.find(session.value());
        return it != cancels.end() && ((it->second.dead && !pinned) || arrival <= it->second.upto || it->second.reqs.contains(req));
    }

    [[nodiscard]] bool dead(session_id session) const {
        const auto it = cancels.find(session.value());
        return it != cancels.end() && it->second.dead;
    }

    // Records a cancel from the network; target 0 = everything `session` sent up to `arrival`.
    void cancel(session_id session, std::uint64_t target, std::uint64_t arrival) {
        session_cancels& c = cancels[session.value()];
        if (target == 0) {
            c.upto = arrival > c.upto ? arrival : c.upto;
        } else {
            c.reqs.insert(target);
        }
        enforce(true);
    }

    // The session ended: whatever it still has running, suspended or queued is stopped.
    void end(session_id session) {
        cancels[session.value()].dead = true;
        enforce(true);
    }

    // Stops the running request when a recorded cancel covers it, and (with `suspended_too`) every
    // covered suspended request. The network thread repeats the first part on a timer: a cancel()
    // that lands before the sandbox's outermost run scope opens is cleared by it.
    void enforce(bool suspended_too) noexcept {
        if (box == nullptr) {
            return;
        }
        if (running_session && covers(running_session, running_req, running_arrival, running_pinned)) {
            box->cancel();
        }
        if (suspended_too) {
            for (const auto& [key, req] : suspended) {
                if (covers(session_id{key.first}, key.second, req.arrival, req.pinned)) {
                    box->cancel(req.id);
                }
            }
        }
    }
};

// Network thread → pump thread.
struct inbound {
    enum class kind : std::uint8_t {
        kOpened,
        kRequest,
        kClosed,
        kAuthFailed,
        kResumed
    };

    kind what = kind::kRequest;
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::shared_ptr<cancel_relay> relay;
    wire::op code = wire::op::kExec;
    std::uint64_t req = 0;
    std::uint64_t arrival = 0; // per-session order in which the network received requests
    value body;
    std::string peer;     // kOpened, kClosed, kAuthFailed, kResumed
    std::string platform; // kOpened
    error reason;         // kClosed, kAuthFailed
    bool tls = false;     // kOpened, kResumed
};

// Pump thread → network thread.
struct outbound {
    session_id session;
    wire::op code = wire::op::kResult;
    std::uint64_t req = 0;
    value body;
};

// Roughly what a value costs to keep (and to encode): enough to bound a cache.
[[nodiscard]] std::size_t approx_size(const value& v) noexcept {
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

[[nodiscard]] bool final_reply(wire::op code, std::uint64_t req) noexcept {
    return req != 0 && (code == wire::op::kResult || code == wire::op::kError);
}

[[nodiscard]] wire::revert_summary summarize(const script::revert_report& r) {
    return {r.undone, r.irreversible, r.failures, r.deferred};
}

[[nodiscard]] wire::module_status describe(const script::module_info& m, bool pinned) {
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
    s.pinned = pinned;
    return s;
}

// Requests the audit log reports (event::script_executed): everything that runs code or changes
// state. Introspection, cancel and blobs (event::blob_received) are left out.
[[nodiscard]] bool audited(wire::op code) noexcept {
    switch (code) {
    case wire::op::kList:
    case wire::op::kStatus:
    case wire::op::kDescribe:
    case wire::op::kCancel:
    case wire::op::kBlob: return false;
    default: return true;
    }
}

[[nodiscard]] std::string ref_text(const wire::module_ref& ref) {
    return ref.name.empty() ? std::format("#{}", ref.id) : ref.name;
}

[[nodiscard]] event::time_point now() {
    return std::chrono::system_clock::now();
}

} // namespace

class engine final : private session::handler {
    static constexpr std::size_t kMaxInFlight = 4096;  // requests with an idempotency key, per session
    static constexpr std::size_t kMaxBacklog = 65'536; // requests held back while pump() is behind
    static constexpr std::chrono::milliseconds kEnforceInterval{20};
    static constexpr std::chrono::milliseconds kGoodbyeWait{500};

public:
    explicit engine(setup s)
        : setup_(std::move(s)),
          inbox_(setup_.options.inbox_capacity),
          outbox_(setup_.options.inbox_capacity) {
        session_options_.limits = setup_.limits;
        session_options_.codec = setup_.codec;
        session_options_.platform = std::string{platform::kOsName};
        session_options_.resumable = setup_.limits.resume_ms != 0;
        if (auto seed = platform::random_array<8>()) {
            std::uint64_t k = 0;
            for (const std::byte b : *seed) {
                k = (k << 8) | std::to_integer<std::uint64_t>(b);
            }
            rng_.seed(k);
        }
        auto policy = session::channel_policy::make(setup_.ep, setup_.transport.network, setup_.tls, setup_.options.tls);
        if (!policy) {
            listen_error_ = std::move(policy).error();
            log(log_level::kError, std::format("host can't use {}: {}", setup_.ep, *listen_error_));
            return;
        }
        policy_ = std::move(*policy);
        const std::string tls_note = policy_.tls() ? std::format(", TLS: {}", policy_.backend()) : std::string{", no TLS"};
        if (setup_.ep.direction == net::endpoint::mode::kDial) {
            // Reverse mode: the host dials a listening client, and keeps dialing.
            reverse_ = true;
            enforce_cancels();
            log(log_level::kInfo, std::format("host dialing {} over {} (reverse mode{})", setup_.ep, setup_.transport.name, tls_note));
            dial_out();
            return;
        }
        auto listener = setup_.transport.listen(io_, policy_.transport_endpoint(), [this](std::unique_ptr<net::link> link) { accept(std::move(link)); });
        if (!listener) {
            listen_error_ = std::move(listener).error();
            log(log_level::kError, std::format("host can't listen ({}): {}", setup_.ep, *listen_error_));
            return;
        }
        listener_ = std::move(*listener);
        enforce_cancels();
        log(log_level::kInfo, std::format("host listening on {} over {} (port {}{})", setup_.ep, setup_.transport.name, listener_->port(), tls_note));
    }

    // The network is stopped (or never ran on another thread) when this runs.
    ~engine() {
        enforce_timer_.cancel();
        redial_timer_.cancel();
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

    void set_enabled(bool on) noexcept {
        enabled_.store(on, std::memory_order_release);
        log(log_level::kWarn, on ? "host enabled" : "host disabled: new connections are closed, requests answered kDisabled");
    }

    [[nodiscard]] bool is_enabled() const noexcept { return enabled_.load(std::memory_order_acquire); }

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

    result<void> add_blob_sink(std::string_view name, blob_fn fn, role need) {
        if (name.empty() || !fn) {
            return fail(errc::kInvalidArgument, "a blob sink needs a name and a function", "host.on_blob");
        }
        if (blob_sinks_.contains(name)) {
            return fail(errc::kAlreadyLoaded, std::format("a blob sink named '{}' is already registered", name), "host.on_blob");
        }
        blob_sinks_.emplace(std::string{name}, blob_sink{std::move(fn), need});
        return {};
    }

    void run_io(std::stop_token stop) { io_.run(std::move(stop)); }

    // Before the network stops: every session is closed with a reason ("the host is shutting
    // down"), so its client fails its calls now instead of waiting to resume; waits briefly for
    // those frames to go out. No new connections or dials after this.
    void goodbye() {
        io_.post([this] {
            stopping_ = true;
            redial_timer_.cancel();
            listener_.reset();
            for (auto& [id, rec] : sessions_) {
                rec.s->close(make_error(errc::kTransport, "the host is shutting down", "host"));
            }
        });
        const auto deadline = std::chrono::steady_clock::now() + kGoodbyeWait;
        while (open_sessions_.load(std::memory_order_acquire) != 0 && std::chrono::steady_clock::now() < deadline) {
            if (setup_.io_thread) {
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
            } else {
                io_.run_one_for(std::chrono::milliseconds{5});
            }
        }
    }

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
        std::set<module_id> pinned; // kept when the last session ends
    };

    // A blob arriving on one session (one at a time).
    struct blob_transfer {
        std::uint64_t id = 0;
        std::string sink;
        std::string name;
        std::uint64_t total = 0;
        std::vector<std::byte> data;
    };

    struct pump_session {
        std::string identity;
        role granted = role::kObserve;
        std::string peer;
        std::optional<blob_transfer> blob;
        std::uint64_t failed_transfer = 0; // later chunks of a refused blob are refused quietly
    };

    struct blob_sink {
        blob_fn fn;
        role need = role::kAdmin;
    };

    // ---- network thread: sessions ----------------------------------------------------------------------

    struct idem_entry {
        bool done = false;
        std::vector<std::uint64_t> reqs; // requests waiting for this result (retries included)
        wire::op code = wire::op::kResult;
        value body;
        std::size_t bytes = 0; // approx_size(body) once done
    };

    struct io_session {
        std::unique_ptr<session::session> s;
        bool ready = false;
        std::string identity;
        std::map<std::uint64_t, std::uint64_t> req_idem; // in-flight req → idempotency key
        std::map<std::uint64_t, idem_entry> idem;
        std::deque<std::uint64_t> idem_done; // completed keys, oldest first (evicted past the cache budgets)
        std::size_t idem_bytes = 0;          // approx_size of every completed body kept
        std::uint64_t arrivals = 0;          // requests received so far
    };

    struct io_identity {
        std::size_t sessions = 0;
        std::shared_ptr<cancel_relay> relay;
    };

    void accept(std::unique_ptr<net::link> link) {
        if (stopping_) {
            park(std::move(link));
            return;
        }
        if (!is_enabled()) {
            log(log_level::kInfo, std::format("refusing {}: the host is disabled", link->peer()));
            refused(link->peer(), make_error(errc::kDisabled, "the host is disabled", "host"));
            park(std::move(link));
            return;
        }
        if (pending_handshakes_ >= setup_.limits.pending_handshakes) {
            log(log_level::kWarn, std::format("refusing {}: {} handshakes already pending", link->peer(), pending_handshakes_));
            refused(link->peer(), make_error(errc::kLimitExceeded, std::format("{} handshakes already pending", pending_handshakes_), "host"));
            park(std::move(link));
            return;
        }
        std::string peer = link->peer();
        auto wrapped = policy_.wrap(std::move(link));
        if (!wrapped) {
            log(log_level::kWarn, std::format("refusing {}: {}", peer, wrapped.error()));
            refused(std::move(peer), std::move(wrapped).error());
            return;
        }
        (void)start_session(std::move(*wrapped));
    }

    // A connection that never got to authenticate (auth_failed, when anyone listens).
    void refused(std::string peer, error why) {
        if (setup_.events == nullptr || !setup_.events->wants(event::kind_of<event::auth_failed>)) {
            return;
        }
        inbound in;
        in.what = inbound::kind::kAuthFailed;
        in.peer = std::move(peer);
        in.reason = std::move(why);
        (void)to_pump(std::move(in));
    }

    // Closes a link we won't serve; it dies once the next connection arrives or the host does.
    void park(std::unique_ptr<net::link> link) {
        link->close();
        closing_links_.push_back(std::move(link));
        if (closing_links_.size() > 64) {
            closing_links_.pop_front();
        }
    }

    session_id start_session(std::unique_ptr<net::link> link, bool dialed = false) {
        const session_id id = session_ids_.next();
        auto handshake = setup_.begin_handshake();
        io_session rec;
        session::options opts = session_options_;
        opts.speaks_first = dialed;
        rec.s = std::make_unique<session::session>(io_, std::move(link), std::move(handshake), static_cast<session::handler&>(*this), std::move(opts), id);
        session::session& s = *rec.s;
        sessions_.emplace(id, std::move(rec));
        open_sessions_.store(sessions_.size(), std::memory_order_release);
        ++pending_handshakes_;
        s.start();
        return id;
    }

    // ---- network thread: reverse mode -------------------------------------------------------------------

    // Dials the client: a new session, or (resume_id set) a new link for that detached session.
    void dial_out(session_id resume_id = {}) {
        setup_.transport.dial(io_, policy_.transport_endpoint(), [this, resume_id](result<std::unique_ptr<net::link>> link) {
            if (link) {
                if (auto wrapped = policy_.wrap(std::move(*link)); wrapped) {
                    link = std::move(*wrapped);
                } else {
                    link = std::unexpected{std::move(wrapped).error()};
                }
            }
            if (resume_id.value() != 0) {
                const auto it = sessions_.find(resume_id);
                if (it == sessions_.end() || it->second.s->current() != session::state::kDetached) {
                    return; // resumed or gone meanwhile; a link we got is dropped
                }
                if (!link) {
                    log(log_level::kDebug, std::format("dialing {} to resume session {} failed: {}", setup_.ep, resume_id, link.error()));
                    redial(resume_id);
                    return;
                }
                it->second.s->resume(std::move(*link));
                return;
            }
            if (!link) {
                log(log_level::kDebug, std::format("dialing {} failed: {}", setup_.ep, link.error()));
                redial();
                return;
            }
            if (!is_enabled()) {
                park(std::move(*link));
                redial();
                return;
            }
            outgoing_ = start_session(std::move(*link), true);
        });
    }

    // Capped exponential backoff with full jitter: a random delay in [0, min(max, min · 2^n)].
    void redial(session_id resume_id = {}) {
        const std::uint32_t lo = setup_.limits.backoff_min_ms == 0 ? 1 : setup_.limits.backoff_min_ms;
        const std::uint32_t hi = setup_.limits.backoff_max_ms < lo ? lo : setup_.limits.backoff_max_ms;
        const std::uint64_t ceiling = std::min<std::uint64_t>(hi, static_cast<std::uint64_t>(lo) << std::min<std::uint32_t>(attempts_, 20));
        ++attempts_;
        std::uniform_int_distribution<std::uint64_t> pick{1, ceiling};
        redial_timer_.start(std::chrono::milliseconds{pick(rng_)}, [this, resume_id] { dial_out(resume_id); });
    }

    // ---- network thread: resume -------------------------------------------------------------------

    void on_detached(session::session& s, const error& why) override {
        log(log_level::kInfo, std::format("session {} ({}) lost its link ({}); it may resume within {} ms", s.id(), s.identity(), why, setup_.limits.resume_ms));
        if (reverse_ && s.id() == outgoing_ && !stopping_) {
            attempts_ = 0;
            redial(s.id());
        }
    }

    void on_resumed(session::session& s) override {
        if (s.id() == outgoing_) {
            attempts_ = 0;
        }
        log(log_level::kInfo, std::format("session {} ({}) resumed from {}{}", s.id(), s.identity(), s.peer(), s.encrypted() ? " over TLS" : ""));
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

    session::session* resume_target(session::session& fresh, session_id id) override {
        if (!is_enabled() || reverse_) {
            return nullptr;
        }
        const auto it = sessions_.find(id);
        if (it == sessions_.end() || !it->second.ready || it->second.s.get() == &fresh) {
            return nullptr;
        }
        return it->second.s.get();
    }

    void on_ready(session::session& s) override {
        --pending_handshakes_;
        auto it = sessions_.find(s.id());
        if (it == sessions_.end()) {
            return;
        }
        if (s.id() == outgoing_) {
            attempts_ = 0;
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
        in.peer = s.peer();
        in.platform = s.peer_platform();
        in.tls = s.encrypted();
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
        if (!to_pump(std::move(in))) {
            s.close(make_error(errc::kLimitExceeded, "the host is not keeping up with this session's requests", "host"));
        }
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
            if (auto ident = io_identities_.find(identity); ident != io_identities_.end()) {
                // Nobody is left to answer: stop what this session runs, has suspended or queued.
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
            }
            inbound in;
            in.what = inbound::kind::kClosed;
            in.session = id;
            in.identity = identity;
            in.peer = s.peer();
            in.reason = why;
            to_pump(std::move(in));
        } else if (why.code == errc::kOk) {
            --pending_handshakes_; // it only carried a resume: its link went to that session
        } else {
            --pending_handshakes_;
            log(log_level::kInfo, std::format("connection from {} closed before authenticating: {}", s.peer(), why));
            refused(s.peer(), why);
        }
        sessions_.erase(it); // allowed inside on_closed
        open_sessions_.store(sessions_.size(), std::memory_order_release);
        if (reverse_ && id == outgoing_) {
            outgoing_ = {};
            if (!stopping_) {
                redial();
            }
        }
    }

    void cancel_from_network(session::session& s, const value& body, std::uint64_t arrival) {
        auto request = Rhp::from_value<wire::cancel_request>(body);
        if (!request) {
            return;
        }
        const auto ident = io_identities_.find(s.identity());
        if (ident == io_identities_.end()) {
            return;
        }
        const std::scoped_lock lock{ident->second.relay->mutex};
        ident->second.relay->cancel(s.id(), request->target, arrival);
    }

    // Re-applies recorded cancels to whatever runs inside pump() right now (see enforce()).
    void enforce_cancels() {
        for (auto& [name, ident] : io_identities_) {
            const std::scoped_lock lock{ident.relay->mutex};
            ident.relay->enforce(false);
        }
        std::erase_if(orphans_, [](const std::shared_ptr<cancel_relay>& relay) {
            const std::scoped_lock lock{relay->mutex};
            relay->enforce(false);
            return relay->box == nullptr;
        });
        enforce_timer_.start(kEnforceInterval, [this] { enforce_cancels(); });
    }

    // False when the backlog is full (the caller drops the session that is flooding it).
    bool to_pump(inbound in) {
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

    void flush_inbox_backlog() {
        while (!inbox_backlog_.empty()) {
            if (!inbox_.try_push(std::move(inbox_backlog_.front()))) {
                return;
            }
            inbox_backlog_.pop_front();
            inbox_backlog_waiting_.store(!inbox_backlog_.empty(), std::memory_order_release);
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

    bool send_reply(io_session& rec, wire::op code, std::uint64_t req, const value& body) {
        auto sent = rec.s->send(code, Rhp::to_value(wire::envelope{req, 0, body}));
        if (!sent && sent.error().code == errc::kLimitExceeded && final_reply(code, req)) {
            // Too big for one frame: the request still gets an answer.
            (void)rec.s->send(wire::op::kError, Rhp::to_value(wire::envelope{req, 0, Rhp::to_value(sent.error())}));
        }
        return sent.has_value();
    }

    // ---- pump thread: events -----------------------------------------------------------------------------

    template <event::host_event E>
    [[nodiscard]] bool wants() const {
        return setup_.events != nullptr && setup_.events->wants(event::kind_of<E>);
    }

    // A handler that throws is logged, never allowed to break pump().
    void publish(event::any e) {
        if (setup_.events == nullptr) {
            return;
        }
        try {
            setup_.events->publish(e);
        } catch (const std::exception& ex) {
            log(log_level::kError, std::format("an event handler threw: {}", ex.what()));
        } catch (...) {
            log(log_level::kError, "an event handler threw");
        }
    }

    // ---- pump thread: requests ---------------------------------------------------------------------------

    void process(std::vector<inbound>& batch) {
        for (inbound& in : batch) {
            switch (in.what) {
            case inbound::kind::kOpened: opened(in); break;
            case inbound::kind::kClosed: closed(in); break;
            case inbound::kind::kRequest: request(in); break;
            case inbound::kind::kAuthFailed:
                if (wants<event::auth_failed>()) {
                    publish(event::auth_failed{now(), std::move(in.peer), std::move(in.reason)});
                }
                break;
            case inbound::kind::kResumed:
                if (wants<event::session_resumed>()) {
                    publish(event::session_resumed{now(), in.session, in.identity, std::move(in.peer), in.tls});
                }
                break;
            }
        }
    }

    void opened(inbound& in) {
        pump_sessions_[in.session] = pump_session{in.identity, in.granted, in.peer, std::nullopt, 0};
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
        } else if (it->second.relay != in.relay) {
            // The identity outlived its sessions (pinned modules) and the network made a new relay
            // for the one that just arrived: hand it the sandbox.
            identity_runtime& rt = it->second;
            {
                const std::scoped_lock lock{rt.relay->mutex};
                rt.relay->box = nullptr;
            }
            rt.relay = in.relay;
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->box = rt.box.get();
        }
        it->second.sessions.insert(in.session);
        if (wants<event::session_opened>()) {
            publish(event::session_opened{now(), in.session, in.identity, in.granted, std::move(in.peer), std::move(in.platform), in.tls});
        }
    }

    void closed(inbound& in) {
        pump_sessions_.erase(in.session);
        if (wants<event::session_closed>()) {
            publish(event::session_closed{now(), in.session, in.identity, in.peer, in.reason});
        }
        const auto it = identities_.find(in.identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        rt.sessions.erase(in.session);
        std::erase_if(rt.waiting, [&](const auto& entry) { return entry.second.session == in.session; });
        {
            // Every request of this session that was queued before its close has been processed.
            const std::scoped_lock lock{rt.relay->mutex};
            std::erase_if(rt.relay->suspended, [&](const auto& entry) { return entry.first.first == in.session.value(); });
            rt.relay->cancels.erase(in.session.value());
        }
        if (!rt.sessions.empty()) {
            return;
        }
        if (!rt.pinned.empty()) {
            release(rt);
            return;
        }
        teardown(rt);
        identities_.erase(it);
        identity_count_.store(identities_.size(), std::memory_order_release);
    }

    // Disconnect = revert: the identity's last session is gone (or the host is).
    void teardown(identity_runtime& rt) {
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->box = nullptr;
            rt.relay->suspended.clear();
            rt.relay->cancels.clear();
        }
        const script::revert_report report = rt.box->revert_all();
        rt.box.reset();
        rt.pinned.clear();
        log(log_level::kInfo, std::format("identity {} reverted: {} effects undone, {} irreversible, {} failures", rt.name, report.undone, report.irreversible,
                                          report.failures.size()));
        if (wants<event::identity_reverted>()) {
            publish(event::identity_reverted{now(), rt.name, report.undone, report.irreversible, report.failures.size(), 0});
        }
    }

    // The identity's last session ended but an admin pinned some of its modules: keep those (and
    // every module they require), revert and unload the rest, keep the sandbox.
    void release(identity_runtime& rt) {
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->box = nullptr; // no session is left to cancel anything
            rt.relay->suspended.clear();
            rt.relay->cancels.clear();
        }
        const std::vector<script::module_info> modules = rt.box->list();
        std::set<module_id> keep = rt.pinned;
        for (bool grew = true; grew;) {
            grew = false;
            for (const script::module_info& m : modules) {
                if (keep.contains(m.id)) {
                    for (const module_id dep : m.dependencies) {
                        grew = keep.insert(dep).second || grew;
                    }
                }
            }
        }
        script::revert_report report;
        for (const script::module_info& m : modules) {
            if (m.scratch || keep.contains(m.id)) {
                continue;
            }
            if (auto r = rt.box->unload(m.id, script::force)) {
                report += std::move(*r);
            }
        }
        if (auto r = rt.box->revert(rt.box->scratch_module())) {
            report += std::move(*r);
        }
        log(log_level::kInfo, std::format("identity {} released: {} effects undone, {} pinned modules kept", rt.name, report.undone, rt.pinned.size()));
        if (wants<event::identity_reverted>()) {
            publish(event::identity_reverted{now(), rt.name, report.undone, report.irreversible, report.failures.size(), rt.pinned.size()});
        }
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

    // print / emit: to the network request that caused it, else to every session of the identity.
    void route(const std::string& identity, request_id r, wire::op code, value body) {
        const auto it = identities_.find(identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        // The operation's own request (an event handler started inside it is a request of its own).
        if (rt.current_session && r && r == rt.box->last_request()) {
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

    void reply_error(session_id s, std::uint64_t req, const error& err) {
        // The request being audited right now failed: its audit record says why.
        if (audit_ != nullptr && s == audit_session_ && req == audit_req_ && audit_->outcome.code == errc::kOk) {
            audit_->outcome = err;
        }
        to_network({s, wire::op::kError, req, Rhp::to_value(err)});
    }

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
        // Wake the network thread only when there is something for it: replies, or requests it is
        // holding back because the inbox was full (pump() just made room).
        if (pushed || !outbox_backlog_.empty() || inbox_backlog_waiting_.load(std::memory_order_acquire)) {
            io_.post([this] { drain_outbox(); });
        }
    }

    [[nodiscard]] result<module_id> resolve(script::sandbox& box, const wire::module_ref& ref) {
        if (ref.id) {
            return ref.id;
        }
        return box.find(ref.name);
    }

    // Who signed `source`: the signer's name, "" for unsigned code an observe session may run, or
    // kBadSignature. Records the source's hash and signer in the audit record.
    [[nodiscard]] result<std::string> check_signature(const pump_session& sess, std::string_view module, std::string_view source, const value& signature) {
        if (audit_ != nullptr) {
            audit_->module = module;
            audit_->hash = security::to_hex(security::blake2b_256(source));
        }
        auto who = setup_.verify ? setup_.verify(source, signature) : result<std::string>{std::string{}};
        if (!who && signature.is_nil() && sess.granted == role::kObserve) {
            who = std::string{}; // observe can't mutate anything: unsigned code is allowed
        }
        if (who && audit_ != nullptr) {
            audit_->signer = *who;
        }
        return who;
    }

    // Runs one sandbox operation as the network request `in`; a request that suspends is answered
    // from on_result later. request() has already marked it running in the relay.
    template <class Op>
    void run_tracked(identity_runtime& rt, const inbound& in, module_id module, Op&& op) {
        const request_id before = rt.box->last_request();
        const bool pinned = module && rt.pinned.contains(module);
        {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->running_pinned = pinned;
        }
        rt.current_session = in.session;
        rt.current_req = in.req;
        auto outcome = op();
        rt.current_session = {};
        rt.current_req = 0;
        const request_id after = rt.box->last_request();
        const bool suspended = outcome && after != before && rt.box->pending(after);
        if (suspended) {
            const std::scoped_lock lock{rt.relay->mutex};
            rt.relay->suspended[{in.session.value(), in.req}] = cancel_relay::suspended_request{after, in.arrival, pinned};
            // A cancel that came while it ran (and found nothing to stop yet) applies now.
            if (rt.relay->covers(in.session, in.req, in.arrival, pinned)) {
                rt.box->cancel(after);
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

    // Marks a request running in the relay for as long as it lives (any op may run Lua: on_unload,
    // on_save, a reload's top level).
    struct running_scope {
        cancel_relay& relay;

        running_scope(cancel_relay& r, const inbound& in) : relay(r) {
            const std::scoped_lock lock{relay.mutex};
            relay.running_session = in.session;
            relay.running_req = in.req;
            relay.running_arrival = in.arrival;
        }

        running_scope(const running_scope&) = delete;
        running_scope& operator=(const running_scope&) = delete;

        ~running_scope() {
            const std::scoped_lock lock{relay.mutex};
            relay.running_session = {};
            relay.running_req = 0;
            relay.running_arrival = 0;
            relay.running_pinned = false;
        }
    };

    void request(const inbound& in) {
        const auto ps = pump_sessions_.find(in.session);
        if (ps == pump_sessions_.end()) {
            return; // the session ended before its request ran
        }
        pump_session& sess = ps->second;

        // The audit record of this request, reported when request() returns (reply_error fills in
        // the outcome; a suspended request reports how it started).
        std::optional<event::script_executed> audit;
        if (audited(in.code) && wants<event::script_executed>()) {
            audit.emplace();
            audit->time = now();
            audit->session = in.session;
            audit->identity = sess.identity;
            audit->granted = sess.granted;
            audit->op = std::string{wire::to_string(in.code)};
        }
        audit_ = audit ? &*audit : nullptr;
        audit_session_ = in.session;
        audit_req_ = in.req;
        const utils::scope_guard report{[&] {
            audit_ = nullptr;
            if (audit) {
                publish(std::move(*audit));
            }
        }};

        if (!is_enabled()) {
            abandon_blob(sess, in);
            reply_error(in.session, in.req, make_error(errc::kDisabled, "the host is disabled", std::string{wire::to_string(in.code)}));
            return;
        }
        const auto need = wire::required_role(in.code);
        if (!need) {
            reply_error(in.session, in.req, make_error(errc::kProtocol, std::format("{} is not a request", in.code), "host"));
            return;
        }
        if (!allows(sess.granted, *need)) {
            reply_error(in.session, in.req,
                        make_error(errc::kForbidden, std::format("{} needs role {}, {} has {}", in.code, *need, sess.identity, sess.granted),
                                   std::string{wire::to_string(in.code)}));
            return;
        }
        const auto it = identities_.find(sess.identity);
        if (it == identities_.end()) {
            return;
        }
        identity_runtime& rt = it->second;
        script::sandbox& box = *rt.box;
        {
            const std::scoped_lock lock{rt.relay->mutex};
            if (rt.relay->dead(in.session)) {
                if (audit) {
                    audit->outcome = make_error(errc::kCancelled, "its session ended before it ran", "host");
                }
                return; // its session ended before it could run: nobody to answer
            }
            if (rt.relay->covers(in.session, in.req, in.arrival)) {
                abandon_blob(sess, in);
                reply_error(in.session, in.req, make_error(errc::kCancelled, "cancelled before it started", std::string{wire::to_string(in.code)}));
                return;
            }
        }
        if (in.code == wire::op::kBlob) {
            blob(sess, in);
            return;
        }
        const running_scope running{*rt.relay, in};

        const auto bad_request = [&](const error& err) { reply_error(in.session, in.req, err); };

        switch (in.code) {
        case wire::op::kExec: {
            auto m = Rhp::from_value<wire::exec_request>(in.body);
            if (!m) {
                return bad_request(m.error());
            }
            if (auto who = check_signature(sess, "", m->source, m->signature); !who) {
                return bad_request(who.error());
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
            if (auto who = check_signature(sess, m->name, m->source, m->signature); !who) {
                return bad_request(who.error());
            }
            // The module id is only known once load() returns: track it through `loaded` (a load of a
            // loaded name is a reload of that module).
            module_id loaded;
            const auto existing = box.find(m->name);
            const request_id before = box.last_request();
            run_tracked(rt, in, existing ? *existing : module_id{}, [&]() -> result<value> {
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
            if (audit) {
                audit->module = ref_text(m->module);
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
                if (auto who = check_signature(sess, ref_text(reload->module), reload->source, reload->signature); !who) {
                    return bad_request(who.error());
                }
            } else {
                auto m = Rhp::from_value<wire::rollback_request>(in.body);
                if (!m) {
                    return bad_request(m.error());
                }
                rollback = std::move(*m);
                if (audit) {
                    audit->module = ref_text(rollback->module);
                }
            }
            auto mod = resolve(box, reload ? reload->module : rollback->module);
            if (!mod) {
                return bad_request(mod.error());
            }
            target = *mod;
            run_tracked(rt, in, target, [&]() -> result<value> {
                auto r = reload ? box.reload(target, reload->source)
                                : box.rollback(target, rollback->steps > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                                                                                 : static_cast<std::size_t>(rollback->steps));
                if (!r) {
                    return std::unexpected{std::move(r).error()};
                }
                return Rhp::to_value(*r);
            });
            return;
        }
        case wire::op::kUnload:
        case wire::op::kRevert:
        case wire::op::kStatus:
        case wire::op::kPin:
        case wire::op::kUnpin: {
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
            if (audit) {
                audit->module = ref_text(ref);
            }
            auto mod = resolve(box, ref);
            if (!mod) {
                return bad_request(mod.error());
            }
            const auto info = box.status(*mod);
            if (!info) {
                return bad_request(make_error(errc::kNotFound, std::format("no module {}", *mod), std::string{wire::to_string(in.code)}));
            }
            if (in.code == wire::op::kStatus) {
                return reply(in.session, in.req, Rhp::to_value(describe(*info, rt.pinned.contains(*mod))));
            }
            if (in.code == wire::op::kPin || in.code == wire::op::kUnpin) {
                if (info->scratch) {
                    return bad_request(make_error(errc::kInvalidArgument, "the scratch module can't be pinned (load a module)", std::string{wire::to_string(in.code)}));
                }
                const bool pin = in.code == wire::op::kPin;
                if (pin) {
                    rt.pinned.insert(*mod);
                } else {
                    rt.pinned.erase(*mod);
                }
                {
                    // Its requests suspended right now outlive their sessions from now on (or stop doing so).
                    const std::scoped_lock lock{rt.relay->mutex};
                    for (const auto& [r, p] : rt.waiting) {
                        if (p.module == *mod) {
                            if (const auto s = rt.relay->suspended.find({p.session.value(), p.req}); s != rt.relay->suspended.end()) {
                                s->second.pinned = pin;
                            }
                        }
                    }
                }
                log(log_level::kInfo, std::format("{} {} module {} ({})", sess.identity, in.code == wire::op::kPin ? "pinned" : "unpinned", info->name, *mod));
                return reply(in.session, in.req, value{});
            }
            if (rt.pinned.contains(*mod)) {
                return bad_request(make_error(errc::kForbidden, std::format("module {} is pinned: unpin it first", info->name), std::string{wire::to_string(in.code)}));
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
            if (audit) {
                audit->module = m->tag;
            }
            if (in.code == wire::op::kCheckpoint) {
                auto r = box.checkpoint(m->tag);
                if (!r) {
                    return bad_request(r.error());
                }
                return reply(in.session, in.req, value{});
            }
            if (!rt.pinned.empty()) {
                // revert_to undoes every effect after the mark, whatever module made it: it would
                // hollow out pinned modules, which only unpin + revert / unload or revert_all may undo.
                return bad_request(make_error(errc::kForbidden, "this identity has pinned modules: unpin them before revert_to", "revert_to"));
            }
            auto r = box.revert_to(m->tag);
            if (!r) {
                return bad_request(r.error());
            }
            return reply(in.session, in.req, Rhp::to_value(summarize(*r)));
        }
        case wire::op::kRevertAll: {
            // The panic button: every module of every identity, pinned ones included.
            script::revert_report total;
            std::vector<std::string> sessionless;
            for (auto& [name, other] : identities_) {
                total += other.box->revert_all();
                other.pinned.clear();
                if (other.sessions.empty()) {
                    sessionless.push_back(name);
                }
            }
            for (const std::string& name : sessionless) {
                if (const auto gone = identities_.find(name); gone != identities_.end()) {
                    teardown(gone->second);
                    identities_.erase(gone);
                }
            }
            identity_count_.store(identities_.size(), std::memory_order_release);
            log(log_level::kWarn, std::format("revert_all by {}: {} effects undone", sess.identity, total.undone));
            return reply(in.session, in.req, Rhp::to_value(summarize(total)));
        }
        case wire::op::kList: {
            value::array modules;
            for (const script::module_info& m : box.list()) {
                modules.push_back(Rhp::to_value(describe(m, rt.pinned.contains(m.id))));
            }
            return reply(in.session, in.req, value{std::move(modules)});
        }
        case wire::op::kDescribe: return reply(in.session, in.req, value{box.stubs()});
        default:
            return bad_request(make_error(errc::kInvalidArgument, std::format("{} is not supported by this host", in.code), std::string{wire::to_string(in.code)}));
        }
    }

    // A blob chunk answered before it reached blob() (cancelled, host disabled): its transfer can't
    // complete any more, so it is dropped and its later chunks refused.
    void abandon_blob(pump_session& sess, const inbound& in) {
        if (in.code != wire::op::kBlob || !sess.blob) {
            return;
        }
        const auto chunk = Rhp::from_value<wire::blob_chunk>(in.body);
        if (chunk && chunk->transfer == sess.blob->id) {
            sess.failed_transfer = sess.blob->id;
            sess.blob.reset();
        }
    }

    // One chunk of a blob (see wire::blob_chunk). The sink and role are checked on the first chunk,
    // before anything is buffered; the whole blob goes to the sink when the last chunk arrives.
    void blob(pump_session& sess, const inbound& in) {
        auto chunk = Rhp::from_value<wire::blob_chunk>(in.body);
        if (!chunk) {
            reply_error(in.session, in.req, chunk.error());
            return;
        }
        if (chunk->transfer == 0) {
            reply_error(in.session, in.req, make_error(errc::kProtocol, "a blob needs a transfer id", "blob"));
            return;
        }
        if (chunk->transfer == sess.failed_transfer) {
            reply_error(in.session, in.req, make_error(errc::kCancelled, "an earlier chunk of this blob was refused", "blob"));
            return;
        }
        const auto refuse = [&](const error& err) {
            if (sess.blob && sess.blob->id == chunk->transfer) {
                sess.blob.reset();
            }
            sess.failed_transfer = chunk->transfer;
            if (wants<event::blob_received>()) {
                publish(event::blob_received{now(), in.session, sess.identity, chunk->sink, chunk->name, chunk->total, {}, err});
            }
            reply_error(in.session, in.req, err);
        };
        if (!sess.blob || sess.blob->id != chunk->transfer) {
            if (chunk->offset != 0) {
                return refuse(make_error(errc::kProtocol, "a blob must start at offset 0", "blob"));
            }
            const auto sink = blob_sinks_.find(chunk->sink);
            if (sink == blob_sinks_.end()) {
                return refuse(make_error(errc::kNotFound, std::format("no blob sink named '{}'", chunk->sink), "blob"));
            }
            if (!allows(sess.granted, sink->second.need)) {
                return refuse(make_error(errc::kForbidden, std::format("blob sink '{}' needs role {}, {} has {}", chunk->sink, sink->second.need, sess.identity, sess.granted),
                                         "blob"));
            }
            if (chunk->total > setup_.limits.max_blob) {
                return refuse(make_error(errc::kLimitExceeded, std::format("a {}-byte blob is over the limit ({} bytes)", chunk->total, setup_.limits.max_blob), "blob"));
            }
            if (sess.blob) {
                // A new transfer replaces one the client gave up on (a chunk timed out or was
                // cancelled): its later chunks are refused.
                log(log_level::kInfo, std::format("blob '{}' from {} abandoned at {} of {} bytes", sess.blob->name, sess.identity, sess.blob->data.size(), sess.blob->total));
                sess.failed_transfer = sess.blob->id;
                sess.blob.reset();
            }
            blob_transfer t;
            t.id = chunk->transfer;
            t.sink = chunk->sink;
            t.name = chunk->name;
            t.total = chunk->total;
            t.data.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(chunk->total, 1u << 20)));
            sess.blob = std::move(t);
        }
        blob_transfer& t = *sess.blob;
        if (chunk->offset != t.data.size() || chunk->sink != t.sink || chunk->total != t.total) {
            return refuse(make_error(errc::kProtocol, "blob chunks out of order or inconsistent", "blob"));
        }
        if (chunk->data.size() > t.total - t.data.size()) {
            return refuse(make_error(errc::kProtocol, "more blob bytes than announced", "blob"));
        }
        t.data.insert(t.data.end(), chunk->data.begin(), chunk->data.end());
        if (t.data.size() < t.total) {
            reply(in.session, in.req, value{});
            return;
        }
        // Complete: the sink decides.
        const auto sink = blob_sinks_.find(t.sink);
        result<void> verdict = fail(errc::kNotFound, std::format("no blob sink named '{}'", t.sink), "blob");
        if (sink != blob_sinks_.end()) {
            try {
                verdict = sink->second.fn(blob_view{t.sink, t.name, sess.identity, t.data});
            } catch (const std::exception& ex) {
                verdict = fail(errc::kRuntime, std::format("blob sink '{}' threw: {}", t.sink, ex.what()), "blob");
            } catch (...) {
                verdict = fail(errc::kRuntime, std::format("blob sink '{}' threw", t.sink), "blob");
            }
        }
        if (wants<event::blob_received>()) {
            publish(event::blob_received{now(), in.session, sess.identity, t.sink, t.name, t.total, security::to_hex(security::blake2b_256(t.data)),
                                         verdict ? error{} : verdict.error()});
        }
        log(log_level::kInfo, std::format("blob '{}' ({} bytes) from {} for sink {}: {}", t.name, t.total, sess.identity, t.sink, verdict ? "taken" : verdict.error().message));
        const std::uint64_t id = t.id;
        sess.blob.reset();
        if (!verdict) {
            sess.failed_transfer = id;
            reply_error(in.session, in.req, verdict.error());
            return;
        }
        reply(in.session, in.req, value{});
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
    std::atomic<bool> enabled_{true};

    // Network thread. io_ is declared first so it is destroyed last.
    net::io_context io_;
    std::unique_ptr<net::listener> listener_;
    std::optional<error> listen_error_;
    std::map<session_id, io_session> sessions_;
    std::atomic<std::size_t> open_sessions_{0};
    bool stopping_ = false; // goodbye(): no new connections or dials
    std::map<std::string, io_identity, std::less<>> io_identities_;
    id_generator<session_id> session_ids_;
    std::size_t pending_handshakes_ = 0;
    std::deque<std::unique_ptr<net::link>> closing_links_;
    std::deque<inbound> inbox_backlog_;
    std::atomic<bool> inbox_backlog_waiting_{false};     // read by pump() to decide whether to wake us
    std::vector<std::shared_ptr<cancel_relay>> orphans_; // identities whose last session ended
    net::io_context::timer enforce_timer_{io_};
    std::atomic<std::size_t> ready_sessions_{0};
    // Reverse mode: the one outgoing session, and when to dial again.
    bool reverse_ = false;
    session_id outgoing_;
    std::uint32_t attempts_ = 0;
    std::mt19937_64 rng_{0x52'48'50'00u};
    net::io_context::timer redial_timer_{io_};
    session::channel_policy policy_;

    // Crossing threads.
    utils::spsc_ring<inbound> inbox_;   // network → pump
    utils::spsc_ring<outbound> outbox_; // pump → network

    // Pump thread.
    std::map<session_id, pump_session> pump_sessions_;
    std::map<std::string, identity_runtime, std::less<>> identities_;
    std::map<std::string, blob_sink, std::less<>> blob_sinks_;
    std::deque<outbound> outbox_backlog_;
    std::atomic<std::size_t> identity_count_{0};
    // The audit record of the request request() is handling (reply_error fills in its outcome).
    event::script_executed* audit_ = nullptr;
    session_id audit_session_;
    std::uint64_t audit_req_ = 0;
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

result<void> add_blob_sink(engine& e, std::string_view name, blob_fn fn, role need) {
    return e.add_blob_sink(name, std::move(fn), need);
}

void set_enabled(engine& e, bool on) noexcept {
    e.set_enabled(on);
}

bool enabled(const engine& e) noexcept {
    return e.is_enabled();
}

void pump(engine& e) {
    e.pump();
}

void goodbye(engine& e) {
    e.goodbye();
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
