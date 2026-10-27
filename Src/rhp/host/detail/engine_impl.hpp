#pragma once

// Private to the host engine's sources (host.cpp, engine_network.cpp, engine_identities.cpp and
// engine_requests.cpp; not installed): the engine, the state its two threads share, and what they
// hand each other.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
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
#include <span>
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
#include <rhp/core/subscription.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/event/hub.hpp>
#include <rhp/host/detail/engine.hpp>
#include <rhp/host/detail/gateway.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/session/admission.hpp>
#include <rhp/session/backoff.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/session/session.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/scope_guard.hpp>
#include <rhp/utils/spsc_ring.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::host_detail {

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
    std::map<std::pair<std::uint64_t, std::uint64_t>, suspended_request> suspended; // (session, req) -> sandbox request
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

// Network thread -> pump thread.
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
    std::string identity; // kAuthFailed: the key name the peer tried, if it named one
    role granted = role::kObserve;
    std::shared_ptr<cancel_relay> relay;
    wire::op code = wire::op::kExec;
    std::uint64_t req = 0;
    std::uint64_t arrival = 0; // per-session order in which the network received requests
    value body;
    std::string peer;     // kOpened, kClosed, kAuthFailed, kResumed; an HTTP kRequest's caller
    std::string platform; // kOpened
    error reason;         // kClosed, kAuthFailed
    bool tls = false;     // kOpened, kResumed
    // kExec / kLoad / kReload: the signature check, made on the network thread (an Ed25519 check
    // takes about a tenth of a millisecond: not on the game's frame). Empty when it wasn't made.
    std::optional<result<std::string>> signer;
};

// Pump thread -> network thread.
struct outbound {
    session_id session;
    wire::op code = wire::op::kResult;
    std::uint64_t req = 0;
    value body;
};

class engine final : private session::handler, private gateway_sink, private script::detail::event_listener {
    static constexpr std::size_t kMaxInFlight = 4096;  // requests with an idempotency key, per session
    static constexpr std::size_t kMaxBacklog = 65'536; // requests held back while pump() is behind
    static constexpr std::size_t kMaxQueued = 4096;    // requests one identity may have waiting for limits.pump_requests
    static constexpr std::chrono::milliseconds kEnforceInterval{20};
    static constexpr std::chrono::milliseconds kGoodbyeWait{500};
    static constexpr std::chrono::seconds kIoCallTimeout{10};

public:
    explicit engine(setup s);

    // The network is stopped (or never ran on another thread) when this runs.
    ~engine();

    engine(const engine&) = delete;
    engine& operator=(const engine&) = delete;

    [[nodiscard]] result<void> listening() const;

    // listener_ belongs to the network thread; the port it bound is fixed once the constructor returns.
    [[nodiscard]] std::uint16_t port() const noexcept { return listen_port_; }
    [[nodiscard]] result<std::uint16_t> gateway_port() const;
    [[nodiscard]] std::size_t ready_sessions() const noexcept { return ready_sessions_.load(std::memory_order_acquire); }
    [[nodiscard]] std::size_t identity_count() const noexcept { return identity_count_.load(std::memory_order_acquire); }

    // The kill switch (any thread): the flag at once, the network's part (closing every session,
    // stopping or restarting reverse dials) posted to the network thread.
    void set_enabled(bool on) noexcept;

    [[nodiscard]] bool is_enabled() const noexcept { return enabled_.load(std::memory_order_acquire); }

    // Setup calls touch pump-thread state: before the first pump() any one thread may make them,
    // after it only the thread that pumps. (A call racing the very first pump() on another thread is
    // not detected.)
    [[nodiscard]] result<void> on_pump_thread(std::string_view where) const;

    result<void> install(std::string_view name, installer fn);

    result<void> serve_releases(release_bridge bridge);

    result<void> add_blob_sink(std::string_view name, blob_fn fn, role need);

    void run_io(std::stop_token stop) { io_.run(std::move(stop)); }

    // Pump thread: builds the record (it reads the installed libs), then registers it on the I/O
    // thread, which owns the provider.
    result<void> advertise(net::advertise_options options);

    // The provider's state (name conflicts and network errors arrive after advertise() returned).
    // Any thread with an owned I/O thread; with io<zero_threads> it runs the network, so pump thread.
    result<void> discovery_status();

    // Before the network stops: every session is closed with a reason ("the host is shutting
    // down"), so its client fails its calls now instead of waiting to resume, and the gateway
    // answers its requests in flight; waits briefly for that to be done and for the sessions'
    // frames to go out. No new connections or dials after this.
    void goodbye();

    // ---- pump thread ---------------------------------------------------------------------------------

    void pump();

private:
    [[nodiscard]] static event::time_point now() { return std::chrono::system_clock::now(); }

    // Runs `fn` on the I/O thread and returns its result; under zero_threads the caller runs the
    // context itself. A context that stopped answering reports kTimeout instead of blocking forever.
    template <class T, std::invocable F>
    result<T> on_io(F fn) {
        struct slot {
            std::mutex mutex;
            std::condition_variable ready;
            std::optional<result<T>> value;
        };
        auto shared = std::make_shared<slot>();
        io_.post([shared, fn = std::move(fn)]() mutable {
            auto outcome = fn();
            {
                const std::scoped_lock lock{shared->mutex};
                shared->value = std::move(outcome);
            }
            shared->ready.notify_all();
        });
        const auto deadline = std::chrono::steady_clock::now() + kIoCallTimeout;
        std::unique_lock lock{shared->mutex};
        while (!shared->value) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return fail(errc::kTimeout, "the network thread did not answer", "host");
            }
            if (setup_.io_thread) {
                shared->ready.wait_until(lock, deadline);
            } else {
                lock.unlock();
                io_.run_one_for(std::chrono::milliseconds{5});
                lock.lock();
            }
        }
        return std::move(*shared->value);
    }

    // ---- HTTP frontend (gateway_sink; network thread) ------------------------------------------------

    void start_gateway();

    [[nodiscard]] bool accepting() const noexcept override { return is_enabled() && !stopping_; }

    [[nodiscard]] std::chrono::steady_clock::time_point steady_now() const noexcept override;

    [[nodiscard]] bool custom_clock() const noexcept override { return setup_.custom_clock; }

    // Pump thread: how far the host's clock is from steady_clock, for the network thread's reads.
    void sample_clock() noexcept;

    [[nodiscard]] result<security::http_grant> authorize(const security::http_proof& request) override;

    [[nodiscard]] session_id open_http(const security::http_grant& grant, const http_peer& peer) override;

    void close_http(session_id id, std::string_view name, const error& why) override;

    [[nodiscard]] bool submit_http(session_id id, std::uint64_t req, wire::op code, value body, const http_peer& peer) override;

    void cancel_http(session_id id, std::uint64_t target, std::uint64_t upto) override;

    struct pending_reply {
        session_id session;
        std::uint64_t req = 0;
        wire::op code = wire::op::kExec;
        module_id module;
    };

    struct identity_runtime {
        std::string name;
        std::unique_ptr<script::sandbox> box;
        std::shared_ptr<cancel_relay> relay;
        std::set<session_id> sessions;
        std::map<request_id, pending_reply> waiting; // suspended network requests
        // Audit records of suspended requests, published with the final outcome (finished()), or
        // as cancelled when the identity is torn down first. Outlive the requesting session.
        std::map<request_id, event::script_executed> audits;
        session_id current_session; // the network request inside a sandbox call
        std::uint64_t current_req = 0;
        std::set<module_id> pinned;        // kept when the last session ends
        Rhp::subscription script_listener; // the sandbox's script events -> host.on_script_event and clients
        std::set<session_id> debuggers;    // sessions that set breakpoints or paused: the last one's end resets the debugger
        session_id profiler;               // started the profiler: its end stops it
        // limits.request_rate: when the identity's token bucket is full again (take_token).
        std::chrono::steady_clock::time_point bucket_full{};
        std::deque<inbound> queued; // limits.pump_requests: admitted, waiting for a pump() with budget left
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
        std::uint64_t failed_transfer = 0;               // later chunks of a refused blob are refused quietly
        std::set<std::string, std::less<>> script_subs;  // rhp.publish names of its identity ("*": all)
        std::set<std::string, std::less<>> program_subs; // C++ lua_event names
        std::size_t sent_this_pump = 0;
        std::uint64_t dropped = 0;        // events not sent since the last one that was
        std::uint64_t rated_transfer = 0; // limits.request_rate: the blob whose first chunk was admitted (its later chunks are free)
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
        session::admission::ticket ticket = 0; // an accepted connection's slot until it authenticates
        bool ready = false;
        std::string identity;
        std::map<std::uint64_t, std::uint64_t> req_idem; // in-flight req -> idempotency key
        std::map<std::uint64_t, idem_entry> idem;
        std::deque<std::uint64_t> idem_done; // completed keys, oldest first (evicted past the cache budgets)
        std::size_t idem_bytes = 0;          // approx_size of every completed body kept
        std::uint64_t arrivals = 0;          // requests received so far
    };

    struct io_identity {
        std::size_t sessions = 0;
        std::shared_ptr<cancel_relay> relay;
    };

    void accept(std::unique_ptr<net::link> link);

    // A connection that never got to authenticate (auth_failed, when anyone listens); `key` is the key
    // name it tried, if it named one.
    void refused(std::string peer, error why, std::string key) override;

    // Closes a link we won't serve; it dies once the next connection arrives or the host does.
    void park(std::unique_ptr<net::link> link);

    // An accepted connection holds `ticket` (admission_) until it authenticates; a dialed one none.
    void start_session(session_id id, std::unique_ptr<net::link> link, bool dialed, session::admission::ticket ticket);

    // The admission gave up on an unauthenticated session (no room, or it sent nothing in time).
    void drop_unauthenticated(session_id id, const error& why);

    // The kill switch's network side, in the order set_enabled was called. Off: every session
    // (native, HTTP, detached, handshaking) closes with kDisabled, so identities revert as on
    // disconnect, and reverse mode stops dialing. On again: reverse mode dials.
    void apply_enabled(bool on);

    // ---- network thread: reverse mode -------------------------------------------------------------------

    // Dials the client: a new session, or (resume_id set) a new link for that detached session.
    void dial_out(session_id resume_id = {});

    // Capped exponential backoff with full jitter (session::backoff_delay).
    void redial(session_id resume_id = {});

    // ---- network thread: resume -------------------------------------------------------------------

    void on_detached(session::session& s, const error& why) override;

    void on_resumed(session::session& s) override;

    session::session* resume_target(session::session& fresh, session_id id) override;

    void on_ready(session::session& s) override;

    void on_message(session::session& s, wire::op code, value body) override;

    void on_closed(session::session& s, const error& why) override;

    // A session authenticated (a native one, or an HTTP identity's logical one): counted in its
    // identity (whose cancel relay it gets) and handed to pump(), which gives the identity a sandbox
    // if it has none.
    void register_session(session_id id, const std::string& identity, role granted, std::string peer, std::string platform, bool tls);

    // An authenticated session ended: nobody is left to answer it, so what it runs, has suspended or
    // queued is stopped, and pump() hears of it.
    void unregister_session(session_id id, std::string_view identity, std::string peer, const error& why);

    void cancel_from_network(session::session& s, const value& body, std::uint64_t arrival);

    // Re-applies recorded cancels to whatever runs inside pump() right now (see enforce()), every
    // kEnforceInterval while a cancel is recorded or an orphaned relay still has its sandbox: an idle
    // host doesn't wake up for it.
    void enforce_cancels();

    // A cancel was recorded or a session ended: enforce_cancels() runs again shortly (pump() clears
    // the records once the requests they cover are dealt with).
    void arm_enforce();

    // False when the backlog is full (the caller drops the session that is flooding it).
    bool to_pump(inbound in);

    void flush_inbox_backlog();

    // The pump's replies, on the network thread.
    void drain_outbox();

    bool send_reply(io_session& rec, wire::op code, std::uint64_t req, const value& body);

    // ---- pump thread: events -----------------------------------------------------------------------------

    template <event::host_event E>
    [[nodiscard]] bool wants() const {
        return setup_.events != nullptr && setup_.events->wants(event::kind_of<E>);
    }

    // A handler that throws is logged, never allowed to break pump().
    void publish(event::any e);

    // ---- pump thread: requests ---------------------------------------------------------------------------

    void process(std::vector<inbound>& batch);

    void opened(inbound& in);

    void closed(inbound& in);

    // No session of the identity is left to cancel anything: the network loses its way to the
    // sandbox, and the cancels and suspended requests it recorded go.
    static void detach_relay(identity_runtime& rt);

    // Disconnect = revert: the identity's last session is gone (or the host is).
    void teardown(identity_runtime& rt);

    // The identity's last session ended but an admin pinned some of its modules: keep those (and
    // every module they require), revert and unload the rest, keep the sandbox.
    void release(identity_runtime& rt);

    script::sandbox_options sandbox_options_for(const std::string& identity, role granted);

    // A script's handler failed: a host event, a log line and an output line for its sessions.
    void handler_failed(const std::string& identity, const script::handler_failure& f);

    // ---- pump thread: events ------------------------------------------------------------------------

    // An rhp.publish of `identity`'s sandbox: host.on_script_event and the identity's subscribed sessions.
    void forward_script_event(const std::string& identity, const script::script_event& e);

    // One kEvent to one session, at most remote_events_per_pump per pump(); the rest are counted.
    void send_event(session_id s, pump_session& sess, std::string_view name, module_id module, std::span<const value> args);

    // C++ lua_events for subscribed sessions (event_listener; attached while any session subscribes).
    [[nodiscard]] std::thread::id listener_thread() const noexcept override { return pump_thread_.load(std::memory_order_acquire); }

    void deliver(std::string_view event, const script::detail::event_args& args) override;

    void enqueue(std::string_view event, const script::detail::event_args& args) noexcept override;

    void deliver_program_events();

    void send_program_event(std::string_view event, const std::vector<value>& args);

    void drop_program_sub(const std::string& name, session_id s);

    // kSubscribe / kUnsubscribe: a C++ event (program-wide) or the identity's script events.
    void subscription_request(pump_session& sess, const inbound& in);

    // print / emit: to the network request that caused it, else to every session of the identity.
    void route(const std::string& identity, request_id r, wire::op code, value body);

    // A suspended network request finished (sandbox on_result).
    void finished(const std::string& identity, request_id r, const result<script::value_list>& res);

    void reply(session_id s, std::uint64_t req, value body) { to_network({s, wire::op::kResult, req, std::move(body)}); }

    void reply_error(session_id s, std::uint64_t req, const error& err);

    void to_network(outbound out) { outbox_backlog_.push_back(std::move(out)); }

    void flush_outbox();

    [[nodiscard]] result<module_id> resolve(script::sandbox& box, const wire::module_ref& ref);

    // Who signed `source`: the signer's name, "" for unsigned code an observe session may run, or
    // kBadSignature. Records the source's hash and signer in the audit record.
    [[nodiscard]] result<std::string> check_signature(const pump_session& sess, const inbound& in, std::string_view module, std::string_view source,
                                                      const value& signature);

    // One network request while request() handles it: the request, its session and its identity.
    struct request_ctx {
        const inbound& in;
        pump_session& sess;
        identity_runtime& rt;
        script::sandbox& box;
    };

    // The request's body as M, or nothing once the request was answered with why it isn't one.
    template <from_value_convertible M>
    [[nodiscard]] std::optional<M> decode(request_ctx& c) {
        auto m = Rhp::from_value<M>(c.in.body);
        if (!m) {
            reject(c, m.error());
            return std::nullopt;
        }
        return std::move(*m);
    }

    // Answers the request with the value, or with the error.
    void answer(request_ctx& c, result<value> r);

    void reject(request_ctx& c, const error& err) { reply_error(c.in.session, c.in.req, err); }

    // Runs one sandbox operation as the request; a request that suspends is answered from
    // on_result later. request() has already marked it running in the relay.
    template <std::invocable Op>
    void run_tracked(request_ctx& c, module_id module, Op&& op) {
        const inbound& in = c.in;
        identity_runtime& rt = c.rt;
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
            if (audit_ != nullptr) {
                // Reported when it really finishes: a later failure must not leave an `ok` record.
                rt.audits[after] = *audit_;
                audit_deferred_ = true;
            }
            return;
        }
        if (!outcome) {
            reject(c, outcome.error());
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

    // `refused`: turned away at admission (audited, answered with it, not run).
    void request(const inbound& in, const error* refused = nullptr);

    // A request from the network: limits.request_rate decides whether it is taken, limits.pump_requests
    // whether it starts now or waits in its identity's queue.
    void admit(inbound& in);

    // limits.pump_requests: up to that many waiting requests of each identity, one identity's at a
    // time in turn (the identity after the one that went first last time goes first).
    void start_queued();

    // The session ended: its requests still waiting go through request(), which finds it ended.
    void drop_queued(identity_runtime& rt, session_id session);

    // ---- pump thread: one function per group of ops (request() has checked role, identity and cancels) ----

    // release_apply / confirm / deactivate / status, revoke: the served release manager answers.
    void op_release(request_ctx& c);

    void op_exec(request_ctx& c);

    void op_load(request_ctx& c);

    void op_call(request_ctx& c);

    // reload (signed new source) and rollback (to an earlier revision): both answer the revision.
    void op_reload(request_ctx& c);

    // unload, revert, status, pin, unpin: one module of the identity.
    void op_module(request_ctx& c);

    // pin / unpin of a module op_module found.
    void op_pin(request_ctx& c, module_id mod, const script::module_info& info);

    // checkpoint / revert_to: a named mark in the identity's journal.
    void op_tag(request_ctx& c);

    // The panic button: every module of every identity, pinned ones included.
    void op_revert_all(request_ctx& c);

    // list (the identity's modules) and describe (LuaLS stubs of what it can use).
    void op_list(request_ctx& c);

    void op_tunables(request_ctx& c);

    void op_tune(request_ctx& c);

    void op_profile(request_ctx& c);

    void op_debug(request_ctx& c);

    // One debug request of `session` against its identity's sandbox.
    result<wire::debug_reply> debug(identity_runtime& rt, script::sandbox& box, session_id session, const wire::debug_request& m);

    // A blob chunk answered before it reached blob() (cancelled, host disabled): its transfer can't
    // complete any more, so it is dropped and its later chunks refused.
    void abandon_blob(pump_session& sess, const inbound& in);

    // One chunk of a blob (see wire::blob_chunk). The sink and role are checked on the first chunk,
    // before anything is buffered; the whole blob goes to the sink when the last chunk arrives.
    void blob(pump_session& sess, const inbound& in);

    // Thread-safe: both threads log. The level check takes no lock (core::logger::enabled is
    // thread-safe) and comes before formatting; writes are serialized.
    [[nodiscard]] bool log_on(log_level level) const { return setup_.log && setup_.log_enabled && setup_.log_enabled(level); }

    template <class... Args>
    void log(log_level level, std::format_string<Args...> fmt, Args&&... args) {
        if (log_on(level)) {
            write_log(level, std::format(fmt, std::forward<Args>(args)...));
        }
    }

    void log_text(log_level level, std::string_view message);

    void write_log(log_level level, std::string_view message);

    setup setup_;
    session::options session_options_;
    std::vector<std::pair<std::string, installer>> installers_;
    std::mutex log_mutex_;
    std::atomic<bool> enabled_{true};

    // Network thread. io_ is declared first so it is destroyed last.
    net::io_context io_;
    session::admission admission_{io_, setup_.limits}; // unauthenticated connections, native and HTTP
    std::unique_ptr<net::listener> listener_;
    std::optional<error> listen_error_;
    std::unique_ptr<http_gateway> gateway_;
    std::optional<error> gateway_error_;
    std::uint16_t gateway_port_ = 0;                  // fixed once the constructor returns
    std::map<session_id, std::string> http_sessions_; // network thread
    std::unique_ptr<net::advertisement> advertisement_;
    std::optional<net::advertise_options> advertise_options_; // pump-thread metadata
    std::uint16_t listen_port_ = 0;                           // fixed once the constructor returns (listener_ belongs to the network thread)
    std::map<session_id, io_session> sessions_;
    std::atomic<std::size_t> open_sessions_{0};
    bool stopping_ = false;                 // goodbye(): no new connections or dials
    std::atomic<bool> said_goodbye_{false}; // goodbye()'s posted work ran (sessions closed, gateway stopped)
    std::map<std::string, io_identity, std::less<>> io_identities_;
    id_generator<session_id> session_ids_;
    std::deque<std::unique_ptr<net::link>> closing_links_;
    std::deque<inbound> inbox_backlog_;
    std::atomic<bool> inbox_backlog_waiting_{false};     // read by pump() to decide whether to wake us
    std::vector<std::shared_ptr<cancel_relay>> orphans_; // identities whose last session ended
    net::io_context::timer enforce_timer_{io_};
    bool enforce_armed_ = false; // network thread
    std::atomic<std::size_t> ready_sessions_{0};
    bool serving_ = true; // the kill switch as apply_enabled last left it
    // Reverse mode: the one outgoing session, and when to dial again.
    bool reverse_ = false;
    bool dialing_ = false; // a dial is under way
    session_id outgoing_;
    std::uint32_t attempts_ = 0;
    std::mt19937_64 rng_{0x52'48'50'00u};
    net::io_context::timer redial_timer_{io_};
    session::channel_policy policy_;

    // Crossing threads.
    utils::spsc_ring<inbound> inbox_;   // network -> pump
    utils::spsc_ring<outbound> outbox_; // pump -> network

    // Pump thread.
    std::map<session_id, pump_session> pump_sessions_;
    std::map<std::string, identity_runtime, std::less<>> identities_;
    std::string first_turn_;                               // start_queued: the identity that went first last time
    std::vector<script::async_leftovers> async_leftovers_; // of identities that went (teardown)
    Rhp::subscription release_events_;                     // to the served manager's events
    release_bridge releases_;                              // host.serve: the release manager, if any
    std::map<std::string, blob_sink, std::less<>> blob_sinks_;
    std::deque<outbound> outbox_backlog_;
    std::atomic<std::size_t> identity_count_{0};
    // config<>::clock minus steady_clock, sampled by pump() (and at construction) for the gateway.
    std::atomic<std::int64_t> clock_offset_ns_{0};
    // The audit record of the request request() is handling (reply_error fills in its outcome).
    event::script_executed* audit_ = nullptr;
    session_id audit_session_;
    std::uint64_t audit_req_ = 0;
    bool audit_deferred_ = false; // the request suspended: identity_runtime::audits reports it
    // Remote subscriptions to C++ events: who wants each name, and the event states listened to.
    std::map<std::string, std::set<session_id>, std::less<>> program_subs_;
    std::map<std::string, script::detail::event_state*, std::less<>> program_attached_;
    std::atomic<std::thread::id> pump_thread_{}; // unclaimed until the first pump()
    std::mutex program_mutex_;                   // guards program_inbox_ (fires from other threads)
    std::vector<std::pair<std::string, std::vector<value>>> program_inbox_;
};

} // namespace Rhp::host_detail
