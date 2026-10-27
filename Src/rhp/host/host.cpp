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
#include <rhp/session/secure_link.hpp>
#include <rhp/session/session.hpp>
#include <rhp/utils/fixed_string.hpp>
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
    std::string peer;     // kOpened, kClosed, kAuthFailed, kResumed; an HTTP kRequest's caller
    std::string platform; // kOpened
    error reason;         // kClosed, kAuthFailed
    bool tls = false;     // kOpened, kResumed
    // kExec / kLoad / kReload: the signature check, made on the network thread (an Ed25519 check
    // takes about a tenth of a millisecond: not on the game's frame). Empty when it wasn't made.
    std::optional<result<std::string>> signer;
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
// state. Introspection, cancel and blobs (event::blob_received) are left out; of the debugger, the
// actions that change what scripts do (breakpoints, pause, resume, steps, reset).
[[nodiscard]] bool audited(wire::op code, const value& body) noexcept {
    if (code == wire::op::kDebug) {
        const value* action = body.find("action");
        const auto* name = action != nullptr ? action->get_if<std::string>() : nullptr;
        if (name == nullptr) {
            return true;
        }
        return *name != "paused" && *name != "stack" && *name != "variables" && *name != "evaluate";
    }
    switch (code) {
    case wire::op::kList:
    case wire::op::kStatus:
    case wire::op::kDescribe:
    case wire::op::kCancel:
    case wire::op::kBlob:
    case wire::op::kSubscribe:
    case wire::op::kUnsubscribe:
    case wire::op::kReleaseStatus:
    case wire::op::kTunables:
    case wire::op::kProfile: return false;
    default: return true;
    }
}

[[nodiscard]] bool is_release_op(wire::op code) noexcept {
    switch (code) {
    case wire::op::kReleaseApply:
    case wire::op::kReleaseConfirm:
    case wire::op::kReleaseDeactivate:
    case wire::op::kReleaseStatus:
    case wire::op::kRevoke: return true;
    default: return false;
    }
}

// The report as one reply: stacks (most samples first) up to about a quarter of the frame limit,
// the rest counted as truncated.
[[nodiscard]] wire::profile_reply profile_message(const script::profile_report& r, std::uint32_t max_frame) {
    wire::profile_reply out;
    out.running = r.running;
    out.interval = r.interval;
    out.samples = r.samples;
    out.dropped = r.dropped;
    out.elapsed_us = static_cast<std::uint64_t>(r.elapsed.count());
    const std::size_t budget = std::max<std::size_t>(max_frame / 4, 4096);
    std::size_t used = 0;
    for (const script::profile_stack& s : r.stacks) {
        used += s.stack.size() + 16;
        if (used > budget) {
            out.truncated = r.stacks.size() - out.stacks.size();
            break;
        }
        out.stacks.push_back(wire::profile_stack_message{s.stack, s.samples});
    }
    return out;
}

[[nodiscard]] std::optional<script::debug_scope> parse_scope(std::string_view text) noexcept {
    for (const auto s : {script::debug_scope::kLocals, script::debug_scope::kUpvalues, script::debug_scope::kGlobals}) {
        if (script::to_string(s) == text) {
            return s;
        }
    }
    return std::nullopt;
}

[[nodiscard]] wire::debug_variable_message variable_message(const script::debug_variable& v) {
    return wire::debug_variable_message{v.name, v.type, v.text, v.expandable};
}

[[nodiscard]] std::string ref_text(const wire::module_ref& ref) {
    return ref.name.empty() ? std::format("#{}", ref.id) : ref.name;
}

[[nodiscard]] event::time_point now() {
    return std::chrono::system_clock::now();
}

} // namespace

class engine final : private session::handler, private gateway_sink, private script::detail::event_listener {
    static constexpr std::size_t kMaxInFlight = 4096;  // requests with an idempotency key, per session
    static constexpr std::size_t kMaxBacklog = 65'536; // requests held back while pump() is behind
    static constexpr std::chrono::milliseconds kEnforceInterval{20};
    static constexpr std::chrono::milliseconds kGoodbyeWait{500};
    static constexpr std::chrono::seconds kIoCallTimeout{10};

public:
    explicit engine(setup s)
        : setup_(std::move(s)),
          inbox_(setup_.options.inbox_capacity),
          outbox_(setup_.options.inbox_capacity) {
        sample_clock();
        session_options_.limits = setup_.limits;
        session_options_.codec = setup_.codec;
        session_options_.ack_delay_ms = setup_.options.ack_delay_ms;
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
            log(log_level::kError, "host can't use {}: {}", setup_.ep, *listen_error_);
            return;
        }
        policy_ = std::move(*policy);
        start_gateway();
        const std::string tls_note = policy_.tls() ? std::format(", TLS: {}", policy_.backend()) : std::string{", no TLS"};
        if (setup_.ep.direction == net::endpoint::mode::kDial) {
            // Reverse mode: the host dials a listening client, and keeps dialing.
            reverse_ = true;
            log(log_level::kInfo, "host dialing {} over {} (reverse mode{})", setup_.ep, setup_.transport.name, tls_note);
            dial_out();
            return;
        }
        auto listener = setup_.transport.listen(io_, policy_.transport_endpoint(), [this](std::unique_ptr<net::link> link) { accept(std::move(link)); });
        if (!listener) {
            listen_error_ = std::move(listener).error();
            log(log_level::kError, "host can't listen ({}): {}", setup_.ep, *listen_error_);
            return;
        }
        listener_ = std::move(*listener);
        listen_port_ = static_cast<std::uint16_t>(listener_->port());
        log(log_level::kInfo, "host listening on {} over {} (port {}{})", setup_.ep, setup_.transport.name, listener_->port(), tls_note);
    }

    // The network is stopped (or never ran on another thread) when this runs.
    ~engine() {
        release_events_.reset(); // a manager that outlives the host never calls into it again
        for (const auto& [name, state] : program_attached_) {
            state->detach(this); // a game thread may still fire: never after this
        }
        program_attached_.clear();
        advertisement_.reset();
        gateway_.reset();
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

    // listener_ belongs to the network thread; the port it bound is fixed once the constructor returns.
    [[nodiscard]] std::uint16_t port() const noexcept { return listen_port_; }
    [[nodiscard]] result<std::uint16_t> gateway_port() const {
        if (gateway_error_) {
            return fail(*gateway_error_);
        }
        if (gateway_port_ == 0) {
            return fail(errc::kDisabled, "the HTTP listener was not requested (host_options::gateway)", "host.gateway");
        }
        return gateway_port_;
    }
    [[nodiscard]] std::size_t ready_sessions() const noexcept { return ready_sessions_.load(std::memory_order_acquire); }
    [[nodiscard]] std::size_t identity_count() const noexcept { return identity_count_.load(std::memory_order_acquire); }

    void set_enabled(bool on) noexcept {
        enabled_.store(on, std::memory_order_release);
        try {
            log_text(log_level::kWarn, on ? "host enabled" : "host disabled: new connections are closed, requests answered kDisabled");
        } catch (...) { // the user's logger threw (or its lock failed): the switch flipped all the same
        }
    }

    [[nodiscard]] bool is_enabled() const noexcept { return enabled_.load(std::memory_order_acquire); }

    // Setup calls touch pump-thread state: before the first pump() any one thread may make them,
    // after it only the thread that pumps. (A call racing the very first pump() on another thread is
    // not detected.)
    [[nodiscard]] result<void> on_pump_thread(std::string_view where) const {
        const std::thread::id owner = pump_thread_.load(std::memory_order_acquire);
        if (owner != std::thread::id{} && owner != std::this_thread::get_id()) {
            return fail(errc::kInvalidArgument, "call this from the thread that calls pump() (or before the first pump())", std::string{where});
        }
        return {};
    }

    result<void> install(std::string_view name, installer fn) {
        if (auto here = on_pump_thread("host.install"); !here) {
            return here;
        }
        for (const auto& [n, f] : installers_) {
            if (n == name) {
                return fail(errc::kAlreadyLoaded, std::format("a lib named '{}' is already installed", name), "host.install");
            }
        }
        installers_.emplace_back(std::string{name}, fn);
        for (auto& [identity, id] : identities_) {
            if (auto ok = fn(*id.box); !ok) {
                log(log_level::kWarn, "install {} into identity {}: {}", name, identity, ok.error());
            }
        }
        if (advertise_options_ && advertise_options_->include_libs) {
            return advertise(*advertise_options_);
        }
        return {};
    }

    result<void> serve_releases(release_bridge bridge) {
        if (auto here = on_pump_thread("host.serve"); !here) {
            return here;
        }
        if (releases_.handle) {
            return fail(errc::kAlreadyLoaded, "this host already serves a release manager", "host.serve");
        }
        releases_ = std::move(bridge);
        if (releases_.on_event) {
            release_events_ = releases_.on_event([this](event::release_changed e) {
                if (wants<event::release_changed>()) {
                    publish(std::move(e));
                }
            });
        }
        return {};
    }

    result<void> add_blob_sink(std::string_view name, blob_fn fn, role need) {
        if (auto here = on_pump_thread("host.on_blob"); !here) {
            return here;
        }
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

    // Pump thread: builds the record (it reads the installed libs), then registers it on the I/O
    // thread, which owns the provider.
    result<void> advertise(net::advertise_options options) {
        if (auto here = on_pump_thread("host.advertise"); !here) {
            return here;
        }
        if (listen_port_ == 0 || !setup_.transport.network) {
            return fail(errc::kInvalidArgument, "only a listening host on a network transport can advertise", "host.advertise");
        }
        if (options.name.empty()) {
            if (advertise_options_) {
                options.name = advertise_options_->name;
            } else {
                auto nonce = platform::random_array<4>();
                if (!nonce) {
                    return std::unexpected{std::move(nonce).error()};
                }
                options.name = "rhp-" + security::to_hex(*nonce);
            }
        }
        net::service_record record;
        record.name = options.name;
        record.address = setup_.ep.host;
        record.port = listen_port_;
        record.protocol_revision = wire::kProtocolRevision;
        record.platform = platform::kOsName;
        record.app = options.app;
        record.build = options.build;
        record.transport = setup_.transport.name;
        if (options.include_libs) {
            for (const auto& [name, fn] : installers_) {
                record.libs.push_back(name);
            }
        }
        auto published = on_io<void>([this, record = std::move(record)]() mutable -> result<void> {
            if (advertisement_) {
                return advertisement_->update(std::move(record));
            }
            auto advertised = setup_.discovery.advertise(io_, std::move(record));
            if (!advertised) {
                return std::unexpected{std::move(advertised).error()};
            }
            advertisement_ = std::move(*advertised);
            return {};
        });
        if (published) {
            advertise_options_ = std::move(options);
        }
        return published;
    }

    // The provider's state (name conflicts and network errors arrive after advertise() returned).
    // Any thread with an owned I/O thread; with io<zero_threads> it runs the network, so pump thread.
    result<void> discovery_status() {
        if (!setup_.io_thread) {
            if (auto here = on_pump_thread("host.discovery_status"); !here) {
                return here;
            }
        }
        return on_io<void>([this]() -> result<void> {
            return advertisement_ ? advertisement_->status() : result<void>{fail(errc::kDisabled, "the host is not advertising", "host.discovery")};
        });
    }

    // Before the network stops: every session is closed with a reason ("the host is shutting
    // down"), so its client fails its calls now instead of waiting to resume, and the gateway
    // answers its requests in flight; waits briefly for that to be done and for the sessions'
    // frames to go out. No new connections or dials after this.
    void goodbye() {
        io_.post([this] {
            stopping_ = true;
            redial_timer_.cancel();
            listener_.reset();
            advertisement_.reset();
            if (gateway_) {
                gateway_->stop();
            }
            for (auto& [id, rec] : sessions_) {
                rec.s->close(make_error(errc::kTransport, "the host is shutting down", "host"));
            }
            said_goodbye_.store(true, std::memory_order_release);
        });
        const auto deadline = std::chrono::steady_clock::now() + kGoodbyeWait;
        // An HTTP-only host has no native session to wait for, but its gateway's answers are only
        // sent once the posted goodbye ran.
        while ((!said_goodbye_.load(std::memory_order_acquire) || open_sessions_.load(std::memory_order_acquire) != 0) &&
               std::chrono::steady_clock::now() < deadline) {
            if (setup_.io_thread) {
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
            } else {
                io_.run_one_for(std::chrono::milliseconds{5});
            }
        }
    }

    // ---- pump thread ---------------------------------------------------------------------------------

    void pump() {
        pump_thread_.store(std::this_thread::get_id(), std::memory_order_release);
        sample_clock();
        if (!setup_.io_thread) {
            io_.poll();
        }
        for (auto& [id, sess] : pump_sessions_) {
            sess.sent_this_pump = 0;
        }
        std::vector<inbound> batch;
        while (auto item = inbox_.try_pop()) {
            batch.push_back(std::move(*item));
        }
        process(batch);
        deliver_program_events();
        for (auto& [name, id] : identities_) {
            id.box->pump();
        }
        std::erase_if(async_leftovers_, [](script::async_leftovers& left) { return left.pump() == 0; });
        if (releases_.pump) {
            releases_.pump();
        }
        flush_outbox();
        if (!setup_.io_thread) {
            io_.poll();
        }
    }

private:
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

    void start_gateway() {
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
        auto policy = session::channel_policy::make(ep, true, setup_.tls, setup_.options.tls);
        if (!policy) {
            gateway_error_ = std::move(policy).error();
            return;
        }
        gateway_ = std::make_unique<http_gateway>(io_, setup_.limits, static_cast<gateway_sink&>(*this), setup_.options.http_require_binding);
        if (auto ok = gateway_->listen(std::move(*policy)); !ok) {
            gateway_error_ = std::move(ok).error();
            gateway_.reset();
            return;
        }
        gateway_port_ = gateway_->port();
    }

    [[nodiscard]] bool accepting() const noexcept override { return is_enabled() && !stopping_; }

    [[nodiscard]] std::chrono::steady_clock::time_point steady_now() const noexcept override {
        return std::chrono::steady_clock::now() + std::chrono::nanoseconds{clock_offset_ns_.load(std::memory_order_relaxed)};
    }

    [[nodiscard]] bool custom_clock() const noexcept override { return setup_.custom_clock; }

    // Pump thread: how far the host's clock is from steady_clock, for the network thread's reads.
    void sample_clock() noexcept {
        if (setup_.custom_clock && setup_.clock) {
            const auto offset = std::chrono::duration_cast<std::chrono::nanoseconds>(setup_.clock() - std::chrono::steady_clock::now());
            clock_offset_ns_.store(offset.count(), std::memory_order_relaxed);
        }
    }

    [[nodiscard]] bool acquire_handshake() noexcept override {
        if (pending_handshakes_ >= setup_.limits.pending_handshakes) {
            return false;
        }
        ++pending_handshakes_;
        return true;
    }

    void release_handshake() noexcept override { --pending_handshakes_; }

    [[nodiscard]] result<security::http_grant> authorize(const security::http_proof& request) override {
        return setup_.http_auth(request, std::chrono::system_clock::now());
    }

    [[nodiscard]] session_id open_http(const security::http_grant& grant, const http_peer& peer) override {
        const session_id id = session_ids_.next();
        auto& identity = io_identities_[grant.identity];
        if (!identity.relay) {
            identity.relay = std::make_shared<cancel_relay>();
        }
        ++identity.sessions;
        ready_sessions_.fetch_add(1, std::memory_order_acq_rel);
        http_sessions_[id] = grant.identity;
        inbound in;
        in.what = inbound::kind::kOpened;
        in.session = id;
        in.identity = grant.identity;
        in.granted = grant.granted;
        in.relay = identity.relay;
        in.peer = peer.address;
        in.platform = "http";
        in.tls = peer.tls;
        (void)to_pump(std::move(in));
        return id;
    }

    void close_http(session_id id, std::string_view name, const error& why) override {
        if (http_sessions_.erase(id) == 0) {
            return;
        }
        ready_sessions_.fetch_sub(1, std::memory_order_acq_rel);
        if (auto identity = io_identities_.find(name); identity != io_identities_.end()) {
            {
                const std::scoped_lock lock{identity->second.relay->mutex};
                identity->second.relay->end(id);
            }
            if (--identity->second.sessions == 0) {
                orphans_.push_back(identity->second.relay);
                io_identities_.erase(identity);
            }
            arm_enforce();
        }
        inbound in;
        in.what = inbound::kind::kClosed;
        in.session = id;
        in.identity = std::string{name};
        in.peer = "http";
        in.reason = why;
        (void)to_pump(std::move(in));
    }

    [[nodiscard]] bool submit_http(session_id id, std::uint64_t req, wire::op code, value body, const http_peer& peer) override {
        inbound in;
        in.session = id;
        in.peer = peer.address; // a logical session has many callers: each request names its own
        in.req = req;
        in.arrival = req; // one logical session: request numbers are the arrival order
        in.code = code;
        in.body = std::move(body);
        return to_pump(std::move(in));
    }

    void cancel_http(session_id id, std::uint64_t target, std::uint64_t upto) override {
        const auto session = http_sessions_.find(id);
        if (session == http_sessions_.end()) {
            return;
        }
        if (const auto identity = io_identities_.find(session->second); identity != io_identities_.end()) {
            const std::scoped_lock lock{identity->second.relay->mutex};
            identity->second.relay->cancel(id, target, upto);
        }
    }

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
        Rhp::subscription script_listener; // the sandbox's script events → host.on_script_event and clients
        std::set<session_id> debuggers;    // sessions that set breakpoints or paused: the last one's end resets the debugger
        session_id profiler;               // started the profiler: its end stops it
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
        std::uint64_t dropped = 0; // events not sent since the last one that was
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
            log(log_level::kInfo, "refusing {}: the host is disabled", link->peer());
            refused(link->peer(), make_error(errc::kDisabled, "the host is disabled", "host"));
            park(std::move(link));
            return;
        }
        if (pending_handshakes_ >= setup_.limits.pending_handshakes) {
            log(log_level::kWarn, "refusing {}: {} handshakes already pending", link->peer(), pending_handshakes_);
            refused(link->peer(), make_error(errc::kLimitExceeded, std::format("{} handshakes already pending", pending_handshakes_), "host"));
            park(std::move(link));
            return;
        }
        std::string peer = link->peer();
        auto wrapped = policy_.wrap(std::move(link));
        if (!wrapped) {
            log(log_level::kWarn, "refusing {}: {}", peer, wrapped.error());
            refused(std::move(peer), std::move(wrapped).error());
            return;
        }
        (void)start_session(std::move(*wrapped));
    }

    // A connection that never got to authenticate (auth_failed, when anyone listens).
    void refused(std::string peer, error why) override {
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
                    log(log_level::kDebug, "dialing {} to resume session {} failed: {}", setup_.ep, resume_id, link.error());
                    redial(resume_id);
                    return;
                }
                it->second.s->resume(std::move(*link));
                return;
            }
            if (!link) {
                log(log_level::kDebug, "dialing {} failed: {}", setup_.ep, link.error());
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
        log(log_level::kInfo, "session {} ({}) lost its link ({}); it may resume within {} ms", s.id(), s.identity(), why, setup_.limits.resume_ms);
        if (reverse_ && s.id() == outgoing_ && !stopping_) {
            attempts_ = 0;
            redial(s.id());
        }
    }

    void on_resumed(session::session& s) override {
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
        log(log_level::kInfo, "session {} from {} ({}) authenticated as {} ({})", s.id(), s.peer(), s.peer_platform(), s.identity(), s.granted());
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

    void on_closed(session::session& s, const error& why) override {
        const session_id id = s.id();
        auto it = sessions_.find(id);
        if (it == sessions_.end()) {
            return;
        }
        const bool was_ready = it->second.ready;
        const std::string identity = it->second.identity;
        if (was_ready) {
            log(log_level::kInfo, "session {} ({}) ended: {}", id, identity, why);
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
                arm_enforce();
            }
            inbound in;
            in.what = inbound::kind::kClosed;
            in.session = id;
            in.identity = identity;
            in.peer = s.peer();
            in.reason = why;
            to_pump(std::move(in));
        } else if (s.handed_over()) {
            --pending_handshakes_; // it only carried a resume: its link went to that session
        } else {
            --pending_handshakes_;
            log(log_level::kInfo, "connection from {} closed before authenticating: {}", s.peer(), why);
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
        {
            const std::scoped_lock lock{ident->second.relay->mutex};
            ident->second.relay->cancel(s.id(), request->target, arrival);
        }
        arm_enforce();
    }

    // Re-applies recorded cancels to whatever runs inside pump() right now (see enforce()), every
    // kEnforceInterval while a cancel is recorded or an orphaned relay still has its sandbox: an idle
    // host doesn't wake up for it.
    void enforce_cancels() {
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

    // A cancel was recorded or a session ended: enforce_cancels() runs again shortly (pump() clears
    // the records once the requests they cover are dealt with).
    void arm_enforce() {
        if (!enforce_armed_) {
            enforce_armed_ = true;
            enforce_timer_.start(kEnforceInterval, [this] { enforce_cancels(); });
        }
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

    bool send_reply(io_session& rec, wire::op code, std::uint64_t req, const value& body) {
        auto sent = rec.s->send(code, wire::envelope_value(req, 0, body));
        if (!sent && sent.error().code == errc::kLimitExceeded && final_reply(code, req)) {
            // Too big for one frame: the request still gets an answer.
            (void)rec.s->send(wire::op::kError, wire::envelope_value(req, 0, Rhp::to_value(sent.error())));
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
            log(log_level::kError, "an event handler threw: {}", ex.what());
        } catch (...) {
            log_text(log_level::kError, "an event handler threw");
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
        pump_session fresh;
        fresh.identity = in.identity;
        fresh.granted = in.granted;
        fresh.peer = in.peer;
        pump_sessions_[in.session] = std::move(fresh);
        auto it = identities_.find(in.identity);
        if (it == identities_.end()) {
            identity_runtime rt;
            rt.name = in.identity;
            rt.relay = in.relay;
            rt.box = std::make_unique<script::sandbox>(sandbox_options_for(in.identity, in.granted));
            for (const auto& [name, fn] : installers_) {
                if (auto ok = fn(*rt.box); !ok) {
                    log(log_level::kWarn, "install {} into identity {}: {}", name, in.identity, ok.error());
                }
            }
            {
                const std::scoped_lock lock{rt.relay->mutex};
                rt.relay->box = rt.box.get();
            }
            rt.script_listener =
                rt.box->on_script_event("*", [this, identity = in.identity](const script::script_event& e) { forward_script_event(identity, e); });
            it = identities_.emplace(in.identity, std::move(rt)).first;
            identity_count_.store(identities_.size(), std::memory_order_release);
            log(log_level::kInfo, "identity {} ({}) has a sandbox", in.identity, in.granted);
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
        if (const auto ps = pump_sessions_.find(in.session); ps != pump_sessions_.end()) {
            for (const std::string& name : ps->second.program_subs) {
                drop_program_sub(name, in.session);
            }
        }
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
        if (rt.debuggers.erase(in.session) != 0 && rt.debuggers.empty()) { // the last debugging session: its breakpoints go, paused scripts run on
            rt.box->debug_reset();
        }
        if (rt.profiler == in.session) {
            rt.profiler = session_id{};
            (void)rt.box->stop_profile();
        }
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
        // Asynchronous calls still running for it: a success arriving later is still taken back.
        if (script::async_leftovers left = rt.box->release_async(); !left.empty()) {
            async_leftovers_.push_back(std::move(left));
        }
        rt.box.reset();
        rt.pinned.clear();
        for (auto& [r, record] : std::exchange(rt.audits, {})) {
            record.outcome = make_error(errc::kCancelled, "the identity was reverted before the request finished", record.op);
            publish(std::move(record));
        }
        log(log_level::kInfo, "identity {} reverted: {} effects undone, {} irreversible, {} failures", rt.name, report.undone, report.irreversible,
            report.failures.size());
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
        log(log_level::kInfo, "identity {} released: {} effects undone, {} pinned modules kept", rt.name, report.undone, rt.pinned.size());
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
            log(log_level::kDebug, "[{}] {}", identity, line);
            route(identity, r, wire::op::kOutput, value{line});
        };
        o.on_emit = [this, identity](request_id r, module_id mod, const value& v) {
            route(identity, r, wire::op::kEmit, Rhp::to_value(wire::emit_message{mod, v}));
        };
        o.on_result = [this, identity](request_id r, const result<script::value_list>& res) { finished(identity, r, res); };
        o.handler_errors = setup_.options.handler_errors;
        o.on_handler_error = [this, identity](const script::handler_failure& f) { handler_failed(identity, f); };
        return o;
    }

    // A script's handler failed: a host event, a log line and an output line for its sessions.
    void handler_failed(const std::string& identity, const script::handler_failure& f) {
        const std::string line =
            std::format("[handler failed] {} ({} {}): {} ({})", f.module_name.empty() ? "?" : f.module_name, f.kind, f.source, f.err, f.action);
        log(log_level::kWarn, "[{}] {}", identity, line);
        route(identity, f.request, wire::op::kOutput, value{line});
        if (wants<event::handler_failed>()) {
            publish(event::handler_failed{now(), identity, f.module_name, std::string{script::to_string(f.kind)}, f.source, f.handler,
                                          std::string{script::to_string(f.action)}, f.err});
        }
    }

    // ---- pump thread: events ------------------------------------------------------------------------

    // An rhp.publish of `identity`'s sandbox: host.on_script_event and the identity's subscribed sessions.
    void forward_script_event(const std::string& identity, const script::script_event& e) {
        if (setup_.script_events != nullptr && setup_.script_events->wants(e.name)) {
            event::script_event copy{now(), identity, std::string{e.module_name}, std::string{e.name}, {e.args.begin(), e.args.end()}};
            try {
                setup_.script_events->publish(copy);
            } catch (const std::exception& ex) {
                log(log_level::kError, "a script event handler threw: {}", ex.what());
            } catch (...) {
                log_text(log_level::kError, "a script event handler threw");
            }
        }
        const auto it = identities_.find(identity);
        if (it == identities_.end()) {
            return;
        }
        for (const session_id s : it->second.sessions) {
            const auto ps = pump_sessions_.find(s);
            if (ps != pump_sessions_.end() && (ps->second.script_subs.contains(e.name) || ps->second.script_subs.contains("*"))) {
                send_event(s, ps->second, e.name, e.module, e.args);
            }
        }
    }

    // One kEvent to one session, at most remote_events_per_pump per pump(); the rest are counted.
    void send_event(session_id s, pump_session& sess, std::string_view name, module_id module, std::span<const value> args) {
        if (sess.sent_this_pump >= setup_.options.remote_events_per_pump) {
            ++sess.dropped;
            return;
        }
        ++sess.sent_this_pump;
        wire::event_message m{std::string{name}, module, value::array{args.begin(), args.end()}, std::exchange(sess.dropped, 0)};
        to_network({s, wire::op::kEvent, 0, Rhp::to_value(m)});
    }

    // C++ lua_events for subscribed sessions (event_listener; attached while any session subscribes).
    [[nodiscard]] std::thread::id listener_thread() const noexcept override { return pump_thread_.load(std::memory_order_acquire); }

    void deliver(std::string_view event, const script::detail::event_args& args) override {
        send_program_event(event, args.values(args.data));
    }

    void enqueue(std::string_view event, const script::detail::event_args& args) noexcept override {
        try {
            const std::uint32_t cap = setup_.limits.event_queue;
            const std::scoped_lock lock{program_mutex_};
            if (cap != 0 && program_inbox_.size() >= cap) {
                return; // each session's next event says nothing about these: they never queued
            }
            program_inbox_.emplace_back(std::string{event}, args.values(args.data));
        } catch (...) { // out of memory: the clients miss this one
        }
    }

    void deliver_program_events() {
        std::vector<std::pair<std::string, std::vector<value>>> queued;
        {
            const std::scoped_lock lock{program_mutex_};
            queued.swap(program_inbox_);
        }
        for (const auto& [event, args] : queued) {
            send_program_event(event, args);
        }
    }

    void send_program_event(std::string_view event, const std::vector<value>& args) {
        const auto subs = program_subs_.find(event);
        if (subs == program_subs_.end()) {
            return;
        }
        for (const session_id s : subs->second) {
            if (const auto ps = pump_sessions_.find(s); ps != pump_sessions_.end()) {
                send_event(s, ps->second, event, module_id{}, args);
            }
        }
    }

    void drop_program_sub(const std::string& name, session_id s) {
        const auto subs = program_subs_.find(name);
        if (subs == program_subs_.end()) {
            return;
        }
        subs->second.erase(s);
        if (!subs->second.empty()) {
            return;
        }
        program_subs_.erase(subs);
        if (const auto attached = program_attached_.find(name); attached != program_attached_.end()) {
            attached->second->detach(this);
            program_attached_.erase(attached);
        }
    }

    // kSubscribe / kUnsubscribe: a C++ event (program-wide) or the identity's script events.
    void subscription_request(pump_session& sess, const inbound& in) {
        auto m = Rhp::from_value<wire::subscribe_request>(in.body);
        if (!m) {
            return reply_error(in.session, in.req, m.error());
        }
        const std::string& name = m->name;
        const std::string_view op = wire::to_string(in.code);
        if (name != "*" && !utils::is_dotted_name(name)) {
            return reply_error(in.session, in.req,
                               make_error(errc::kInvalidArgument, std::format("'{}' is not an event name (dotted lowercase, or *)", name), std::string{op}));
        }
        script::detail::event_state* state = nullptr;
        if (name != "*") {
            auto found = script::detail::find_event(name);
            if (found) {
                state = (*found)->state;
            } else if (found.error().code != errc::kNotFound) {
                return reply_error(in.session, in.req, make_error(found.error().code, found.error().message, std::string{op}));
            }
        }
        if (in.code == wire::op::kUnsubscribe) {
            if (state != nullptr) {
                if (sess.program_subs.erase(name) != 0) {
                    drop_program_sub(name, in.session);
                }
            } else {
                sess.script_subs.erase(name);
            }
            return reply(in.session, in.req, value{});
        }
        if (state != nullptr) {
            if (sess.program_subs.insert(name).second) {
                program_subs_[name].insert(in.session);
                if (!program_attached_.contains(name)) {
                    program_attached_.emplace(name, state);
                    state->attach(this);
                }
            }
        } else {
            sess.script_subs.insert(name);
        }
        reply(in.session, in.req, value{});
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
        if (const auto a = rt.audits.find(r); a != rt.audits.end()) {
            event::script_executed record = std::move(a->second);
            rt.audits.erase(a);
            if (!res) {
                record.outcome = res.error();
            }
            publish(std::move(record));
        }
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
    [[nodiscard]] result<std::string> check_signature(const pump_session& sess, const inbound& in, std::string_view module, std::string_view source,
                                                      const value& signature) {
        if (audit_ != nullptr) {
            audit_->module = module;
            audit_->hash = security::to_hex(security::blake2b_256(source));
        }
        auto who = in.signer ? *in.signer : setup_.verify ? setup_.verify(source, signature)
                                                          : result<std::string>{std::string{}};
        if (!who && signature.is_nil() && sess.granted == role::kObserve) {
            who = std::string{}; // observe can't mutate anything: unsigned code is allowed
        }
        if (who && audit_ != nullptr) {
            audit_->signer = *who;
        }
        return who;
    }

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
    void answer(request_ctx& c, result<value> r) {
        if (!r) {
            reject(c, r.error());
            return;
        }
        reply(c.in.session, c.in.req, std::move(*r));
    }

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

    void request(const inbound& in) {
        const auto ps = pump_sessions_.find(in.session);
        if (ps == pump_sessions_.end()) {
            return; // the session ended before its request ran
        }
        pump_session& sess = ps->second;

        // The audit record of this request, reported when request() returns (reply_error fills in
        // the outcome; a suspended request reports how it started).
        std::optional<event::script_executed> audit;
        if (audited(in.code, in.body) && wants<event::script_executed>()) {
            audit.emplace();
            audit->time = now();
            audit->session = in.session;
            audit->identity = sess.identity;
            audit->granted = sess.granted;
            audit->peer = in.peer.empty() ? sess.peer : in.peer;
            audit->op = std::string{wire::to_string(in.code)};
        }
        audit_ = audit ? &*audit : nullptr;
        audit_session_ = in.session;
        audit_req_ = in.req;
        audit_deferred_ = false;
        const utils::scope_guard report{[&] {
            audit_ = nullptr;
            if (audit && !std::exchange(audit_deferred_, false)) {
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
        request_ctx c{in, sess, rt, *rt.box};
        if (in.code == wire::op::kBlob) {
            return blob(sess, in);
        }
        if (in.code == wire::op::kSubscribe || in.code == wire::op::kUnsubscribe) {
            return subscription_request(sess, in);
        }
        if (is_release_op(in.code)) {
            return op_release(c);
        }
        const running_scope running{*rt.relay, in};
        switch (in.code) {
        case wire::op::kExec: return op_exec(c);
        case wire::op::kLoad: return op_load(c);
        case wire::op::kCall: return op_call(c);
        case wire::op::kReload:
        case wire::op::kRollback: return op_reload(c);
        case wire::op::kUnload:
        case wire::op::kRevert:
        case wire::op::kStatus:
        case wire::op::kPin:
        case wire::op::kUnpin: return op_module(c);
        case wire::op::kCheckpoint:
        case wire::op::kRevertTo: return op_tag(c);
        case wire::op::kRevertAll: return op_revert_all(c);
        case wire::op::kList:
        case wire::op::kDescribe: return op_list(c);
        case wire::op::kTunables: return op_tunables(c);
        case wire::op::kTune: return op_tune(c);
        case wire::op::kProfile: return op_profile(c);
        case wire::op::kDebug: return op_debug(c);
        default:
            return reject(c, make_error(errc::kInvalidArgument, std::format("{} is not supported by this host", in.code), std::string{wire::to_string(in.code)}));
        }
    }

    // ---- pump thread: one function per group of ops (request() has checked role, identity and cancels) ----

    // release_apply / confirm / deactivate / status, revoke: the served release manager answers.
    void op_release(request_ctx& c) {
        if (!releases_.handle) {
            return reject(c, make_error(errc::kNotFound, "this host serves no releases (host.serve)", std::string{wire::to_string(c.in.code)}));
        }
        answer(c, releases_.handle(c.in.code, c.in.body));
    }

    void op_exec(request_ctx& c) {
        auto m = decode<wire::exec_request>(c);
        if (!m) {
            return;
        }
        if (auto who = check_signature(c.sess, c.in, "", m->source, m->signature); !who) {
            return reject(c, who.error());
        }
        run_tracked(c, {}, [&]() -> result<value> {
            auto r = c.box.exec(m->source, m->chunk);
            if (!r) {
                return std::unexpected{std::move(r).error()};
            }
            return value{std::move(*r)}; // a value_list is a value::array
        });
    }

    void op_load(request_ctx& c) {
        auto m = decode<wire::load_request>(c);
        if (!m) {
            return;
        }
        if (auto who = check_signature(c.sess, c.in, m->name, m->source, m->signature); !who) {
            return reject(c, who.error());
        }
        // The module id is only known once load() returns: track it through `loaded` (a load of a
        // loaded name is a reload of that module).
        module_id loaded;
        const auto existing = c.box.find(m->name);
        const request_id before = c.box.last_request();
        run_tracked(c, existing ? *existing : module_id{}, [&]() -> result<value> {
            auto r = c.box.load(m->name, m->source);
            if (!r) {
                return std::unexpected{std::move(r).error()};
            }
            loaded = *r;
            return Rhp::to_value(*r);
        });
        if (const request_id after = c.box.last_request(); after != before) {
            if (const auto w = c.rt.waiting.find(after); w != c.rt.waiting.end()) {
                w->second.module = loaded;
            }
        }
    }

    void op_call(request_ctx& c) {
        auto m = decode<wire::call_request>(c);
        if (!m) {
            return;
        }
        if (audit_ != nullptr) {
            audit_->module = ref_text(m->module);
        }
        auto mod = resolve(c.box, m->module);
        if (!mod) {
            return reject(c, mod.error());
        }
        run_tracked(c, *mod, [&]() -> result<value> {
            auto r = c.box.call(*mod, m->function, m->args);
            if (!r) {
                return std::unexpected{std::move(r).error()};
            }
            return value{value::array(std::make_move_iterator(r->begin()), std::make_move_iterator(r->end()))};
        });
    }

    // reload (signed new source) and rollback (to an earlier revision): both answer the revision.
    void op_reload(request_ctx& c) {
        std::optional<wire::reload_request> reload;
        std::optional<wire::rollback_request> rollback;
        if (c.in.code == wire::op::kReload) {
            reload = decode<wire::reload_request>(c);
            if (!reload) {
                return;
            }
            if (auto who = check_signature(c.sess, c.in, ref_text(reload->module), reload->source, reload->signature); !who) {
                return reject(c, who.error());
            }
        } else {
            rollback = decode<wire::rollback_request>(c);
            if (!rollback) {
                return;
            }
            if (audit_ != nullptr) {
                audit_->module = ref_text(rollback->module);
            }
        }
        auto mod = resolve(c.box, reload ? reload->module : rollback->module);
        if (!mod) {
            return reject(c, mod.error());
        }
        const module_id target = *mod;
        run_tracked(c, target, [&]() -> result<value> {
            auto r = reload ? c.box.reload(target, reload->source)
                            : c.box.rollback(target, rollback->steps > std::numeric_limits<std::size_t>::max() ? std::numeric_limits<std::size_t>::max()
                                                                                                               : static_cast<std::size_t>(rollback->steps));
            if (!r) {
                return std::unexpected{std::move(r).error()};
            }
            return Rhp::to_value(*r);
        });
    }

    // unload, revert, status, pin, unpin: one module of the identity.
    void op_module(request_ctx& c) {
        const inbound& in = c.in;
        wire::module_ref ref;
        bool forced = false;
        if (in.code == wire::op::kUnload) {
            auto m = decode<wire::unload_request>(c);
            if (!m) {
                return;
            }
            ref = std::move(m->module);
            forced = m->force;
        } else {
            auto m = decode<wire::module_request>(c);
            if (!m) {
                return;
            }
            ref = std::move(m->module);
        }
        if (audit_ != nullptr) {
            audit_->module = ref_text(ref);
        }
        auto mod = resolve(c.box, ref);
        if (!mod) {
            return reject(c, mod.error());
        }
        const auto info = c.box.status(*mod);
        if (!info) {
            return reject(c, make_error(errc::kNotFound, std::format("no module {}", *mod), std::string{wire::to_string(in.code)}));
        }
        if (in.code == wire::op::kStatus) {
            return answer(c, Rhp::to_value(describe(*info, c.rt.pinned.contains(*mod))));
        }
        if (in.code == wire::op::kPin || in.code == wire::op::kUnpin) {
            return op_pin(c, *mod, *info);
        }
        if (c.rt.pinned.contains(*mod)) {
            return reject(c, make_error(errc::kForbidden, std::format("module {} is pinned: unpin it first", info->name), std::string{wire::to_string(in.code)}));
        }
        auto r = in.code == wire::op::kRevert ? c.box.revert(*mod) : forced ? c.box.unload(*mod, script::force)
                                                                            : c.box.unload(*mod);
        if (!r) {
            return reject(c, r.error());
        }
        answer(c, Rhp::to_value(summarize(*r)));
    }

    // pin / unpin of a module op_module found.
    void op_pin(request_ctx& c, module_id mod, const script::module_info& info) {
        if (info.scratch) {
            return reject(c, make_error(errc::kInvalidArgument, "the scratch module can't be pinned (load a module)", std::string{wire::to_string(c.in.code)}));
        }
        identity_runtime& rt = c.rt;
        const bool pinning = c.in.code == wire::op::kPin;
        if (pinning) {
            rt.pinned.insert(mod);
        } else {
            rt.pinned.erase(mod);
        }
        {
            // Its requests suspended right now outlive their sessions from now on (or stop doing so).
            const std::scoped_lock lock{rt.relay->mutex};
            for (const auto& [r, p] : rt.waiting) {
                if (p.module == mod) {
                    if (const auto s = rt.relay->suspended.find({p.session.value(), p.req}); s != rt.relay->suspended.end()) {
                        s->second.pinned = pinning;
                    }
                }
            }
        }
        log(log_level::kInfo, "{} {} module {} ({})", c.sess.identity, pinning ? "pinned" : "unpinned", info.name, mod);
        answer(c, value{});
    }

    // checkpoint / revert_to: a named mark in the identity's journal.
    void op_tag(request_ctx& c) {
        auto m = decode<wire::tag_request>(c);
        if (!m) {
            return;
        }
        if (audit_ != nullptr) {
            audit_->module = m->tag;
        }
        if (c.in.code == wire::op::kCheckpoint) {
            auto r = c.box.checkpoint(m->tag);
            if (!r) {
                return reject(c, r.error());
            }
            return answer(c, value{});
        }
        if (!c.rt.pinned.empty()) {
            // revert_to undoes every effect after the mark, whatever module made it: it would
            // hollow out pinned modules, which only unpin + revert / unload or revert_all may undo.
            return reject(c, make_error(errc::kForbidden, "this identity has pinned modules: unpin them before revert_to", "revert_to"));
        }
        auto r = c.box.revert_to(m->tag);
        if (!r) {
            return reject(c, r.error());
        }
        answer(c, Rhp::to_value(summarize(*r)));
    }

    // The panic button: every module of every identity, pinned ones included.
    void op_revert_all(request_ctx& c) {
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
        log(log_level::kWarn, "revert_all by {}: {} effects undone", c.sess.identity, total.undone);
        answer(c, Rhp::to_value(summarize(total)));
    }

    // list (the identity's modules) and describe (LuaLS stubs of what it can use).
    void op_list(request_ctx& c) {
        if (c.in.code == wire::op::kDescribe) {
            return answer(c, value{c.box.stubs()});
        }
        value::array modules;
        for (const script::module_info& m : c.box.list()) {
            modules.push_back(Rhp::to_value(describe(m, c.rt.pinned.contains(m.id))));
        }
        answer(c, value{std::move(modules)});
    }

    void op_tunables(request_ctx& c) {
        auto m = decode<wire::tunables_request>(c);
        if (!m) {
            return;
        }
        auto list = c.box.tunables(m->prefix);
        if (!list) {
            return reject(c, list.error());
        }
        value::array out;
        out.reserve(list->size());
        for (script::tunable_info& t : *list) {
            out.push_back(Rhp::to_value(wire::tunable_message{std::move(t.path), std::move(t.type), std::move(t.current), t.writable, t.min, t.max, t.step,
                                                              std::move(t.unit), std::move(t.doc)}));
        }
        answer(c, value{std::move(out)});
    }

    void op_tune(request_ctx& c) {
        auto m = decode<wire::tune_request>(c);
        if (!m) {
            return;
        }
        if (auto r = c.box.tune(m->path, m->to); !r) {
            return reject(c, r.error());
        }
        answer(c, value{});
    }

    void op_profile(request_ctx& c) {
        auto m = decode<wire::profile_request>(c);
        if (!m) {
            return;
        }
        if (m->action == "start") {
            const script::profile_options options{m->interval, static_cast<std::size_t>(m->max_depth), static_cast<std::size_t>(m->max_stacks)};
            if (auto r = c.box.start_profile(options); !r) {
                return reject(c, r.error());
            }
            c.rt.profiler = c.in.session;
            return answer(c, Rhp::to_value(profile_message(c.box.profile(), setup_.limits.max_frame)));
        }
        if (m->action == "read") {
            return answer(c, Rhp::to_value(profile_message(c.box.profile(), setup_.limits.max_frame)));
        }
        if (m->action == "stop") {
            c.rt.profiler = session_id{};
            return answer(c, Rhp::to_value(profile_message(c.box.stop_profile(), setup_.limits.max_frame)));
        }
        reject(c, make_error(errc::kInvalidArgument, std::format("profile action is start, read or stop, not '{}'", m->action), "profile"));
    }

    void op_debug(request_ctx& c) {
        auto m = decode<wire::debug_request>(c);
        if (!m) {
            return;
        }
        auto r = debug(c.rt, c.box, c.in.session, *m);
        if (!r) {
            return reject(c, r.error());
        }
        answer(c, Rhp::to_value(*r));
    }

    // One debug request of `session` against its identity's sandbox.
    result<wire::debug_reply> debug(identity_runtime& rt, script::sandbox& box, session_id session, const wire::debug_request& m) {
        wire::debug_reply out;
        const request_id req{m.request};
        const std::string_view action = m.action;
        if (action == "break") {
            auto lines = box.set_breakpoints(m.source, m.lines);
            if (!lines) {
                return std::unexpected{std::move(lines).error()};
            }
            out.lines = std::move(*lines);
            rt.debuggers.insert(session);
        } else if (action == "pause") {
            box.debug_pause();
            rt.debuggers.insert(session);
        } else if (action == "continue" || action == "into" || action == "over" || action == "out") {
            const script::step_mode mode = action == "into"   ? script::step_mode::kInto
                                           : action == "over" ? script::step_mode::kOver
                                           : action == "out"  ? script::step_mode::kOut
                                                              : script::step_mode::kContinue;
            if (auto r = box.debug_resume(req, mode); !r) {
                return std::unexpected{std::move(r).error()};
            }
        } else if (action == "paused") {
            for (const script::debug_stop& p : box.paused()) {
                out.paused.push_back(wire::debug_stop_message{p.request.value(), p.label, p.reason, p.source, p.line, p.module.value()});
            }
        } else if (action == "stack") {
            auto frames = box.debug_stack(req);
            if (!frames) {
                return std::unexpected{std::move(frames).error()};
            }
            for (script::debug_frame& f : *frames) {
                out.frames.push_back(wire::debug_frame_message{f.level, std::move(f.name), std::move(f.what), std::move(f.source), f.line, f.defined});
            }
        } else if (action == "variables") {
            const auto scope = parse_scope(m.scope);
            if (!scope) {
                return fail(errc::kInvalidArgument, std::format("scope is locals, upvalues or globals, not '{}'", m.scope), "debug");
            }
            auto vars = box.debug_variables(req, m.frame, *scope, m.path);
            if (!vars) {
                return std::unexpected{std::move(vars).error()};
            }
            for (const script::debug_variable& v : *vars) {
                out.variables.push_back(variable_message(v));
            }
        } else if (action == "evaluate") {
            auto v = box.debug_evaluate(req, m.frame, m.expression);
            if (!v) {
                return std::unexpected{std::move(v).error()};
            }
            out.variables.push_back(variable_message(*v));
        } else if (action == "reset") {
            box.debug_reset();
            rt.debuggers.clear();
        } else {
            return fail(errc::kInvalidArgument, std::format("'{}' is not a debug action", m.action), "debug");
        }
        return out;
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
                log(log_level::kInfo, "blob '{}' from {} abandoned at {} of {} bytes", sess.blob->name, sess.identity, sess.blob->data.size(), sess.blob->total);
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
        log(log_level::kInfo, "blob '{}' ({} bytes) from {} for sink {}: {}", t.name, t.total, sess.identity, t.sink, verdict ? "taken" : verdict.error().message);
        const std::uint64_t id = t.id;
        sess.blob.reset();
        if (!verdict) {
            sess.failed_transfer = id;
            reply_error(in.session, in.req, verdict.error());
            return;
        }
        reply(in.session, in.req, value{});
    }

    // Thread-safe: both threads log. The level check takes no lock (core::logger::enabled is
    // thread-safe) and comes before formatting; writes are serialized.
    [[nodiscard]] bool log_on(log_level level) const { return setup_.log && setup_.log_enabled && setup_.log_enabled(level); }

    template <class... Args>
    void log(log_level level, std::format_string<Args...> fmt, Args&&... args) {
        if (log_on(level)) {
            write_log(level, std::format(fmt, std::forward<Args>(args)...));
        }
    }

    void log_text(log_level level, std::string_view message) {
        if (log_on(level)) {
            write_log(level, message);
        }
    }

    void write_log(log_level level, std::string_view message) {
        const std::scoped_lock lock{log_mutex_};
        setup_.log(level, message);
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
    std::size_t pending_handshakes_ = 0;
    std::deque<std::unique_ptr<net::link>> closing_links_;
    std::deque<inbound> inbox_backlog_;
    std::atomic<bool> inbox_backlog_waiting_{false};     // read by pump() to decide whether to wake us
    std::vector<std::shared_ptr<cancel_relay>> orphans_; // identities whose last session ended
    net::io_context::timer enforce_timer_{io_};
    bool enforce_armed_ = false; // network thread
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

result<std::uint16_t> gateway_port(const engine& e) {
    return e.gateway_port();
}

result<void> advertise(engine& e, net::advertise_options options) {
    return e.advertise(std::move(options));
}

result<void> discovery_status(engine& e) {
    return e.discovery_status();
}

result<void> install(engine& e, std::string_view name, installer fn) {
    return e.install(name, fn);
}

result<void> add_blob_sink(engine& e, std::string_view name, blob_fn fn, role need) {
    return e.add_blob_sink(name, std::move(fn), need);
}

result<void> serve_releases(engine& e, release_bridge bridge) {
    return e.serve_releases(std::move(bridge));
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
