#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/client/detail/engine.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/session/session.hpp>
#include <rhp/wire/messages.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::client_detail {

namespace {

using clock = std::chrono::steady_clock;

// While a zero_threads client waits, it runs the network in slices this long.
constexpr std::chrono::milliseconds kPollSlice{5};
constexpr std::chrono::milliseconds kCloseWait{1'000};
// Room a blob chunk leaves for the envelope and the frame around its bytes.
constexpr std::size_t kChunkOverhead = 1024;

// A fresh idempotency key: 63 random bits (wire integers are signed 64-bit), never 0.
[[nodiscard]] std::uint64_t random_key() {
    constexpr std::uint64_t kMask = 0x7fff'ffff'ffff'ffffu;
    if (auto bytes = platform::random_array<8>()) {
        std::uint64_t k = 0;
        for (const std::byte b : *bytes) {
            k = (k << 8) | std::to_integer<std::uint64_t>(b);
        }
        k &= kMask;
        return k != 0 ? k : 1;
    }
    return (static_cast<std::uint64_t>(clock::now().time_since_epoch().count()) & kMask) | 1u;
}

} // namespace

class engine final : private session::handler {
public:
    explicit engine(setup s)
        : setup_(std::move(s)),
          reverse_(setup_.ep.direction == net::endpoint::mode::kListen),
          owned_io_(setup_.shared_io == nullptr ? std::make_unique<net::io_context>() : nullptr),
          io_(setup_.shared_io != nullptr ? *setup_.shared_io : *owned_io_) {
        options_.limits = setup_.limits;
        options_.codec = setup_.codec;
        options_.platform = std::string{platform::kOsName};
        options_.resumable = setup_.limits.resume_ms != 0;
        if (auto policy = session::channel_policy::make(setup_.ep, setup_.transport.network, setup_.tls, setup_.options.tls)) {
            policy_ = std::move(*policy);
        } else {
            policy_error_ = std::move(policy).error();
        }
        if (auto seed = platform::random_array<8>()) {
            std::uint64_t k = 0;
            for (const std::byte b : *seed) {
                k = (k << 8) | std::to_integer<std::uint64_t>(b);
            }
            rng_.seed(k);
        }
    }

    ~engine() {
        // The network is stopped, was never on another thread, or (a shared reactor) this runs on
        // its thread: plain teardown. Work still queued on a shared reactor finds `alive_` false.
        *alive_ = false;
        timers_.clear();
        redial_timer_.cancel();
        others_.clear();
        session_.reset();
        listener_.reset();
    }

    engine(const engine&) = delete;
    engine& operator=(const engine&) = delete;

    result<void> connect() {
        std::unique_lock lock{mutex_};
        if (ready_) {
            return {};
        }
        if (closed_) {
            return fail(failure_.value_or(make_error(errc::kTransport, "the client is closed", "client")));
        }
        start(lock);
        if (reverse_) {
            wait(lock, clock::time_point::max(), [this] { return listen_done_; });
            if (closed_) {
                return fail(*failure_);
            }
        }
        const auto deadline = clock::now() + setup_.options.connect_timeout;
        wait(lock, deadline, [this] { return ready_ || closed_; });
        if (ready_) {
            return {};
        }
        if (closed_) {
            return fail(failure_.value_or(make_error(errc::kTransport, "the session ended", "client")));
        }
        if (reverse_) {
            return fail(errc::kTimeout, std::format("no host dialed in to {} within {} ms", setup_.ep, setup_.options.connect_timeout.count()), "client.connect");
        }
        return fail(errc::kTimeout, std::format("no session with {} within {} ms", setup_.ep, setup_.options.connect_timeout.count()), "client.connect");
    }

    result<std::uint16_t> port() {
        if (!reverse_) {
            return fail(errc::kInvalidArgument, "only a client that listens (reverse mode) has a port", "client.port");
        }
        std::unique_lock lock{mutex_};
        if (closed_) {
            return fail(failure_.value_or(make_error(errc::kTransport, "the client is closed", "client")));
        }
        start(lock);
        wait(lock, clock::time_point::max(), [this] { return listen_done_; });
        if (listen_error_) {
            return fail(*listen_error_);
        }
        if (closed_) {
            return fail(failure_.value_or(make_error(errc::kTransport, "the client is closed", "client")));
        }
        return listen_port_;
    }

    result<value> request(wire::op code, value body) {
        if (auto ok = connect(); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        std::unique_lock lock{mutex_};
        const std::uint64_t req = ++last_req_;
        pending_[req];
        const wire::envelope env{req, random_key(), std::move(body)};
        post([this, code, message = Rhp::to_value(env), req] { send_or_queue(code, message, req); });
        const bool timed = setup_.options.request_timeout.count() > 0;
        const auto deadline = timed ? clock::now() + setup_.options.request_timeout : clock::time_point::max();
        wait(lock, deadline, [this, req] { return pending_.at(req).done.has_value(); });
        auto node = pending_.extract(req);
        if (!node.mapped().done) {
            // Timed out: stop it on the host too.
            lock.unlock();
            post_cancel(req);
            return fail(errc::kTimeout, std::format("no reply to {} within {} ms", code, setup_.options.request_timeout.count()), "client");
        }
        return std::move(*node.mapped().done);
    }

    result<std::uint64_t> subscribe(std::string_view name, remote_event_fn fn) {
        if (!fn) {
            return fail(errc::kInvalidArgument, "client.on needs a callback", "client.on");
        }
        std::uint64_t id = 0;
        bool first = false;
        {
            const std::scoped_lock lock{mutex_};
            id = ++last_listener_;
            listeners_.emplace(id, listener_entry{std::string{name}, std::make_shared<remote_event_fn>(std::move(fn))});
            first = ++remote_names_[std::string{name}] == 1;
        }
        if (first) {
            if (auto r = request(wire::op::kSubscribe, Rhp::to_value(wire::subscribe_request{std::string{name}})); !r) {
                (void)forget_listener(id);
                return std::unexpected{std::move(r).error()};
            }
        }
        return id;
    }

    result<void> unsubscribe(std::uint64_t id) {
        auto last = forget_listener(id);
        if (!last) {
            return std::unexpected{std::move(last).error()};
        }
        if (!last->empty()) {
            if (auto r = request(wire::op::kUnsubscribe, Rhp::to_value(wire::subscribe_request{*last})); !r) {
                return std::unexpected{std::move(r).error()};
            }
        }
        return {};
    }

    // Removes a callback; the name when it was the last one for it (empty otherwise).
    result<std::string> forget_listener(std::uint64_t id) {
        const std::scoped_lock lock{mutex_};
        const auto it = listeners_.find(id);
        if (it == listeners_.end()) {
            return fail(errc::kNotFound, std::format("no event callback {}", id), "client.off");
        }
        std::string name = std::move(it->second.name);
        listeners_.erase(it);
        const auto count = remote_names_.find(name);
        if (count != remote_names_.end() && --count->second == 0) {
            remote_names_.erase(count);
            return name;
        }
        return std::string{};
    }

    std::uint64_t submit(wire::op code, value body, completion done) {
        std::unique_lock lock{mutex_};
        if (closed_) {
            const error why = failure_.value_or(make_error(errc::kTransport, "the client is closed", "client"));
            lock.unlock();
            done(std::unexpected{why});
            return 0;
        }
        const std::uint64_t req = ++last_req_;
        pending_[req].callback = std::move(done);
        start(lock);
        lock.unlock();
        const wire::envelope env{req, random_key(), std::move(body)};
        post([this, code, message = Rhp::to_value(env), req] {
            if (setup_.options.request_timeout.count() > 0) {
                auto& t = timers_[req];
                t = std::make_unique<net::io_context::timer>(io_);
                t->start(setup_.options.request_timeout, [this, req, code] {
                    timers_.erase(req);
                    if (complete(req, fail(errc::kTimeout, std::format("no reply to {} within {} ms", code, setup_.options.request_timeout.count()), "client"))) {
                        send_cancel(req);
                    }
                });
            }
            send_or_queue(code, message, req);
        });
        return req;
    }

    result<void> blob(std::string_view sink, std::string_view name, std::span<const std::byte> data) {
        if (auto ok = connect(); !ok) {
            return ok;
        }
        const std::size_t frame_room = setup_.limits.max_frame > kChunkOverhead * 2 ? setup_.limits.max_frame - kChunkOverhead : kChunkOverhead;
        const std::size_t chunk = std::clamp<std::size_t>(setup_.options.blob_chunk, 1, frame_room);
        const std::size_t window = std::max<std::size_t>(setup_.options.blob_window, 1);
        const std::uint64_t transfer = random_key();

        // Chunks go out while fewer than `window` are unanswered; the first error stops the rest.
        struct progress {
            std::mutex mutex;
            std::condition_variable cv;
            std::size_t in_flight = 0;
            std::optional<error> failure;
        };
        auto state = std::make_shared<progress>();
        const auto done = [state](result<value> r) {
            {
                const std::scoped_lock lock{state->mutex};
                --state->in_flight;
                if (!r && !state->failure) {
                    state->failure = std::move(r).error();
                }
            }
            state->cv.notify_all();
        };
        // Waits until `pred` (running the network with io<zero_threads>).
        const auto wait_until = [&](auto pred) {
            std::unique_lock lock{state->mutex};
            if (setup_.io_thread) {
                state->cv.wait(lock, pred);
                return;
            }
            while (!pred()) {
                lock.unlock();
                io_.run_one_for(kPollSlice);
                lock.lock();
            }
        };

        std::size_t offset = 0;
        do {
            wait_until([&] { return state->in_flight < window || state->failure.has_value(); });
            {
                const std::scoped_lock lock{state->mutex};
                if (state->failure) {
                    break;
                }
                ++state->in_flight;
            }
            const std::size_t n = std::min(chunk, data.size() - offset);
            wire::blob_chunk c;
            c.transfer = transfer;
            c.sink = sink;
            c.name = name;
            c.total = data.size();
            c.offset = offset;
            c.data.assign(data.begin() + static_cast<std::ptrdiff_t>(offset), data.begin() + static_cast<std::ptrdiff_t>(offset + n));
            offset += n;
            (void)submit(wire::op::kBlob, Rhp::to_value(c), done);
        } while (offset < data.size());
        wait_until([&] { return state->in_flight == 0; });
        const std::scoped_lock lock{state->mutex};
        if (state->failure) {
            return fail(*state->failure);
        }
        return {};
    }

    void cancel(std::uint64_t target) noexcept {
        try {
            post_cancel(target);
        } catch (...) { // out of memory: nothing was sent
        }
    }

    void close() noexcept {
        try {
            {
                const std::scoped_lock lock{mutex_};
                if (closed_) {
                    return;
                }
                closing_ = true;
                if (!started_) {
                    // Nothing was dialed or listened on: just closed for good.
                    closed_ = true;
                    listen_done_ = true;
                    failure_ = make_error(errc::kCancelled, "the client closed", "client");
                    return;
                }
            }
            post([this] {
                listener_.reset();
                if (session_ != nullptr) {
                    session_->close(make_error(errc::kCancelled, "the client closed", "client"));
                } else {
                    mark_closed(make_error(errc::kCancelled, "the client closed", "client"));
                }
            });
            std::unique_lock lock{mutex_};
            wait(lock, clock::now() + kCloseWait, [this] { return closed_; });
        } catch (...) { // the destructor tears everything down regardless
        }
    }

    void run_io(std::stop_token stop) {
        if (owned_io_ != nullptr) {
            io_.run(std::move(stop)); // a shared reactor is run by its owner
        }
    }

    void poll() {
        if (!setup_.io_thread) {
            io_.poll();
        }
    }

    [[nodiscard]] std::function<void(std::chrono::milliseconds)> pump() {
        if (setup_.io_thread) {
            return {};
        }
        return [this](std::chrono::milliseconds slice) { io_.run_one_for(slice); };
    }

    [[nodiscard]] session_info info() const {
        const std::scoped_lock lock{mutex_};
        auto snapshot = info_;
        snapshot.closed = closed_;
        return snapshot;
    }

private:
    struct call {
        std::optional<result<value>> done; // a blocking request() waits for this
        completion callback;               // an async call gets this called instead
    };

    // Under the mutex: dial (or, in reverse mode, listen) once.
    void start(std::unique_lock<std::mutex>&) {
        if (started_) {
            return;
        }
        started_ = true;
        if (reverse_) {
            post([this] { listen(); });
        } else {
            post([this] { dial(); });
        }
    }

    // Waits on the condition; a zero_threads client runs the network meanwhile.
    template <class Pred>
    bool wait(std::unique_lock<std::mutex>& lock, clock::time_point deadline, Pred done) {
        if (setup_.io_thread) {
            if (deadline == clock::time_point::max()) {
                cv_.wait(lock, done); // no wait_until(max): some libraries overflow converting it
                return true;
            }
            return cv_.wait_until(lock, deadline, done);
        }
        while (!done()) {
            const auto now = clock::now();
            if (now >= deadline) {
                return false;
            }
            lock.unlock();
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            io_.run_one_for(left < kPollSlice ? left : kPollSlice);
            lock.lock();
        }
        return true;
    }

    void post_cancel(std::uint64_t target) {
        post([this, target] { send_cancel(target); });
    }

    // Runs `fn` on the network thread, unless this engine is gone by then (a shared reactor
    // outlives the engines on it, so work queued for one can run after it was destroyed).
    template <class F>
    void post(F fn) {
        io_.post([alive = std::weak_ptr<bool>{alive_}, fn = std::move(fn)]() mutable {
            if (const auto still = alive.lock(); still != nullptr && *still) {
                fn();
            }
        });
    }

    [[nodiscard]] static bool gone(const std::weak_ptr<bool>& alive) noexcept {
        const auto still = alive.lock();
        return still == nullptr || !*still;
    }

    // ---- network thread ------------------------------------------------------------------------------

    // Cancels `target` (0 = everything): requests still queued for the session never went out, so
    // they are dropped here (and answered kCancelled); the host is told about the rest.
    void send_cancel(std::uint64_t target) {
        std::vector<std::uint64_t> dropped;
        std::erase_if(queued_, [&](const queued_request& q) {
            if (target == 0 || q.req == target) {
                dropped.push_back(q.req);
                return true;
            }
            return false;
        });
        for (const std::uint64_t req : dropped) {
            drop_timer(req);
            (void)complete(req, fail(errc::kCancelled, "cancelled before it was sent", "client"));
        }
        if (session_ != nullptr && session_->usable()) {
            std::uint64_t req = 0;
            {
                const std::scoped_lock lock{mutex_};
                req = ++last_req_;
            }
            (void)session_->send(wire::op::kCancel, Rhp::to_value(wire::envelope{req, 0, Rhp::to_value(wire::cancel_request{target})}));
        }
    }

    // Sends now, or holds the request until the session is ready (async calls made before it was).
    void send_or_queue(wire::op code, const value& message, std::uint64_t req) {
        {
            // Answered already (timed out, cancelled, or failed with its session): it must not run.
            const std::scoped_lock lock{mutex_};
            const auto it = pending_.find(req);
            if (it == pending_.end() || it->second.done.has_value()) {
                return;
            }
        }
        if (session_ != nullptr && ready_ && session_->usable()) {
            // Ready, or detached and resuming: the session queues it and resends it when back.
            if (auto sent = session_->send(code, message); !sent) {
                drop_timer(req);
                complete(req, std::unexpected{std::move(sent).error()});
            }
            return;
        }
        std::optional<error> gone;
        {
            const std::scoped_lock lock{mutex_};
            if (closed_) {
                gone = failure_.value_or(make_error(errc::kTransport, "the session ended", "client"));
            }
        }
        if (gone) {
            drop_timer(req);
            complete(req, std::unexpected{std::move(*gone)});
            return;
        }
        queued_.push_back({code, message, req});
    }

    void dial() {
        if (policy_error_) {
            mark_closed(*policy_error_);
            return;
        }
        setup_.transport.dial(io_, policy_.transport_endpoint(), [this, alive = std::weak_ptr<bool>{alive_}](result<std::unique_ptr<net::link>> link) {
            if (gone(alive)) {
                return; // the engine was destroyed while dialing (shared reactor): the link is dropped
            }
            if (link) {
                if (auto wrapped = policy_.wrap(std::move(*link)); wrapped) {
                    link = std::move(*wrapped);
                } else {
                    link = std::unexpected{std::move(wrapped).error()};
                }
            }
            if (!link) {
                mark_closed(std::move(link).error());
                return;
            }
            {
                const std::scoped_lock lock{mutex_};
                if (closed_ || closing_) {
                    return; // close() came first: drop the new link
                }
            }
            session_ = std::make_unique<session::session>(io_, std::move(*link), setup_.begin_handshake(), static_cast<session::handler&>(*this), options_);
            session_->start();
        });
    }

    // ---- resume (dialing side) ---------------------------------------------------------------------

    void on_detached(session::session& s, const error&) override {
        if (reverse_ || &s != session_.get()) {
            return; // a listening client waits for its host to dial back in
        }
        redial();
    }

    // Capped exponential backoff with full jitter (the first try comes quickly).
    void redial() {
        const std::uint32_t lo = setup_.limits.backoff_min_ms == 0 ? 1 : setup_.limits.backoff_min_ms;
        const std::uint32_t hi = setup_.limits.backoff_max_ms < lo ? lo : setup_.limits.backoff_max_ms;
        const std::uint64_t ceiling = attempts_ == 0 ? 50 : std::min<std::uint64_t>(hi, static_cast<std::uint64_t>(lo) << std::min<std::uint32_t>(attempts_, 20));
        ++attempts_;
        std::uniform_int_distribution<std::uint64_t> pick{1, ceiling};
        redial_timer_.start(std::chrono::milliseconds{pick(rng_)}, [this] {
            if (session_ == nullptr || session_->current() != session::state::kDetached) {
                return;
            }
            setup_.transport.dial(io_, policy_.transport_endpoint(), [this, alive = std::weak_ptr<bool>{alive_}](result<std::unique_ptr<net::link>> link) {
                if (gone(alive) || session_ == nullptr || session_->current() != session::state::kDetached) {
                    return; // closed meanwhile: the link is dropped
                }
                if (link) {
                    if (auto wrapped = policy_.wrap(std::move(*link)); wrapped) {
                        link = std::move(*wrapped);
                    } else {
                        link = std::unexpected{std::move(wrapped).error()};
                    }
                }
                if (!link) {
                    redial();
                    return;
                }
                session_->resume(std::move(*link));
            });
        });
    }

    void on_resumed(session::session& s) override {
        attempts_ = 0;
        const std::scoped_lock lock{mutex_};
        ++info_.resumes;
        info_.tls = s.encrypted();
    }

    // Reverse mode: a new connection asks to continue the session it lost.
    session::session* resume_target(session::session& fresh, session_id id) override {
        if (!reverse_ || session_ == nullptr || session_.get() == &fresh || session_->id() != id) {
            return nullptr;
        }
        return session_.get();
    }

    // Reverse mode: listen, and serve one host at a time.
    void listen() {
        if (policy_error_) {
            {
                const std::scoped_lock lock{mutex_};
                listen_done_ = true;
                listen_error_ = *policy_error_;
            }
            mark_closed(*policy_error_);
            return;
        }
        auto l = setup_.transport.listen(io_, policy_.transport_endpoint(), [this, alive = std::weak_ptr<bool>{alive_}](std::unique_ptr<net::link> link) {
            if (!gone(alive)) {
                accept(std::move(link));
            }
        });
        {
            const std::scoped_lock lock{mutex_};
            listen_done_ = true;
            if (!l) {
                listen_error_ = l.error();
            } else {
                listen_port_ = static_cast<std::uint16_t>((*l)->port());
            }
        }
        if (!l) {
            mark_closed(std::move(l).error());
            return;
        }
        listener_ = std::move(*l);
        cv_.notify_all();
    }

    void park(std::unique_ptr<net::link> link) {
        link->close();
        parked_.push_back(std::move(link));
        if (parked_.size() > 8) {
            parked_.pop_front();
        }
    }

    // Reverse mode. With no session the connection becomes it; with one, it may be that session's
    // host coming back (a resume) or, once that session is detached, a new session of a restarted
    // host: it waits as a candidate (a few at most) until its first frame tells.
    void accept(std::unique_ptr<net::link> link) {
        bool refuse = false;
        {
            const std::scoped_lock lock{mutex_};
            refuse = closed_ || closing_;
        }
        if (refuse || (session_ != nullptr && others_.size() >= kMaxCandidates)) {
            park(std::move(link));
            return;
        }
        auto wrapped = policy_.wrap(std::move(link));
        if (!wrapped) {
            return; // refused (plaintext where TLS is required): the link is gone
        }
        auto s = std::make_unique<session::session>(io_, std::move(*wrapped), setup_.begin_handshake(), static_cast<session::handler&>(*this), options_);
        session::session& started = *s;
        if (session_ == nullptr) {
            session_ = std::move(s);
        } else {
            others_.push_back(std::move(s));
        }
        started.start();
    }

    void on_ready(session::session& s) override {
        if (&s != session_.get()) {
            // Reverse mode: a candidate finished a full handshake. While the current session is
            // alive the host already has one: refuse. Once it is detached, the host restarted (its
            // old session can't come back): the new one takes over.
            if (session_ != nullptr && session_->current() != session::state::kDetached) {
                s.close(make_error(errc::kForbidden, "this client already serves a host", "client"));
                return;
            }
            const auto it = std::ranges::find_if(others_, [&](const auto& o) { return o.get() == &s; });
            if (it == others_.end()) {
                return;
            }
            std::unique_ptr<session::session> fresh = std::move(*it);
            others_.erase(it);
            if (session_ != nullptr) {
                fail_pending(make_error(errc::kTransport, "the host started a new session", "client"));
                session_->close(make_error(errc::kCancelled, "replaced by the host's new session", "client"));
                others_.push_back(std::move(session_));
            }
            session_ = std::move(fresh);
        }
        {
            const std::scoped_lock lock{mutex_};
            ready_ = true;
            info_.connected = true;
            info_.session = s.id();
            info_.identity = s.identity();
            info_.granted = s.granted();
            info_.host_platform = s.peer_platform();
            info_.tls = s.encrypted();
        }
        cv_.notify_all();
        auto queued = std::move(queued_);
        queued_.clear();
        for (const queued_request& q : queued) {
            send_or_queue(q.code, q.message, q.req);
        }
        if (std::exchange(had_session_, true)) {
            resubscribe(); // a new host session (reverse mode) knows nothing of this client's events
        }
    }

    void resubscribe() {
        std::vector<std::pair<std::uint64_t, std::string>> sends;
        {
            const std::scoped_lock lock{mutex_};
            for (const auto& [name, count] : remote_names_) {
                const std::uint64_t req = ++last_req_;
                pending_[req].callback = [](result<value>) {};
                sends.emplace_back(req, name);
            }
        }
        for (const auto& [req, name] : sends) {
            const wire::envelope env{req, random_key(), Rhp::to_value(wire::subscribe_request{name})};
            send_or_queue(wire::op::kSubscribe, Rhp::to_value(env), req);
        }
    }

    void on_message(session::session&, wire::op code, value body) override {
        auto env = Rhp::from_value<wire::envelope>(body);
        if (!env) {
            return;
        }
        switch (code) {
        case wire::op::kResult:
            drop_timer(env->req);
            complete(env->req, std::move(env->body));
            return;
        case wire::op::kError: {
            drop_timer(env->req);
            auto err = Rhp::from_value<error>(env->body);
            complete(env->req, std::unexpected{err ? std::move(*err) : make_error(errc::kProtocol, "malformed error reply", "client")});
            return;
        }
        case wire::op::kOutput:
            if (setup_.options.on_output) {
                if (const auto* line = env->body.get_if<std::string>()) {
                    setup_.options.on_output(env->req, *line);
                }
            }
            return;
        case wire::op::kEmit:
            if (setup_.options.on_emit) {
                if (auto m = Rhp::from_value<wire::emit_message>(env->body)) {
                    setup_.options.on_emit(env->req, m->module, m->data);
                }
            }
            return;
        case wire::op::kEvent: {
            auto m = Rhp::from_value<wire::event_message>(env->body);
            if (!m) {
                return;
            }
            std::vector<std::shared_ptr<remote_event_fn>> targets;
            {
                const std::scoped_lock lock{mutex_};
                for (const auto& [id, l] : listeners_) {
                    if (l.name == m->name || l.name == "*") {
                        targets.push_back(l.fn);
                    }
                }
            }
            const remote_event e{m->name, m->module, m->args, m->dropped};
            for (const auto& fn : targets) {
                (*fn)(e);
            }
            return;
        }
        default: return;
        }
    }

    void on_closed(session::session& s, const error& why) override {
        if (&s != session_.get()) {
            // A reverse-mode candidate (handed over to a resume, refused, or failed) or a replaced
            // session. Destroying it inside on_closed is allowed.
            std::erase_if(others_, [&](const auto& o) { return o.get() == &s; });
            return;
        }
        bool closing = false;
        bool was_ready = false;
        {
            const std::scoped_lock lock{mutex_};
            closing = closing_;
            was_ready = ready_;
        }
        if (reverse_ && !closing) {
            // The host may dial again: keep listening. Calls in flight fail only if this session
            // was ready — a connection that never authenticated (a stray client, a port scan) had
            // none, and the calls queued for the next host stay queued.
            {
                const std::scoped_lock lock{mutex_};
                ready_ = false;
                info_.connected = false;
            }
            if (was_ready) {
                fail_pending(why.code == errc::kOk ? make_error(errc::kTransport, "the session ended", "client") : why);
            }
        } else {
            mark_closed(why);
        }
        // Destroying the session inside on_closed is allowed.
        session_.reset();
    }

    // Returns true if `req` was still pending (and is now completed).
    bool complete(std::uint64_t req, result<value> r) {
        completion callback;
        {
            const std::scoped_lock lock{mutex_};
            const auto it = pending_.find(req);
            if (it == pending_.end() || it->second.done.has_value()) {
                return false;
            }
            if (it->second.callback) {
                callback = std::move(it->second.callback);
                pending_.erase(it);
            } else {
                it->second.done = std::move(r);
            }
        }
        if (callback) {
            callback(std::move(r));
        } else {
            cv_.notify_all();
        }
        return true;
    }

    void drop_timer(std::uint64_t req) { timers_.erase(req); }

    // Every call in flight or queued fails with `why`.
    void fail_pending(const error& why) {
        std::vector<completion> callbacks;
        {
            const std::scoped_lock lock{mutex_};
            for (auto it = pending_.begin(); it != pending_.end();) {
                if (it->second.done) {
                    ++it;
                } else if (it->second.callback) {
                    callbacks.push_back(std::move(it->second.callback));
                    it = pending_.erase(it);
                } else {
                    it->second.done = std::unexpected{why};
                    ++it;
                }
            }
        }
        queued_.clear();
        timers_.clear();
        cv_.notify_all();
        for (completion& fn : callbacks) {
            fn(std::unexpected{why});
        }
    }

    void mark_closed(const error& why) {
        const error reason = why.code == errc::kOk ? make_error(errc::kTransport, "the session ended", "client") : why;
        {
            const std::scoped_lock lock{mutex_};
            ready_ = false;
            closed_ = true;
            listen_done_ = true;
            info_.connected = false;
            if (!failure_) {
                failure_ = reason;
            }
        }
        listener_.reset();
        fail_pending(reason);
    }

    setup setup_;
    bool reverse_; // listens for the host instead of dialing it
    session::options options_;
    std::unique_ptr<net::io_context> owned_io_; // null on a shared reactor
    net::io_context& io_;
    std::shared_ptr<bool> alive_ = std::make_shared<bool>(true); // false once the engine is being destroyed

    // Network thread only.
    struct queued_request {
        wire::op code = wire::op::kExec;
        value message;
        std::uint64_t req = 0;
    };
    std::unique_ptr<session::session> session_;
    std::unique_ptr<net::listener> listener_;
    std::deque<std::unique_ptr<net::link>> parked_; // extra hosts turned away (reverse mode)
    std::vector<queued_request> queued_;            // sent once the session is ready
    std::map<std::uint64_t, std::unique_ptr<net::io_context::timer>> timers_;
    static constexpr std::size_t kMaxCandidates = 4;
    std::vector<std::unique_ptr<session::session>> others_; // reverse mode: candidates and replaced sessions
    session::channel_policy policy_;
    std::optional<error> policy_error_;
    net::io_context::timer redial_timer_{io_};
    std::uint32_t attempts_ = 0;
    std::mt19937_64 rng_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool started_ = false;
    bool ready_ = false;
    bool closing_ = false; // close() was called
    bool closed_ = false;  // for good: close(), a failed dial or listen, or a dialed session's end
    bool listen_done_ = false;
    std::optional<error> listen_error_;
    std::uint16_t listen_port_ = 0;
    std::optional<error> failure_;
    std::uint64_t last_req_ = 0;
    std::map<std::uint64_t, call> pending_;
    session_info info_;
    // client.on: callbacks by id, and how many each subscribed name has.
    struct listener_entry {
        std::string name;
        std::shared_ptr<remote_event_fn> fn;
    };
    std::map<std::uint64_t, listener_entry> listeners_;
    std::map<std::string, std::size_t, std::less<>> remote_names_;
    std::uint64_t last_listener_ = 0;
    bool had_session_ = false; // network thread: a session was ready before (resubscribe on the next)
};

// ---- the C++ wall --------------------------------------------------------------------------------------

void engine_deleter::operator()(engine* e) const noexcept {
    delete e;
}

engine_ptr make_engine(setup s) {
    return engine_ptr{new engine{std::move(s)}};
}

result<void> connect(engine& e) {
    return e.connect();
}

result<std::uint16_t> port(engine& e) {
    return e.port();
}

result<value> request(engine& e, wire::op code, value body) {
    return e.request(code, std::move(body));
}

std::uint64_t submit(engine& e, wire::op code, value body, completion done) {
    return e.submit(code, std::move(body), std::move(done));
}

result<void> blob(engine& e, std::string_view sink, std::string_view name, std::span<const std::byte> data) {
    return e.blob(sink, name, data);
}

result<std::uint64_t> subscribe(engine& e, std::string_view name, remote_event_fn fn) {
    return e.subscribe(name, std::move(fn));
}

result<void> unsubscribe(engine& e, std::uint64_t id) {
    return e.unsubscribe(id);
}

void cancel(engine& e, std::uint64_t req) noexcept {
    e.cancel(req);
}

void close(engine& e) noexcept {
    e.close();
}

void poll(engine& e) {
    e.poll();
}

std::function<void(std::chrono::milliseconds)> pump_fn(engine& e) {
    return e.pump();
}

void run_io(engine& e, std::stop_token stop) {
    e.run_io(std::move(stop));
}

session_info info(const engine& e) {
    return e.info();
}

} // namespace Rhp::client_detail
