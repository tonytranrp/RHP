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
    explicit engine(setup s) : setup_(std::move(s)), reverse_(setup_.ep.direction == net::endpoint::mode::kListen) {
        options_.limits = setup_.limits;
        options_.codec = setup_.codec;
        options_.platform = std::string{platform::kOsName};
    }

    ~engine() {
        // The network is stopped (or was never on another thread): plain teardown.
        timers_.clear();
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
        start(lock);
        wait(lock, clock::time_point::max(), [this] { return listen_done_; });
        if (listen_error_) {
            return fail(*listen_error_);
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
        io_.post([this, code, message = Rhp::to_value(env), req] { send_or_queue(code, message, req); });
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
        io_.post([this, code, message = Rhp::to_value(env), req] {
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
                if (!started_ || closed_) {
                    return;
                }
                closing_ = true;
            }
            io_.post([this] {
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

    void run_io(std::stop_token stop) { io_.run(std::move(stop)); }

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
        return info_;
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
            io_.post([this] { listen(); });
        } else {
            io_.post([this] { dial(); });
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
        io_.post([this, target] { send_cancel(target); });
    }

    // ---- network thread ------------------------------------------------------------------------------

    void send_cancel(std::uint64_t target) {
        if (session_ != nullptr && session_->ready()) {
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
        if (session_ != nullptr && session_->ready()) {
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
        setup_.transport.dial(io_, setup_.ep, [this](result<std::unique_ptr<net::link>> link) {
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

    // Reverse mode: listen, and serve one host at a time.
    void listen() {
        auto l = setup_.transport.listen(io_, setup_.ep, [this](std::unique_ptr<net::link> link) { accept(std::move(link)); });
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

    void accept(std::unique_ptr<net::link> link) {
        bool refuse = session_ != nullptr;
        {
            const std::scoped_lock lock{mutex_};
            refuse = refuse || closed_ || closing_;
        }
        if (refuse) {
            link->close();
            parked_.push_back(std::move(link));
            if (parked_.size() > 8) {
                parked_.pop_front();
            }
            return;
        }
        session_ = std::make_unique<session::session>(io_, std::move(link), setup_.begin_handshake(), static_cast<session::handler&>(*this), options_);
        session_->start();
    }

    void on_ready(session::session& s) override {
        {
            const std::scoped_lock lock{mutex_};
            ready_ = true;
            info_.connected = true;
            info_.session = s.id();
            info_.identity = s.identity();
            info_.granted = s.granted();
            info_.host_platform = s.peer_platform();
        }
        cv_.notify_all();
        auto queued = std::move(queued_);
        queued_.clear();
        for (const queued_request& q : queued) {
            send_or_queue(q.code, q.message, q.req);
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
        default: return;
        }
    }

    void on_closed(session::session&, const error& why) override {
        bool closing = false;
        {
            const std::scoped_lock lock{mutex_};
            closing = closing_;
        }
        if (reverse_ && !closing) {
            // The host may dial again: fail what was in flight, keep listening.
            {
                const std::scoped_lock lock{mutex_};
                ready_ = false;
                info_.connected = false;
            }
            fail_pending(why.code == errc::kOk ? make_error(errc::kTransport, "the session ended", "client") : why);
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
    net::io_context io_;

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
