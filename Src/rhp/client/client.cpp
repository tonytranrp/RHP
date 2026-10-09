#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <utility>

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
    explicit engine(setup s) : setup_(std::move(s)) {
        options_.limits = setup_.limits;
        options_.codec = setup_.codec;
        options_.platform = std::string{platform::kOsName};
    }

    ~engine() {
        // The network is stopped (or was never on another thread): plain teardown.
        session_.reset();
    }

    engine(const engine&) = delete;
    engine& operator=(const engine&) = delete;

    result<void> connect() {
        std::unique_lock lock{mutex_};
        if (ready_) {
            return {};
        }
        if (failure_ && dialed_) {
            return fail(*failure_);
        }
        if (setup_.ep.direction != net::endpoint::mode::kDial) {
            return fail(errc::kInvalidArgument, "a Stage 3 client dials; reverse mode (a client that listens) arrives in Stage 4", "client");
        }
        if (!dialed_) {
            dialed_ = true;
            io_.post([this] { dial(); });
        }
        const auto deadline = clock::now() + setup_.options.connect_timeout;
        const bool done = wait(lock, deadline, [this] { return ready_ || failure_.has_value(); });
        if (ready_) {
            return {};
        }
        if (failure_) {
            return fail(*failure_);
        }
        (void)done;
        return fail(errc::kTimeout, std::format("no session with {} within {} ms", setup_.ep, setup_.options.connect_timeout.count()), "client.connect");
    }

    result<value> request(wire::op code, value body) {
        if (auto ok = connect(); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        std::unique_lock lock{mutex_};
        const std::uint64_t req = ++last_req_;
        auto& slot = pending_[req];
        (void)slot;
        const wire::envelope env{req, random_key(), std::move(body)};
        io_.post([this, code, message = Rhp::to_value(env), req] {
            if (session_ == nullptr || !session_->ready()) {
                complete(req, fail(errc::kTransport, "the session ended", "client"));
                return;
            }
            if (auto sent = session_->send(code, message); !sent) {
                complete(req, std::unexpected{std::move(sent).error()});
            }
        });
        const bool timed = setup_.options.request_timeout.count() > 0;
        const auto deadline = timed ? clock::now() + setup_.options.request_timeout : clock::time_point::max();
        wait(lock, deadline, [this, req] { return pending_.at(req).has_value(); });
        auto node = pending_.extract(req);
        if (!node.mapped()) {
            // Timed out: stop it on the host too.
            lock.unlock();
            post_cancel(req);
            return fail(errc::kTimeout, std::format("no reply to {} within {} ms", code, setup_.options.request_timeout.count()), "client");
        }
        return std::move(*node.mapped());
    }

    void cancel() noexcept {
        try {
            post_cancel(0);
        } catch (...) { // out of memory: nothing was sent
        }
    }

    void close() noexcept {
        try {
            {
                const std::scoped_lock lock{mutex_};
                if (!dialed_ || closed_) {
                    return;
                }
            }
            io_.post([this] {
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

    [[nodiscard]] session_info info() const {
        const std::scoped_lock lock{mutex_};
        return info_;
    }

private:
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
        io_.post([this, target] {
            if (session_ != nullptr && session_->ready()) {
                std::uint64_t req = 0;
                {
                    const std::scoped_lock lock{mutex_};
                    req = ++last_req_;
                }
                (void)session_->send(wire::op::kCancel, Rhp::to_value(wire::envelope{req, 0, Rhp::to_value(wire::cancel_request{target})}));
            }
        });
    }

    // ---- network thread ------------------------------------------------------------------------------

    void dial() {
        setup_.transport.dial(io_, setup_.ep, [this](result<std::unique_ptr<net::link>> link) {
            if (!link) {
                mark_closed(std::move(link).error());
                return;
            }
            {
                const std::scoped_lock lock{mutex_};
                if (closed_) {
                    return; // close() came first: drop the new link
                }
            }
            session_ = std::make_unique<session::session>(io_, std::move(*link), setup_.begin_handshake(), static_cast<session::handler&>(*this), options_);
            session_->start();
        });
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
    }

    void on_message(session::session&, wire::op code, value body) override {
        auto env = Rhp::from_value<wire::envelope>(body);
        if (!env) {
            return;
        }
        switch (code) {
        case wire::op::kResult: complete(env->req, std::move(env->body)); return;
        case wire::op::kError: {
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
        mark_closed(why);
        // Destroying the session inside on_closed is allowed.
        session_.reset();
    }

    void complete(std::uint64_t req, result<value> r) {
        {
            const std::scoped_lock lock{mutex_};
            const auto it = pending_.find(req);
            if (it == pending_.end() || it->second.has_value()) {
                return;
            }
            it->second = std::move(r);
        }
        cv_.notify_all();
    }

    void mark_closed(const error& why) {
        {
            const std::scoped_lock lock{mutex_};
            ready_ = false;
            closed_ = true;
            info_.connected = false;
            if (!failure_) {
                failure_ = why;
            }
            for (auto& [req, slot] : pending_) {
                if (!slot) {
                    slot = std::unexpected{why.code == errc::kOk ? make_error(errc::kTransport, "the session ended", "client") : why};
                }
            }
        }
        cv_.notify_all();
    }

    setup setup_;
    session::options options_;
    net::io_context io_;
    std::unique_ptr<session::session> session_; // network thread only

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool dialed_ = false;
    bool ready_ = false;
    bool closed_ = false;
    std::optional<error> failure_;
    std::uint64_t last_req_ = 0;
    std::map<std::uint64_t, std::optional<result<value>>> pending_;
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

result<value> request(engine& e, wire::op code, value body) {
    return e.request(code, std::move(body));
}

void cancel(engine& e) noexcept {
    e.cancel();
}

void close(engine& e) noexcept {
    e.close();
}

void poll(engine& e) {
    e.poll();
}

void run_io(engine& e, std::stop_token stop) {
    e.run_io(std::move(stop));
}

session_info info(const engine& e) {
    return e.info();
}

} // namespace Rhp::client_detail
