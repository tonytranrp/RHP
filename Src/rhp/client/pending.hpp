#pragma once

#include <chrono>
#include <concepts>
#include <condition_variable>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/errors_mode.hpp>
#include <rhp/core/result.hpp>

namespace Rhp {

namespace client_detail {

// The shared state of one asynchronous call: filled once, on the client's network thread (or inside
// poll() / a blocking call with io<zero_threads>), consumed once by whichever of then / get /
// future / co_await the caller picked.
template <class T>
class pending_state {
public:
    // With io<zero_threads> nobody else runs the network: get() / wait_for() run it through this.
    using pump_fn = std::function<void(std::chrono::milliseconds)>;

    // `blocked` (when set) says the calling thread is the one that has to deliver the result: get()
    // there would wait for itself, so it reports an error instead.
    pending_state(std::uint64_t request, pump_fn pump, std::function<bool()> blocked = {})
        : request_(request), pump_(std::move(pump)), blocked_(std::move(blocked)) {}

    void complete(result<T> r) {
        std::function<void(result<T>)> fn;
        std::coroutine_handle<> waiter;
        {
            const std::scoped_lock lock{mutex_};
            if (done_) {
                return;
            }
            done_ = true;
            if (then_) {
                fn = std::move(then_);
            } else {
                outcome_.emplace(std::move(r));
                waiter = std::exchange(waiter_, {});
            }
        }
        cv_.notify_all();
        if (fn) {
            fn(std::move(r));
        } else if (waiter) {
            waiter.resume();
        }
    }

    // Calls `fn` with the result: right away if it is in, else when it arrives.
    void then(std::function<void(result<T>)> fn) {
        std::optional<result<T>> ready;
        {
            const std::scoped_lock lock{mutex_};
            if (outcome_) {
                ready = std::move(outcome_);
                outcome_.reset();
            } else if (!done_) {
                then_ = std::move(fn);
                return;
            } else {
                return; // already consumed
            }
        }
        fn(std::move(*ready));
    }

    [[nodiscard]] bool ready() const {
        const std::scoped_lock lock{mutex_};
        return outcome_.has_value();
    }

    // Waits up to `timeout` for the result (running the network with io<zero_threads>).
    bool wait_for(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        std::unique_lock lock{mutex_};
        if (!done_ && blocked_ && blocked_()) {
            return false; // the network thread itself: nothing would arrive while it waits
        }
        if (!pump_) {
            return cv_.wait_until(lock, deadline, [this] { return done_; });
        }
        while (!done_) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                return false;
            }
            lock.unlock();
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            pump_(left < std::chrono::milliseconds{5} ? left : std::chrono::milliseconds{5});
            lock.lock();
        }
        return true;
    }

    // Blocks for the result (running the network with io<zero_threads>).
    result<T> take() {
        std::unique_lock lock{mutex_};
        if (!done_ && blocked_ && blocked_()) {
            return fail(errc::kInvalidArgument,
                        "get() on the client's own network thread (a callback or a co_await continuation) would wait for itself; use then() or co_await",
                        "pending");
        }
        if (!pump_) {
            cv_.wait(lock, [this] { return done_; });
        } else {
            while (!done_) {
                lock.unlock();
                pump_(std::chrono::milliseconds{5});
                lock.lock();
            }
        }
        if (!outcome_) {
            return fail(errc::kInvalidArgument, "this result was already taken", "pending");
        }
        result<T> out = std::move(*outcome_);
        outcome_.reset();
        return out;
    }

    // co_await: false (and the handle is kept) if the result isn't in yet.
    bool suspend(std::coroutine_handle<> h) {
        const std::scoped_lock lock{mutex_};
        if (done_) {
            return false;
        }
        waiter_ = h;
        return true;
    }

    // The awaiting coroutine is being destroyed while suspended: forget its handle so a later
    // completion keeps the result instead of resuming freed memory.
    void abandon(std::coroutine_handle<> h) noexcept {
        const std::scoped_lock lock{mutex_};
        if (waiter_ == h) {
            waiter_ = {};
        }
    }

    [[nodiscard]] std::uint64_t request() const noexcept {
        const std::scoped_lock lock{mutex_};
        return request_;
    }

    void set_request(std::uint64_t id) noexcept {
        const std::scoped_lock lock{mutex_};
        request_ = id;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool done_ = false;
    std::optional<result<T>> outcome_;
    std::function<void(result<T>)> then_;
    std::coroutine_handle<> waiter_;
    std::uint64_t request_ = 0;
    pump_fn pump_;
    std::function<bool()> blocked_;
};

} // namespace client_detail

// The future result of an asynchronous client call (client.async().exec(...)). Consume it once,
// in one of four ways:
//
//   p.then([](Rhp::result<T> r) { ... });     // callback (both error modes get a result<T>)
//   auto r = p.get();                         // block: Rhp::result<T>, or T under errors::throwing
//   std::future<...> f = std::move(p).future(); // std::future of the same
//   auto r = co_await std::move(p);           // from any C++20 coroutine
//
// Callbacks and coroutine resumptions run on the client's network thread (with io<zero_threads>,
// inside poll(), a blocking call, or get()): keep them short and don't make blocking calls on the
// same client from them. `request()` names the call for client.cancel(request); it stays valid
// while and after the result is consumed (also on a moved-from pending). Move-only: one consumer.
template <class T, ::Rhp::errors::mode Errors = ::Rhp::errors::expected>
class pending {
public:
    using value_type = T;
    using return_type = typename Errors::template return_t<T>;
    using future_type = std::conditional_t<std::is_same_v<Errors, ::Rhp::errors::throwing>, T, result<T>>;

    explicit pending(std::shared_ptr<client_detail::pending_state<T>> state) noexcept
        : state_(std::move(state)), request_(state_ != nullptr ? state_->request() : 0) {}

    pending(const pending&) = delete;
    pending& operator=(const pending&) = delete;
    pending(pending&&) noexcept = default;
    pending& operator=(pending&&) noexcept = default;
    ~pending() = default;

    [[nodiscard]] std::uint64_t request() const noexcept { return request_; }
    [[nodiscard]] bool ready() const { return state_ != nullptr && state_->ready(); }
    // True once the result is in (runs the network meanwhile with io<zero_threads>).
    bool wait_for(std::chrono::milliseconds timeout) { return state_ != nullptr && state_->wait_for(timeout); }

    template <std::invocable<result<T>> F>
    void then(F fn) && {
        if (!state_) {
            fn(taken());
            return;
        }
        state_->then(std::function<void(result<T>)>{std::move(fn)});
    }

    [[nodiscard]] return_type get() && { return Errors::finish(state_ != nullptr ? state_->take() : taken()); }

    [[nodiscard]] std::future<future_type> future() && {
        auto promise = std::make_shared<std::promise<future_type>>();
        std::future<future_type> f = promise->get_future();
        std::move(*this).then([promise](result<T> r) {
            if constexpr (std::is_same_v<Errors, ::Rhp::errors::throwing>) {
                if (!r) {
                    promise->set_exception(std::make_exception_ptr(exception{std::move(r).error()}));
                } else if constexpr (std::is_void_v<T>) {
                    promise->set_value();
                } else {
                    promise->set_value(std::move(*r));
                }
            } else {
                promise->set_value(std::move(r));
            }
        });
        return f;
    }

    // Lives in the awaiting coroutine's frame. Destroying a suspended coroutine destroys it too,
    // which unregisters the handle: completion can't resume a frame that is gone. Destroying the
    // coroutine must not race with its completion on the network thread (destroy it there, or
    // before the call can complete, e.g. after client.cancel() has finished).
    class awaiter {
    public:
        explicit awaiter(std::shared_ptr<client_detail::pending_state<T>> state) noexcept : state_(std::move(state)) {}
        awaiter(const awaiter&) = delete;
        awaiter& operator=(const awaiter&) = delete;
        // Movable before it suspends (adapters store awaitables by value); never move a suspended one.
        awaiter(awaiter&& other) noexcept : state_(std::move(other.state_)), suspended_(std::exchange(other.suspended_, {})) {}
        awaiter& operator=(awaiter&&) = delete;
        ~awaiter() {
            if (state_ && suspended_) {
                state_->abandon(suspended_);
            }
        }

        [[nodiscard]] bool await_ready() const { return state_->ready(); }
        bool await_suspend(std::coroutine_handle<> h) {
            // Recorded before the handle is published: once suspend() returns true the network
            // thread may already have resumed (or destroyed) this frame, so `this` is off limits.
            suspended_ = h;
            if (!state_->suspend(h)) {
                suspended_ = {};
                return false;
            }
            return true;
        }
        return_type await_resume() {
            suspended_ = {};
            return Errors::finish(state_->take());
        }

    private:
        std::shared_ptr<client_detail::pending_state<T>> state_;
        std::coroutine_handle<> suspended_;
    };

    // Shares the state, so request() and ready() keep working while (and after) the call is awaited.
    [[nodiscard]] awaiter operator co_await() && { return awaiter{state_ != nullptr ? state_ : taken_state()}; }

private:
    [[nodiscard]] static result<T> taken() { return fail(errc::kInvalidArgument, "this result was already taken", "pending"); }
    // An already-completed state holding the "taken" error, for awaiting a moved-from pending.
    [[nodiscard]] static std::shared_ptr<client_detail::pending_state<T>> taken_state() {
        auto s = std::make_shared<client_detail::pending_state<T>>(0, nullptr);
        s->complete(taken());
        return s;
    }

    std::shared_ptr<client_detail::pending_state<T>> state_; // declared before request_ (its initializer reads it)
    std::uint64_t request_ = 0;
};

} // namespace Rhp
