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

    pending_state(std::uint64_t request, pump_fn pump) : request_(request), pump_(std::move(pump)) {}

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
// same client from them. `request()` names the call for client.cancel(request).
template <class T, ::Rhp::errors::mode Errors = ::Rhp::errors::expected>
class pending {
public:
    using value_type = T;
    using return_type = typename Errors::template return_t<T>;
    using future_type = std::conditional_t<std::is_same_v<Errors, ::Rhp::errors::throwing>, T, result<T>>;

    explicit pending(std::shared_ptr<client_detail::pending_state<T>> state) noexcept : state_(std::move(state)) {}

    [[nodiscard]] std::uint64_t request() const { return state_->request(); }
    [[nodiscard]] bool ready() const { return state_->ready(); }
    // True once the result is in (runs the network meanwhile with io<zero_threads>).
    bool wait_for(std::chrono::milliseconds timeout) { return state_->wait_for(timeout); }

    template <std::invocable<result<T>> F>
    void then(F fn) && {
        state_->then(std::function<void(result<T>)>{std::move(fn)});
    }

    [[nodiscard]] return_type get() && { return Errors::finish(state_->take()); }

    [[nodiscard]] std::future<future_type> future() && {
        auto promise = std::make_shared<std::promise<future_type>>();
        std::future<future_type> f = promise->get_future();
        state_->then([promise](result<T> r) {
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
        ~awaiter() {
            if (state_ && suspended_) {
                state_->abandon(suspended_);
            }
        }

        [[nodiscard]] bool await_ready() const { return state_->ready(); }
        bool await_suspend(std::coroutine_handle<> h) {
            if (!state_->suspend(h)) {
                return false;
            }
            suspended_ = h;
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

    [[nodiscard]] awaiter operator co_await() && { return awaiter{std::move(state_)}; }

private:
    std::shared_ptr<client_detail::pending_state<T>> state_;
};

} // namespace Rhp
