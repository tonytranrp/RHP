#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <type_traits>
#include <utility>

#include <rhp/core/result.hpp>

namespace Rhp {

// A result that arrives later, and the means to deliver it: what an asynchronous binding returns.
//
//   Rhp::async<texture> load_texture(std::string path) {
//       auto [later, done] = Rhp::make_async<texture>();
//       std::thread{[done, path] {
//           if (!done.complete(read_texture(path))) {
//               // nobody receives it any more (the script went away): free what was made
//           }
//       }}.detach();
//       return std::move(later); // a structured binding is not moved implicitly
//   }
//   using game_lib = Rhp::lib<"game">::fn<"load_texture", &load_texture>;
//
// A script calling game.load_texture(path) suspends until complete() is called (from any thread),
// then gets the value, or the error raised. promise is copyable; the first completion wins and the
// rest return false. When the reader goes away first (the script was cancelled, its module unloaded,
// limits.async_ms ran out) stop_requested() turns true: long work may check it and give up. When the
// last promise copy is dropped without completing, the reader gets an error.
template <class T>
class async;
template <class T>
class promise;

namespace async_detail {

template <class T>
struct state {
    std::mutex mutex;
    bool done = false;
    bool taken = false;
    bool reader_gone = false;
    std::optional<result<T>> outcome;
    std::function<void()> waker; // armed by the reader; called once, on the completing thread, outside the lock
    std::stop_source stop{std::nostopstate}; // made by make_async: an operation that's already over needs none
};

// Delivers `r` unless something already did; returns true when a reader may still take it.
template <class T>
bool complete(state<T>& s, result<T>&& r) {
    std::function<void()> wake;
    {
        const std::scoped_lock lock{s.mutex};
        if (s.done || s.reader_gone) {
            return false;
        }
        s.done = true;
        s.outcome.emplace(std::move(r));
        wake = std::move(s.waker);
        s.waker = nullptr;
    }
    if (wake) {
        wake();
    }
    return true;
}

// Shared by every copy of one promise: the last copy to go completes the operation if nobody did.
template <class T>
struct anchor {
    std::shared_ptr<state<T>> s;

    explicit anchor(std::shared_ptr<state<T>> st) noexcept : s(std::move(st)) {}
    anchor(const anchor&) = delete;
    anchor& operator=(const anchor&) = delete;
    ~anchor() {
        if (s) {
            const bool stopped = s->stop.stop_requested();
            (void)complete(*s, result<T>{fail(stopped ? errc::kCancelled : errc::kRuntime,
                                              stopped ? "the async operation stopped" : "the async operation ended without a result", "async")});
        }
    }
};

} // namespace async_detail

template <class T>
class [[nodiscard]] async {
public:
    using value_type = T;

    // An operation that is already over (a cache hit, an argument error): the script doesn't suspend.
    // No producer ever sees it, so the outcome is kept here, without a shared state.
    [[nodiscard]] static async completed(result<T> r) {
        async a{nullptr};
        a.outcome_.emplace(std::move(r));
        a.completed_ = true;
        return a;
    }

    async(async&& other) noexcept
        : s_(std::move(other.s_)), outcome_(std::move(other.outcome_)), completed_(std::exchange(other.completed_, false)) {
        other.outcome_.reset();
    }
    async& operator=(async&& other) noexcept {
        if (this != &other) {
            release();
            s_ = std::move(other.s_);
            outcome_ = std::move(other.outcome_);
            other.outcome_.reset();
            completed_ = std::exchange(other.completed_, false);
        }
        return *this;
    }
    async(const async&) = delete;
    async& operator=(const async&) = delete;
    ~async() { release(); }

    // The outcome is there (or this async was moved from / abandoned).
    [[nodiscard]] bool ready() const {
        if (completed_ || !s_) {
            return true;
        }
        const std::scoped_lock lock{s_->mutex};
        return s_->done;
    }

    // The outcome, once ready(): kInvalidArgument before, and after it was taken or abandoned.
    [[nodiscard]] result<T> take() {
        if (completed_) {
            if (!outcome_) {
                return fail(errc::kInvalidArgument, "the async result was already taken", "async");
            }
            result<T> out = std::move(*outcome_);
            outcome_.reset();
            return out;
        }
        if (!s_) {
            return fail(errc::kInvalidArgument, "this async was moved from or abandoned", "async");
        }
        const std::scoped_lock lock{s_->mutex};
        if (s_->taken) {
            return fail(errc::kInvalidArgument, "the async result was already taken", "async");
        }
        if (!s_->done) {
            return fail(errc::kInvalidArgument, "the async result isn't ready", "async");
        }
        s_->taken = true;
        result<T> out = std::move(*s_->outcome);
        s_->outcome.reset();
        return out;
    }

    // Asks the producer to give up (promise::stop_requested()).
    void request_stop() noexcept {
        if (s_) {
            s_->stop.request_stop();
        }
    }

    // Stops reading, atomically: afterwards complete() returns false, and the outcome that already
    // arrived (if any, untaken) is handed back so whoever abandons it can undo it. Requests a stop.
    [[nodiscard]] std::optional<result<T>> abandon() {
        if (completed_) {
            completed_ = false; // from now on: abandoned
            return std::exchange(outcome_, std::nullopt);
        }
        if (!s_) {
            return std::nullopt;
        }
        std::optional<result<T>> left;
        {
            const std::scoped_lock lock{s_->mutex};
            s_->reader_gone = true;
            s_->waker = nullptr;
            if (s_->done && !s_->taken && s_->outcome) {
                s_->taken = true;
                left = std::move(s_->outcome);
                s_->outcome.reset();
            }
        }
        s_->stop.request_stop();
        s_.reset();
        return left;
    }

    // For the script engine: calls `wake` once, on the completing thread, when the outcome arrives.
    // Returns false and arms nothing when it is already there.
    [[nodiscard]] bool arm(std::function<void()> wake) {
        if (completed_ || !s_) {
            return false;
        }
        const std::scoped_lock lock{s_->mutex};
        if (s_->done) {
            return false;
        }
        s_->waker = std::move(wake);
        return true;
    }

private:
    template <class U>
    friend std::pair<async<U>, promise<U>> make_async();

    explicit async(std::shared_ptr<async_detail::state<T>> s) noexcept : s_(std::move(s)) {}

    void release() noexcept {
        completed_ = false;
        outcome_.reset();
        if (!s_) {
            return;
        }
        {
            const std::scoped_lock lock{s_->mutex};
            s_->reader_gone = true;
            s_->waker = nullptr;
        }
        s_->stop.request_stop();
        s_.reset();
    }

    std::shared_ptr<async_detail::state<T>> s_;
    std::optional<result<T>> outcome_; // completed(): the outcome, until taken or abandoned
    bool completed_ = false;           // made by completed() (no state), not yet abandoned
};

template <class T>
class promise {
public:
    // Delivers the outcome; the first completion wins. Returns true when a reader will receive it;
    // false when it was already completed or nobody reads any more (the script went away): then
    // whatever the work made is the caller's to clean up. Any thread.
    [[nodiscard]] bool complete(result<T> r) const { return a_ != nullptr && async_detail::complete(*a_->s, std::move(r)); }

    [[nodiscard]] bool complete() const
        requires std::is_void_v<T>
    {
        return complete(result<void>{});
    }

    // A moved-from promise has no operation: its stop token never stops, complete() returns false.
    [[nodiscard]] std::stop_token stop_token() const noexcept { return a_ != nullptr ? a_->s->stop.get_token() : std::stop_token{}; }
    [[nodiscard]] bool stop_requested() const noexcept { return a_ != nullptr && a_->s->stop.stop_requested(); }

private:
    template <class U>
    friend std::pair<async<U>, promise<U>> make_async();

    explicit promise(std::shared_ptr<async_detail::anchor<T>> a) noexcept : a_(std::move(a)) {}

    std::shared_ptr<async_detail::anchor<T>> a_;
};

// A new pending operation: the reading side and the completing side.
template <class T>
[[nodiscard]] std::pair<async<T>, promise<T>> make_async() {
    auto s = std::make_shared<async_detail::state<T>>();
    s->stop = std::stop_source{};
    auto a = std::make_shared<async_detail::anchor<T>>(s);
    return {async<T>{std::move(s)}, promise<T>{std::move(a)}};
}

template <class T>
inline constexpr bool is_async_v = false;

template <class T>
inline constexpr bool is_async_v<async<T>> = true;

} // namespace Rhp
