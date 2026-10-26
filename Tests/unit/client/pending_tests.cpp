#include <chrono>
#include <coroutine>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <rhp/client/pending.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/errors_mode.hpp>
#include <rhp/core/result.hpp>

using namespace std::chrono_literals;
using Rhp::errc;

namespace {

template <class T, class Errors = Rhp::errors::expected>
struct call {
    std::shared_ptr<Rhp::client_detail::pending_state<T>> state = std::make_shared<Rhp::client_detail::pending_state<T>>(7, nullptr);
    Rhp::pending<T, Errors> handle{state};
};

// The smallest coroutine that can co_await: starts eagerly, never suspends at the end of its own.
struct task {
    struct promise_type {
        task get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() { std::terminate(); }
    };
};

// A coroutine its caller owns: starts eagerly and can be destroyed while suspended.
struct owned_task {
    struct promise_type {
        owned_task get_return_object() noexcept { return owned_task{std::coroutine_handle<promise_type>::from_promise(*this)}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() { std::terminate(); }
    };

    explicit owned_task(std::coroutine_handle<promise_type> h) noexcept : handle(h) {}
    owned_task(const owned_task&) = delete;
    owned_task& operator=(const owned_task&) = delete;
    ~owned_task() {
        if (handle) {
            handle.destroy();
        }
    }

    std::coroutine_handle<promise_type> handle;
};

owned_task await_owned(Rhp::pending<int> p, bool& resumed) {
    auto r = co_await std::move(p);
    resumed = r.has_value();
}

task await_into(Rhp::pending<int> p, std::optional<Rhp::result<int>>& out) {
    out = co_await std::move(p);
}

// Awaits a pending its caller keeps: the caller still asks it for request() and ready() meanwhile.
task await_from(Rhp::pending<int>& p, std::optional<Rhp::result<int>>& out) {
    out = co_await std::move(p);
}

task await_throwing(Rhp::pending<int, Rhp::errors::throwing> p, std::optional<int>& out, std::optional<Rhp::errc>& failed) {
    try {
        out = co_await std::move(p);
    } catch (const Rhp::exception& e) {
        failed = e.err().code;
    }
}

} // namespace

TEST_CASE("pending: get after the result is in", "[client][pending]") {
    call<int> c;
    CHECK(c.handle.request() == 7);
    CHECK_FALSE(c.handle.ready());
    c.state->complete(41);
    c.state->complete(99); // only the first result counts
    CHECK(c.handle.ready());
    CHECK(std::move(c.handle).get() == 41);
}

TEST_CASE("pending: get blocks until another thread completes it", "[client][pending]") {
    call<std::string> c;
    std::promise<void> checked; // the network thread completes only after the first check (no timing race)
    std::jthread network{[state = c.state, go = checked.get_future()] {
        go.wait();
        std::this_thread::sleep_for(5ms);
        state->complete(std::string{"done"});
    }};
    CHECK_FALSE(c.handle.wait_for(1ms));
    checked.set_value();
    CHECK(std::move(c.handle).get() == std::string{"done"});
}

TEST_CASE("pending: then runs now or later", "[client][pending]") {
    call<int> early;
    early.state->complete(1);
    std::optional<Rhp::result<int>> got;
    std::move(early.handle).then([&](Rhp::result<int> r) { got = std::move(r); });
    REQUIRE(got);
    CHECK(**got == 1);

    call<int> late;
    std::optional<Rhp::result<int>> later;
    std::move(late.handle).then([&](Rhp::result<int> r) { later = std::move(r); });
    CHECK_FALSE(later);
    late.state->complete(Rhp::fail(errc::kCancelled, "stop"));
    REQUIRE(later);
    CHECK(later->error().code == errc::kCancelled);
}

TEST_CASE("pending: future in both error modes", "[client][pending]") {
    call<int> ok;
    auto f = std::move(ok.handle).future();
    ok.state->complete(5);
    CHECK(f.get() == 5);

    call<int, Rhp::errors::throwing> bad;
    auto g = std::move(bad.handle).future();
    bad.state->complete(Rhp::fail(errc::kTimeout, "slow"));
    CHECK_THROWS_AS(g.get(), Rhp::exception);

    call<void> nothing;
    auto h = std::move(nothing.handle).future();
    nothing.state->complete(Rhp::result<void>{});
    CHECK(h.get().has_value());
}

TEST_CASE("pending: co_await resumes when the result arrives", "[client][pending]") {
    call<int> c;
    std::optional<Rhp::result<int>> out;
    await_into(std::move(c.handle), out);
    CHECK_FALSE(out); // suspended
    c.state->complete(9);
    REQUIRE(out);
    CHECK(**out == 9);

    call<int> ready;
    ready.state->complete(3);
    std::optional<Rhp::result<int>> now;
    await_into(std::move(ready.handle), now); // doesn't suspend at all
    REQUIRE(now);
    CHECK(**now == 3);

    call<int, Rhp::errors::throwing> thrower;
    std::optional<int> value;
    std::optional<Rhp::errc> failed;
    await_throwing(std::move(thrower.handle), value, failed);
    thrower.state->complete(Rhp::fail(errc::kForbidden, "no"));
    CHECK_FALSE(value);
    CHECK(failed == errc::kForbidden);
}

TEST_CASE("pending: destroying a suspended coroutine unregisters it", "[client][pending]") {
    call<int> c;
    bool resumed = false;
    {
        owned_task t = await_owned(std::move(c.handle), resumed);
        REQUIRE_FALSE(t.handle.done()); // suspended on the call
    } // the frame (and its awaiter) is destroyed before the result arrives
    c.state->complete(5); // must not resume the destroyed frame
    CHECK_FALSE(resumed);
    CHECK(c.state->ready()); // the result is kept, unconsumed

    call<int> finished;
    bool done = false;
    {
        owned_task t = await_owned(std::move(finished.handle), done);
        finished.state->complete(6);
        CHECK(t.handle.done());
    }
    CHECK(done);
}

TEST_CASE("pending: with a pump / waiting runs it", "[client][pending]") {
    int pumped = 0;
    std::shared_ptr<Rhp::client_detail::pending_state<int>> state;
    state = std::make_shared<Rhp::client_detail::pending_state<int>>(1, [&](std::chrono::milliseconds) {
        if (++pumped == 3) {
            state->complete(12); // what the network would do inside a zero_threads poll
        }
    });
    Rhp::pending<int> p{state};
    CHECK(std::move(p).get() == 12);
    CHECK(pumped == 3);
}

TEST_CASE("pending: request and ready stay valid while and after co_await takes the result", "[client][pending]") {
    call<int> c;
    std::optional<Rhp::result<int>> out;
    await_from(c.handle, out);      // suspended: the call is still in flight
    CHECK(c.handle.request() == 7); // what client.cancel(p.request()) needs meanwhile
    CHECK_FALSE(c.handle.ready());
    c.state->complete(4);
    REQUIRE(out);
    REQUIRE(*out);
    CHECK(**out == 4);
    CHECK(c.handle.request() == 7);
    CHECK_FALSE(c.handle.ready()); // the awaiter took the result
}

TEST_CASE("pending: a moved-from pending still names its request", "[client][pending]") {
    call<int> c;
    Rhp::pending<int> moved{std::move(c.handle)};
    CHECK(moved.request() == 7);
    CHECK(c.handle.request() == 7); // NOLINT(bugprone-use-after-move): the id is kept on purpose
    CHECK_FALSE(c.handle.ready());
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<Rhp::pending<int>>); // one consumer per result
}
