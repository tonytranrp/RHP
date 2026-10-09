#include <chrono>
#include <coroutine>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
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

task await_into(Rhp::pending<int> p, std::optional<Rhp::result<int>>& out) {
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
    std::jthread network{[state = c.state] {
        std::this_thread::sleep_for(20ms);
        state->complete(std::string{"done"});
    }};
    CHECK_FALSE(c.handle.wait_for(1ms));
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
