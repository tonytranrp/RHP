#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <latch>
#include <stdexcept>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/listener_table.hpp>

using namespace std::chrono_literals;

namespace {

using table = Rhp::core::listener_table<int, std::function<void(int)>>;

bool any_key(int) {
    return true;
}

} // namespace

TEST_CASE("listener_table dispatches by key in the order callbacks were added", "[core][listeners]") {
    table t;
    std::vector<int> seen;
    const auto a = t.add(1, [&](int v) { seen.push_back(10 + v); });
    t.add(2, [&](int v) { seen.push_back(20 + v); });
    t.add(1, [&](int v) { seen.push_back(30 + v); });
    t.dispatch([](int k) { return k == 1; }, 5);
    CHECK(seen == std::vector<int>{15, 35});
    CHECK(t.any([](int k) { return k == 2; }));
    CHECK_FALSE(t.any([](int k) { return k == 3; }));
    CHECK(t.remove(a));
    CHECK_FALSE(t.remove(a));
    seen.clear();
    t.dispatch(any_key, 1);
    CHECK(seen == std::vector<int>{21, 31});
}

TEST_CASE("listener_table lets a callback remove itself and others while it runs", "[core][listeners]") {
    table t;
    std::uint64_t self = 0;
    std::uint64_t other = 0;
    int calls = 0;
    self = t.add(0, [&](int) {
        ++calls;
        CHECK(t.remove(self)); // its own thread: no wait
        CHECK(t.remove(other));
    });
    other = t.add(0, [&](int) { ++calls; }); // removed before it starts
    t.dispatch(any_key, 0);
    CHECK(calls == 1);
    CHECK(t.empty());
}

TEST_CASE("listener_table keeps working after a callback throws", "[core][listeners]") {
    table t;
    const auto bad = t.add(0, [](int) { throw std::runtime_error{"boom"}; });
    CHECK_THROWS_AS(t.dispatch(any_key, 0), std::runtime_error);
    CHECK(t.remove(bad)); // no thread is left counted as inside it
    CHECK(t.empty());
}

TEST_CASE("listener_table remove waits for a call running on another thread", "[core][listeners][threads]") {
    table t;
    std::latch entered{1};
    std::atomic<bool> release{false};
    std::atomic<bool> running{false};
    const auto id = t.add(0, [&](int) {
        running = true;
        entered.count_down();
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
        running = false;
    });
    std::jthread dispatcher{[&] { t.dispatch(any_key, 0); }};
    entered.wait();
    std::jthread releaser{[&] {
        std::this_thread::sleep_for(50ms);
        release = true;
    }};
    CHECK(t.remove(id));
    const bool still_running = running.load(); // read on this thread, checked below
    CHECK_FALSE(still_running);
}

TEST_CASE("listener_table never starts a callback after its remove returned", "[core][listeners][threads]") {
    table t;
    std::latch first_entered{1};
    std::atomic<bool> release{false};
    std::atomic<bool> removed{false};
    std::atomic<bool> late_call{false};
    t.add(0, [&](int) { // holds the dispatch inside the first callback
        first_entered.count_down();
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
    });
    const auto second = t.add(0, [&](int) {
        if (removed.load()) {
            late_call = true;
        }
    });
    std::jthread dispatcher{[&] { t.dispatch(any_key, 0); }}; // snapshot holds both callbacks
    first_entered.wait();
    CHECK(t.remove(second));
    removed = true;
    release = true;
    dispatcher.join();
    CHECK_FALSE(late_call.load());
}

TEST_CASE("listener_table takes dispatches and subscriptions from many threads", "[core][listeners][threads]") {
    table t;
    std::atomic<int> calls{0};
    std::atomic<int> failed_removes{0}; // Catch2 assertions stay on this thread
    std::atomic<bool> stop{false};
    std::jthread publisher{[&] {
        for (int i = 0; i < 5'000; ++i) {
            t.dispatch(any_key, i);
        }
        stop = true;
    }};
    const auto churn = [&] {
        while (!stop.load()) {
            const auto id = t.add(0, [&](int) { calls.fetch_add(1, std::memory_order_relaxed); });
            (void)t.any(any_key);
            if (!t.remove(id)) {
                ++failed_removes;
            }
        }
    };
    std::jthread a{churn};
    std::jthread b{churn};
    publisher.join();
    a.join();
    b.join();
    CHECK(t.empty());
    CHECK(failed_removes.load() == 0);
    CHECK(calls.load() >= 0);
}
