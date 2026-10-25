#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/async.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>

using Rhp::errc;

TEST_CASE("async: the first completion wins and later ones are refused", "[core][async]") {
    auto [later, done] = Rhp::make_async<int>();
    CHECK_FALSE(later.ready());
    CHECK(done.complete(7));
    CHECK_FALSE(done.complete(8));
    CHECK(later.ready());
    const auto r = later.take();
    REQUIRE(r.has_value());
    CHECK(*r == 7);
    const auto again = later.take();
    REQUIRE_FALSE(again.has_value()); // taken once
    CHECK(again.error().message.find("already taken") != std::string::npos);
}

TEST_CASE("async: abandon hands back an untaken outcome and refuses later completions", "[core][async]") {
    auto [later, done] = Rhp::make_async<int>();
    CHECK(done.complete(5));
    auto left = later.abandon();
    REQUIRE(left.has_value());
    CHECK(**left == 5);
    CHECK(done.stop_requested());
    auto [other, other_done] = Rhp::make_async<int>();
    CHECK_FALSE(other.abandon().has_value()); // nothing arrived
    CHECK_FALSE(other_done.complete(1));
}

TEST_CASE("async: a moved-from promise does nothing", "[core][async]") {
    auto [later, done] = Rhp::make_async<int>();
    const Rhp::promise<int> keeper = std::move(done);
    CHECK_FALSE(done.complete(1)); // NOLINT(bugprone-use-after-move): the point of the test
    CHECK_FALSE(done.stop_requested());
    CHECK_FALSE(done.stop_token().stop_possible());
    CHECK(keeper.complete(2));
    CHECK(*later.take() == 2);
}

TEST_CASE("async: completed() builds an operation that is already over", "[core][async]") {
    auto ok = Rhp::async<std::string>::completed(std::string{"hit"});
    CHECK(ok.ready());
    CHECK(*ok.take() == "hit");
    auto bad = Rhp::async<int>::completed(Rhp::fail(errc::kNotFound, "no such texture"));
    CHECK(bad.ready());
    const auto r = bad.take();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kNotFound);
}

TEST_CASE("async: take before the result arrives is an error", "[core][async]") {
    auto [later, done] = Rhp::make_async<int>();
    const auto r = later.take();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kInvalidArgument);
    CHECK(done.complete(1));
    CHECK(*later.take() == 1);
}

TEST_CASE("async: void operations complete without a value", "[core][async]") {
    auto [later, done] = Rhp::make_async<void>();
    CHECK(done.complete());
    REQUIRE(later.ready());
    CHECK(later.take().has_value());
}

TEST_CASE("async: dropping every promise copy without completing reports an error", "[core][async]") {
    auto [later, done] = Rhp::make_async<int>();
    {
        const auto copy = done;
        const auto moved = std::move(done);
    }
    REQUIRE(later.ready());
    const auto r = later.take();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kRuntime);
}

TEST_CASE("async: a reader that goes away asks the producer to stop", "[core][async]") {
    auto pair = Rhp::make_async<int>();
    Rhp::promise<int> done = pair.second;
    CHECK_FALSE(done.stop_requested());
    {
        auto later = std::move(pair.first);
    }
    CHECK(done.stop_requested());
    CHECK(done.stop_token().stop_requested());
    CHECK_FALSE(done.complete(1)); // nobody receives it
}

TEST_CASE("async: request_stop is seen by the producer and an abandoned stop reads as cancelled", "[core][async]") {
    auto pair = Rhp::make_async<int>();
    auto later = std::move(pair.first);
    {
        Rhp::promise<int> done = std::move(pair.second);
        later.request_stop();
        CHECK(done.stop_requested());
    } // the producer gave up without completing
    REQUIRE(later.ready());
    const auto r = later.take();
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kCancelled);
}

TEST_CASE("async: arm calls the waker once on the completing thread", "[core][async]") {
    auto [later, done] = Rhp::make_async<int>();
    std::atomic<int> calls{0};
    std::thread::id woke_on;
    REQUIRE(later.arm([&] {
        woke_on = std::this_thread::get_id();
        ++calls;
    }));
    std::thread worker{[d = done] { (void)d.complete(42); }};
    const std::thread::id worker_id = worker.get_id();
    worker.join();
    CHECK(calls.load() == 1);
    CHECK(woke_on == worker_id);
    CHECK(*later.take() == 42);
    CHECK_FALSE(later.arm([] {})); // already there
}

TEST_CASE("async: many threads racing to complete deliver exactly one result", "[core][async][threads]") {
    for (int round = 0; round < 200; ++round) {
        auto [later, done] = Rhp::make_async<int>();
        std::atomic<int> wakes{0};
        REQUIRE(later.arm([&] { ++wakes; }));
        std::atomic<int> accepted{0};
        std::vector<std::thread> workers;
        for (int i = 0; i < 4; ++i) {
            workers.emplace_back([&accepted, d = done, i] {
                if (d.complete(i)) {
                    ++accepted;
                }
            });
        }
        for (auto& w : workers) {
            w.join();
        }
        CHECK(accepted.load() == 1);
        CHECK(wakes.load() == 1);
        CHECK(later.take().has_value());
    }
}

TEST_CASE("async: a reader destroyed while another thread completes stays safe", "[core][async][threads]") {
    for (int round = 0; round < 200; ++round) {
        auto pair = Rhp::make_async<std::string>();
        auto later = std::make_unique<Rhp::async<std::string>>(std::move(pair.first));
        std::atomic<bool> woke{false};
        REQUIRE(later->arm([&woke] { woke = true; }));
        std::thread worker{[d = std::move(pair.second)] { (void)d.complete(std::string(64, 'x')); }};
        later.reset();
        worker.join();
        SUCCEED();
    }
}
