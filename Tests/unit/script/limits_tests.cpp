#include <chrono>
#include <cstdint>
#include <limits>
#include <stop_token>
#include <string_view>
#include <thread>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/utils/units.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

namespace {

sandbox make_box(Rhp::limits limits = {}) {
    sandbox_options options;
    options.limits = limits;
    options.output = [](std::string_view) {};
    return sandbox{std::move(options)};
}

// Runs source while another thread keeps calling cancel() (first after ~20 ms) until it returns.
// Cancelling repeatedly avoids a race with the script not having started yet.
Rhp::result<Rhp::script::value_list> exec_cancelled(sandbox& box, std::string_view source) {
    std::jthread canceller{[&box](const std::stop_token& stop) {
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{20});
            box.cancel();
        }
    }};
    auto r = box.exec(source);
    canceller.request_stop();
    canceller.join();
    return r;
}

} // namespace

TEST_CASE("cancel stops a running script from another thread", "[script][limits]") {
    sandbox box = make_box();

    const auto spin = exec_cancelled(box, "while true do end");
    REQUIRE_FALSE(spin.has_value());
    CHECK(spin.error().code == errc::kCancelled);

    // The sandbox is fine afterwards.
    CHECK(box.exec<int>("return 40 + 2") == 42);
}

TEST_CASE("cancel is sticky: pcall can't swallow it", "[script][limits]") {
    sandbox box = make_box();

    const auto stubborn = exec_cancelled(box, "while true do pcall(function() while true do end end) end");
    REQUIRE_FALSE(stubborn.has_value());
    CHECK(stubborn.error().code == errc::kCancelled);

    const auto stubborn_error = exec_cancelled(box, "while true do pcall(error, 'x') end");
    REQUIRE_FALSE(stubborn_error.has_value());
    CHECK(stubborn_error.error().code == errc::kCancelled);

    CHECK(box.exec<int>("return 1") == 1);
}

TEST_CASE("cancel while nothing runs is a no-op", "[script][limits]") {
    sandbox box = make_box();
    box.cancel();
    CHECK(box.exec<int>("local s = 0 for i = 1, 100000 do s = s + 1 end return s") == 100000);
}

TEST_CASE("memory limit stops a growing script", "[script][limits]") {
    using namespace Rhp::literals;
    Rhp::limits limits;
    limits.memory = 1_MiB;
    sandbox box = make_box(limits);

    CHECK(box.exec<int>("return #string.rep('x', 1000)") == 1000);

    const auto hog = box.exec(R"lua(
        local t = {}
        for i = 1, 1e7 do t[i] = string.rep("x", 100) .. i end
    )lua");
    REQUIRE_FALSE(hog.has_value());
    CHECK(hog.error().code == errc::kMemoryExceeded);
    CHECK(box.memory_used() <= 1_MiB);

    CHECK(box.exec<int>("return 2 + 2") == 4);
}

TEST_CASE("instruction budget stops a runaway script", "[script][limits]") {
    Rhp::limits limits;
    limits.instructions = 100'000;
    sandbox box = make_box(limits);

    // The budget is per run: several small runs all fit.
    for (int run = 0; run < 3; ++run) {
        CAPTURE(run);
        CHECK(box.exec<int>("local s = 0 for i = 1, 1000 do s = s + i end return s") == 500500);
    }

    const auto spin = box.exec("while true do end");
    REQUIRE_FALSE(spin.has_value());
    CHECK(spin.error().code == errc::kBudgetExceeded);

    const auto stubborn = box.exec("while true do pcall(function() while true do end end) end");
    REQUIRE_FALSE(stubborn.has_value());
    CHECK(stubborn.error().code == errc::kBudgetExceeded);
}

// Cancels and limits are checked at safe points (loop back-edges and Lua calls, cmake/lua/lua_cxx.cpp):
// every shape of loop and recursion without a loop must reach one.
TEST_CASE("an instruction budget stops every kind of loop and call chain", "[script][limits]") {
    Rhp::limits limits;
    limits.instructions = 50'000;
    sandbox box = make_box(limits);

    const char* const runaways[] = {
        "while true do end",
        "repeat local x = 1 until false",
        "::top:: goto top",
        "for i = 1, math.maxinteger do end",
        "for i = 1.0, math.huge do end",
        "for _ in function() return 1 end do end",
        "local function f(n) return f(n + 1) end return f(1)",
        "local function f(n) if n == 0 then return 1 end return f(n - 1) + f(n - 1) end return f(40)",
    };
    for (const char* source : runaways) {
        CAPTURE(source);
        const auto r = box.exec(source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kBudgetExceeded);
    }
}

TEST_CASE("an instruction budget counts each loop iteration's instructions", "[script][limits]") {
    Rhp::limits limits;
    limits.instructions = 100'000;
    sandbox box = make_box(limits);

    // About 4 instructions an iteration: 1000 iterations fit, 100000 don't.
    CHECK(box.exec<int>("local s = 0 for i = 1, 1000 do s = s + i * 2 end return s") == 1001000);
    const auto r = box.exec("local s = 0 for i = 1, 100000 do s = s + i * 2 end return s");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kBudgetExceeded);
}

TEST_CASE("cancel stops recursion that never loops", "[script][limits]") {
    sandbox box = make_box();

    const auto r = exec_cancelled(box, "local function f(n) if n == 0 then return 1 end return f(n - 1) + f(n - 1) end return f(60)");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kCancelled);
}

TEST_CASE("a check interval larger than Lua's hook count holds still arms the hook", "[script][limits]") {
    Rhp::limits limits;
    limits.instructions = 1'000'000'000;             // arms the hook on every run
    limits.cancel_check_instructions = 0x8000'0000u; // more than an int, which is what Lua takes
    sandbox_options options;
    options.limits = limits;
    options.caller_role = Rhp::role::kAdmin; // debug.gethook
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    // The request's coroutine counts with the largest count Lua takes (a negative one switched it off).
    CHECK(box.exec<std::int64_t>("return select(3, debug.gethook())") == std::int64_t{(std::numeric_limits<int>::max)()});
}
