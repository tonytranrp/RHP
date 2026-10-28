#include <chrono>
#include <cstdint>
#include <limits>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/hardening.hpp>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

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

// Work Lua does in C, where no hook fires, that would run for minutes unchecked: a pattern that
// backtracks through ten nested expansions (and the same through gmatch and gsub), %b rescanning to
// the end from every position, and plain finds whose every candidate almost matches.
constexpr std::string_view kRunawayPatterns[] = {
    R"lua(return string.find(("a"):rep(5000), ("a*"):rep(10) .. "b"))lua",
    R"lua(for m in ("a"):rep(5000):gmatch(("a*"):rep(10) .. "b") do end)lua",
    R"lua(return (("a"):rep(5000):gsub(("a-"):rep(10) .. "b", "")))lua",
    R"lua(return string.find(("("):rep(1 << 20), "%b()"))lua",
    R"lua(return string.find(("a"):rep(1 << 20), ("a"):rep(1 << 16) .. "b", 1, true))lua",
    R"lua(return string.find(("a"):rep(1 << 20), ("a"):rep(1 << 16) .. "b"))lua", // no specials: a plain find too
};

// What `source` (which returns one string) gives in a plain Lua state: no step function, no hook.
std::string raw_string(std::string_view source) {
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);
    REQUIRE(luaL_loadbufferx(L, source.data(), source.size(), "=raw", "t") == LUA_OK);
    REQUIRE(lua_pcall(L, 0, 1, 0) == LUA_OK);
    std::string out = lua_tostring(L, -1);
    lua_close(L);
    return out;
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

TEST_CASE("an instruction budget stops pattern matching and plain find", "[script][limits][patterns]") {
    Rhp::limits limits;
    limits.instructions = 1'000'000;
    sandbox box = make_box(limits);
    for (const std::string_view source : kRunawayPatterns) {
        CAPTURE(source);
        const auto r = box.exec(source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kBudgetExceeded);
    }
    // Sticky: a pcall around the match doesn't swallow the stop.
    const auto stubborn = box.exec(R"lua(while true do pcall(load('return string.find(("a"):rep(5000), ("a*"):rep(10) .. "b")')) end)lua");
    REQUIRE_FALSE(stubborn.has_value());
    CHECK(stubborn.error().code == errc::kBudgetExceeded);
    CHECK(box.exec<int>("return 1") == 1);
}

TEST_CASE("a wall time limit stops pattern matching and plain find", "[script][limits][patterns]") {
    Rhp::limits limits;
    limits.wall_ms = 100;
    sandbox box = make_box(limits);
    for (const std::string_view source : kRunawayPatterns) {
        CAPTURE(source);
        const auto started = std::chrono::steady_clock::now();
        const auto r = box.exec(source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kTimeout);
        CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds{10});
    }
}

TEST_CASE("cancel stops pattern matching and plain find", "[script][limits][patterns]") {
    sandbox box = make_box();
    for (const std::string_view source : kRunawayPatterns) {
        CAPTURE(source);
        const auto r = exec_cancelled(box, source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kCancelled);
    }
}

TEST_CASE("charging pattern steps doesn't change what matching returns", "[script][limits][patterns]") {
    // Every function of the matcher and plain find, each over enough text to charge its steps many
    // times; compared with a plain Lua state.
    constexpr std::string_view source = R"lua(
        local s = ("ab"):rep(50000)
        local out = {}
        local function add(...)
            for i = 1, select("#", ...) do out[#out + 1] = tostring((select(i, ...))) end
        end
        add(select(2, s:gsub("a", "x")))
        local count = 0
        for _ in s:gmatch("ab") do count = count + 1 end
        add(count)
        add(s:find("ba", 1, true))
        add(s:find("bb", 1, true))
        add((("a"):rep(100000) .. "b"):find(("a"):rep(1000) .. "b", 1, true))
        add((("x"):rep(10000) .. "(a(b)c)"):match("%b()"))
        add(("THE (quick) fox"):find("%f[%a]%a+", 5))
        add(("hello world"):match("(o)(.-)%1"))
        add((("a"):rep(5000)):find(("a*"):rep(10) .. "$"))
        add((("a"):rep(20000) .. "b"):match("(a-)b"):len())
        add(s:match("^(.-)(b+)$"))
        -- Lua's own recursion limit is untouched: 5000 nested items are "too complex" at once.
        add(pcall(string.find, ("a"):rep(5000), ("a?"):rep(5000) .. ("a"):rep(5000)))
        return table.concat(out, " ")
    )lua";
    const std::string expected = raw_string(source);
    CHECK(expected.contains("pattern too complex"));

    Rhp::limits limits;
    limits.instructions = 1'000'000'000; // every run checked: steps are charged, and fit
    sandbox box = make_box(limits);
    CHECK(box.exec<std::string>(source) == expected);
    sandbox unchecked = make_box();
    CHECK(unchecked.exec<std::string>(source) == expected);
}

TEST_CASE("a check interval larger than Lua's hook count holds still arms the hook", "[script][limits]") {
    rhp_test::needs(Rhp::hardening::kDev, "admin's debug library");
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

TEST_CASE("limits.handlers refuses one handler more and makes room as they go", "[script][limits][handlers]") {
    Rhp::limits limits;
    limits.handlers = 4;
    sandbox box = make_box(limits);
    constexpr std::string_view kTimer = "rhp.after(1000, function() end)";
    constexpr std::string_view kFrames = "rhp.every_frame(function() end)";
    constexpr std::string_view kSubscription = "rhp.on('tests.handlers.ping', function() end)";
    constexpr std::string_view kTask = "rhp.spawn(function() end)";
    const auto refused = [&box](std::string_view source) {
        const auto r = box.exec(source);
        return !r && r.error().code == errc::kLimitExceeded && r.error().message.contains("limits.handlers");
    };

    // One of each kind fills it; one more of any kind is refused.
    const auto mod = box.load("tests.handlers.full", R"lua(
        rhp.after(1000, function() end)
        rhp.every_frame(function() end)
        rhp.on("tests.handlers.ping", function() end)
        rhp.spawn(function() while true do rhp.next_frame() end end)
    )lua");
    REQUIRE(mod);
    for (const std::string_view more : {kTimer, kFrames, kSubscription, kTask}) {
        CHECK(refused(more));
    }

    // Reverting the module that registered them makes room for as many.
    REQUIRE(box.revert(*mod));
    REQUIRE(box.exec(R"lua(
        rhp.after(0, function() end)
        rhp.every_frame(function() end)
        sub = rhp.on("tests.handlers.ping", function() end)
        task = rhp.spawn(function() while true do rhp.next_frame() end end)
    )lua"));
    CHECK(refused(kTimer));

    // So do rhp.off, a one-shot timer once it fired, and a task's end.
    REQUIRE(box.exec("rhp.off(sub)"));
    REQUIRE(box.exec(kSubscription));
    CHECK(refused(kSubscription));
    box.pump(); // the timer fires
    REQUIRE(box.exec(kFrames));
    CHECK(refused(kFrames));
    REQUIRE(box.exec("task:cancel()"));
    REQUIRE(box.exec(kTask));
    CHECK(refused(kTask));
    box.pump(); // that task runs and ends
    REQUIRE(box.exec(kTimer));
    CHECK(refused(kTimer));
}

TEST_CASE("without limits.handlers a sandbox keeps as many handlers as it registers", "[script][limits][handlers]") {
    sandbox box = make_box();
    REQUIRE(box.exec(R"lua(
        for i = 1, 1000 do
            rhp.after(1000, function() end)
            rhp.on("tests.handlers.many", function() end)
        end
    )lua"));
}
