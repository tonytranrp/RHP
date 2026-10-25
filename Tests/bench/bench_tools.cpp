// Stage 11 tools: what the debugger costs while armed (a breakpoint somewhere else), what the
// profiler costs at two sampling rates, and tunables against plain Lua globals. Each group's raw
// twin runs the same work in a plain lua_State.
#include <cstdint>
#include <string_view>
#include <vector>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>

namespace bench_tools_fixture {

constexpr std::string_view kWork = R"(
local M = {}
function M.loop() local s = 0 for i = 1, 100000 do s = s + (i % 7) end return s end
local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
function M.fib() return fib(22) end
return M
)";

inline double g_speed = 1.0;

using tools_lib = Rhp::lib<"benchtools">::var<"speed", &g_speed, Rhp::range<0.0, 100.0>, Rhp::unit<"m/s">>;

} // namespace bench_tools_fixture

using namespace bench_tools_fixture;

TEST_CASE("bench tools: an armed debugger and the profiler on script work", "[bench][tools]") {
    rhp_bench::raw_lua raw;
    raw.define("M", kWork);
    const auto call_raw = [&](const char* fn) {
        lua_getglobal(raw.get(), "M");
        lua_getfield(raw.get(), -1, fn);
        lua_remove(raw.get(), -2);
        REQUIRE(lua_pcall(raw.get(), 0, 1, 0) == LUA_OK);
        const lua_Integer r = lua_tointeger(raw.get(), -1);
        lua_pop(raw.get(), 1);
        return r;
    };

    // No tool: the reference the other groups are read against (what the cancel hook costs).
    Rhp::script::sandbox plain{rhp_bench::quiet()};
    const auto plain_mod = rhp_bench::load(plain, "bench.work", kWork);
    // A breakpoint in another module: every line runs the line hook, the bitmap rejects it.
    Rhp::script::sandbox armed{rhp_bench::quiet()};
    const auto armed_mod = rhp_bench::load(armed, "bench.work", kWork);
    REQUIRE(armed.set_breakpoints("bench.elsewhere", std::vector<std::uint32_t>{1}));
    // A breakpoint on a line number this module's loop runs on, but in another module: each of
    // those lines also pays a lua_getinfo and a source lookup.
    Rhp::script::sandbox same_lines{rhp_bench::quiet()};
    const auto same_mod = rhp_bench::load(same_lines, "bench.work", kWork);
    REQUIRE(same_lines.set_breakpoints("bench.other", std::vector<std::uint32_t>{3}));

    // A breakpoint inside this module on a line nothing runs: the same as elsewhere.
    Rhp::script::sandbox inside{rhp_bench::quiet()};
    const auto inside_mod = rhp_bench::load(inside, "bench.work", kWork);
    REQUIRE(inside.set_breakpoints("bench.work", std::vector<std::uint32_t>{6}));

    Rhp::script::sandbox every_1000{rhp_bench::quiet()};
    const auto p1000_mod = rhp_bench::load(every_1000, "bench.work", kWork);
    REQUIRE(every_1000.start_profile({.interval = 1000}));
    Rhp::script::sandbox every_100{rhp_bench::quiet()};
    const auto p100_mod = rhp_bench::load(every_100, "bench.work", kWork);
    REQUIRE(every_100.start_profile({.interval = 100}));

    const auto call = [](Rhp::script::sandbox& box, Rhp::module_id mod, std::string_view fn) {
        auto r = box.call(mod, fn);
        REQUIRE(r);
        return r->size();
    };

    BENCHMARK("tools-off raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("tools-off rhp: 100k arithmetic loop") {
        return call(plain, plain_mod, "loop");
    };
    BENCHMARK("tools-off raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("tools-off rhp: fib(22)") {
        return call(plain, plain_mod, "fib");
    };
    BENCHMARK("debug-armed raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("debug-armed rhp: 100k arithmetic loop") {
        return call(armed, armed_mod, "loop");
    };
    BENCHMARK("debug-armed raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("debug-armed rhp: fib(22)") {
        return call(armed, armed_mod, "fib");
    };
    BENCHMARK("debug-line raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("debug-line rhp: 100k arithmetic loop") {
        return call(same_lines, same_mod, "loop");
    };
    BENCHMARK("debug-inside raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("debug-inside rhp: 100k arithmetic loop") {
        return call(inside, inside_mod, "loop");
    };
    BENCHMARK("debug-inside raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("debug-inside rhp: fib(22)") {
        return call(inside, inside_mod, "fib");
    };
    BENCHMARK("profile-1000 raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("profile-1000 rhp: 100k arithmetic loop") {
        return call(every_1000, p1000_mod, "loop");
    };
    BENCHMARK("profile-1000 raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("profile-1000 rhp: fib(22)") {
        return call(every_1000, p1000_mod, "fib");
    };
    BENCHMARK("profile-100 raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("profile-100 rhp: 100k arithmetic loop") {
        return call(every_100, p100_mod, "loop");
    };
    BENCHMARK("profile-100 raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("profile-100 rhp: fib(22)") {
        return call(every_100, p100_mod, "fib");
    };
    (void)every_1000.stop_profile();
    (void)every_100.stop_profile();
}

TEST_CASE("bench tools: tunables against plain globals", "[bench][tools]") {
    rhp_bench::raw_lua raw;
    lua_pushnumber(raw.get(), 1.0);
    lua_setglobal(raw.get(), "speed");
    Rhp::script::sandbox box{rhp_bench::quiet()};
    REQUIRE(box.install<tools_lib>());

    BENCHMARK("tunables raw: read one variable") {
        lua_getglobal(raw.get(), "speed");
        const lua_Number v = lua_tonumber(raw.get(), -1);
        lua_pop(raw.get(), 1);
        return v;
    };
    BENCHMARK("tunables rhp: read one variable") {
        auto t = box.tunables("benchtools.speed");
        REQUIRE(t);
        return t->size();
    };
    double next = 1.0;
    BENCHMARK("tunables raw: write one variable") {
        next = next > 50.0 ? 1.0 : next + 1.0;
        lua_pushnumber(raw.get(), next);
        lua_setglobal(raw.get(), "speed");
        return next;
    };
    BENCHMARK("tunables rhp: write one variable") {
        next = next > 50.0 ? 1.0 : next + 1.0;
        REQUIRE(box.tune("benchtools.speed", Rhp::value{next}));
        return next;
    };
    (void)box.revert_all(); // the journal of every write above
}
