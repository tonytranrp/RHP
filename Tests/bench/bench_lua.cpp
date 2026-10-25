// A: plain Lua work, run by a raw lua_State and by a sandbox (a module function called through
// sandbox::call). The ratio is what RHP's request machinery and hooks cost on script code itself.
// "unchecked" runs the same calls with limits.cancel_checks = kNone: no cancel hook, so the gap
// between rhp and unchecked is what being cancellable costs.
#include <string_view>
#include <utility>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

namespace bench_lua_fixture {

// Each chunk returns a table of functions; the raw twin and the sandbox module run the same text.
constexpr std::string_view kWork = R"(
local M = {}
function M.loop() local s = 0 for i = 1, 100000 do s = s + (i % 7) end return s end
local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
function M.fib() return fib(22) end
function M.table() local t = {} for i = 1, 10000 do t[i] = i end local s = 0 for _, v in ipairs(t) do s = s + v end return s end
function M.strings() local p = {} for i = 1, 1000 do p[#p + 1] = tostring(i) end return #table.concat(p, ",") end
function M.closures() local s = 0 for i = 1, 10000 do local f = function() return i end s = s + f() end return s end
function M.coroutines() local co = coroutine.wrap(function() for i = 1, 1000 do coroutine.yield(i) end end) local s = 0 for _ = 1, 1000 do s = s + co() end return s end
function M.pcall_errors() local n = 0 for _ = 1, 1000 do if not pcall(error, "x") then n = n + 1 end end return n end
function M.empty() return 0 end
return M
)";

} // namespace bench_lua_fixture

using namespace bench_lua_fixture;

TEST_CASE("bench lua: script work raw and in a sandbox", "[bench][lua]") {
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

    Rhp::script::sandbox box{rhp_bench::quiet()};
    const auto mod = rhp_bench::load(box, "bench.work", kWork);
    const auto call_box = [&](std::string_view fn) {
        auto r = box.call(mod, fn);
        REQUIRE(r);
        return r->size();
    };

    Rhp::script::sandbox_options fast = rhp_bench::quiet();
    fast.limits.cancel_checks = Rhp::cancel_scope::kNone;
    Rhp::script::sandbox unchecked{std::move(fast)};
    const auto fast_mod = rhp_bench::load(unchecked, "bench.work", kWork);
    const auto call_unchecked = [&](std::string_view fn) {
        auto r = unchecked.call(fast_mod, fn);
        REQUIRE(r);
        return r->size();
    };

    BENCHMARK("lua raw: empty function call") {
        return call_raw("empty");
    };
    BENCHMARK("lua rhp: empty function call") {
        return call_box("empty");
    };
    BENCHMARK("lua unchecked: empty function call") {
        return call_unchecked("empty");
    };
    BENCHMARK("lua raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("lua rhp: 100k arithmetic loop") {
        return call_box("loop");
    };
    BENCHMARK("lua unchecked: 100k arithmetic loop") {
        return call_unchecked("loop");
    };
    BENCHMARK("lua raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("lua rhp: fib(22)") {
        return call_box("fib");
    };
    BENCHMARK("lua unchecked: fib(22)") {
        return call_unchecked("fib");
    };
    BENCHMARK("lua raw: 10k table fill and ipairs") {
        return call_raw("table");
    };
    BENCHMARK("lua rhp: 10k table fill and ipairs") {
        return call_box("table");
    };
    BENCHMARK("lua unchecked: 10k table fill and ipairs") {
        return call_unchecked("table");
    };
    BENCHMARK("lua raw: 1k tostring and concat") {
        return call_raw("strings");
    };
    BENCHMARK("lua rhp: 1k tostring and concat") {
        return call_box("strings");
    };
    BENCHMARK("lua raw: 10k closures") {
        return call_raw("closures");
    };
    BENCHMARK("lua rhp: 10k closures") {
        return call_box("closures");
    };
    BENCHMARK("lua unchecked: 10k closures") {
        return call_unchecked("closures");
    };
    BENCHMARK("lua raw: 1k coroutine yields") {
        return call_raw("coroutines");
    };
    BENCHMARK("lua rhp: 1k coroutine yields") {
        return call_box("coroutines");
    };
    BENCHMARK("lua raw: 1k pcall errors") {
        return call_raw("pcall_errors");
    };
    BENCHMARK("lua rhp: 1k pcall errors") {
        return call_box("pcall_errors");
    };
}

TEST_CASE("bench lua: compiling and running a chunk", "[bench][lua]") {
    rhp_bench::raw_lua raw;
    Rhp::script::sandbox box{rhp_bench::quiet()};

    BENCHMARK("lua raw: load and run return 1") {
        luaL_loadstring(raw.get(), "return 1");
        lua_pcall(raw.get(), 0, 1, 0);
        const lua_Integer r = lua_tointeger(raw.get(), -1);
        lua_pop(raw.get(), 1);
        return r;
    };
    BENCHMARK("lua rhp: exec return 1") {
        return box.exec("return 1")->size();
    };
    BENCHMARK("lua rhp: exec returning a 100-entry table") {
        return box.exec("local t = {} for i = 1, 100 do t[i] = i end return t")->size();
    };
}
