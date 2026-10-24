// B: calling C++ from Lua. A Rhp::lib function, variable and handle, next to the same work as a
// plain lua_CFunction registered by hand (what RHP's DSL replaces).
#include <cstdint>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/script/lib.hpp>

namespace bench_bindings_fixture {

int add(int a, int b) {
    return a + b;
}
double g_speed = 1.0;

struct unit_id {
    std::uint32_t v = 0;
    [[nodiscard]] bool operator==(const unit_id&) const = default;
};
bool unit_alive(const unit_id& u) {
    return u.v != 0;
}
unit_id first_unit() {
    return unit_id{7};
}
std::uint32_t unit_number(unit_id u) {
    return u.v;
}

using bench_lib = Rhp::lib<"bench">        //
    ::fn<"add", &add>                      //
    ::var<"speed", &g_speed>               //
    ::handle<"unit", unit_id, &unit_alive> //
    ::fn<"first_unit", &first_unit>::fn<"unit_number", &unit_number>;

int raw_add(lua_State* L) {
    const auto a = static_cast<int>(luaL_checkinteger(L, 1));
    const auto b = static_cast<int>(luaL_checkinteger(L, 2));
    lua_pushinteger(L, add(a, b));
    return 1;
}

constexpr std::string_view kCalls = R"(
local M = {}
function M.add() local s = 0 for i = 1, 10000 do s = bench.add(s, 1) end return s end
function M.add_local() local add = bench.add local s = 0 for i = 1, 10000 do s = add(s, 1) end return s end
function M.read_var() local s = 0 for i = 1, 10000 do s = s + bench.speed end return s end
function M.write_var() for i = 1, 10000 do bench.speed = i end return 0 end
function M.handles() local s = 0 for i = 1, 10000 do s = s + bench.unit_number(bench.first_unit()) end return s end
return M
)";

constexpr std::string_view kRawCalls = R"(
local M = {}
function M.add() local s = 0 for i = 1, 10000 do s = bench.add(s, 1) end return s end
function M.add_local() local add = bench.add local s = 0 for i = 1, 10000 do s = add(s, 1) end return s end
function M.read_var() local s = 0 for i = 1, 10000 do s = s + bench.speed end return s end
return M
)";

} // namespace bench_bindings_fixture

using namespace bench_bindings_fixture;

TEST_CASE("bench bindings: Rhp::lib calls next to hand-written C functions", "[bench][bindings]") {
    rhp_bench::raw_lua raw;
    lua_newtable(raw.get());
    lua_pushcfunction(raw.get(), &raw_add);
    lua_setfield(raw.get(), -2, "add");
    lua_pushnumber(raw.get(), 1.0);
    lua_setfield(raw.get(), -2, "speed");
    lua_setglobal(raw.get(), "bench");
    raw.define("M", kRawCalls);
    const auto call_raw = [&](const char* fn) {
        lua_getglobal(raw.get(), "M");
        lua_getfield(raw.get(), -1, fn);
        lua_remove(raw.get(), -2);
        REQUIRE(lua_pcall(raw.get(), 0, 1, 0) == LUA_OK);
        const lua_Number r = lua_tonumber(raw.get(), -1);
        lua_pop(raw.get(), 1);
        return r;
    };

    Rhp::script::sandbox box{rhp_bench::quiet()};
    REQUIRE(box.install<bench_lib>());
    const auto mod = rhp_bench::load(box, "bench.calls", kCalls);
    const auto call_box = [&](std::string_view fn) {
        auto r = box.call(mod, fn);
        REQUIRE(r);
        return r->size();
    };

    BENCHMARK("bindings raw: 10k calls of bench.add") {
        return call_raw("add");
    };
    BENCHMARK("bindings rhp: 10k calls of bench.add") {
        return call_box("add");
    };
    BENCHMARK("bindings raw: 10k calls of bench.add held in a local") {
        return call_raw("add_local");
    };
    BENCHMARK("bindings rhp: 10k calls of bench.add held in a local") {
        return call_box("add_local");
    };
    BENCHMARK("bindings raw: 10k reads of bench.speed") {
        return call_raw("read_var");
    };
    BENCHMARK("bindings rhp: 10k reads of bench.speed") {
        return call_box("read_var");
    };
    BENCHMARK("bindings rhp: 10k handle round trips") { return call_box("handles"); };

    // Every write is journaled (it can be undone), so this one includes undoing them: run in the
    // scratch module of a second sandbox, then revert_all.
    Rhp::script::sandbox writer{rhp_bench::quiet()};
    REQUIRE(writer.install<bench_lib>());
    BENCHMARK("bindings rhp: 10k journaled var writes then their revert") {
        auto r = writer.exec("for i = 1, 10000 do bench.speed = i end");
        REQUIRE(r);
        return writer.revert_all().undone;
    };
}
