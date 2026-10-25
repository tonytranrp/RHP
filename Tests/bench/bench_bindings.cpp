// B: calling C++ from Lua. A Rhp::lib function, variable and handle (with a method and a
// property), next to the same work as a plain lua_CFunction registered by hand (what RHP's DSL
// replaces); and an asynchronous binding whose result is already there.
#include <cstdint>
#include <cstring>

#include <rhp/core/async.hpp>

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
Rhp::async<int> ready_add(int a, int b) {
    return Rhp::async<int>::ready(a + b);
}

using bench_lib = Rhp::lib<"bench">        //
    ::fn<"add", &add>                      //
    ::var<"speed", &g_speed>               //
    ::handle<"unit", unit_id, &unit_alive> //
    ::fn<"first_unit", &first_unit>::fn<"unit_number", &unit_number>
    ::method<"number", &unit_number>  //
    ::property<"id", &unit_number>    //
    ::fn<"ready_add", &ready_add>;

// The raw twin of a handle: a userdata holding the id, a methods table as __index; the property
// version looks the key up in a C __index.
int raw_unit_number(lua_State* L) {
    std::uint32_t v = 0;
    std::memcpy(&v, luaL_checkudata(L, 1, "raw.unit"), sizeof v);
    lua_pushinteger(L, v);
    return 1;
}

int raw_first_unit(lua_State* L) {
    const std::uint32_t v = 7;
    std::memcpy(lua_newuserdatauv(L, sizeof v, 0), &v, sizeof v);
    luaL_setmetatable(L, "raw.unit");
    return 1;
}

int raw_prop_index(lua_State* L) {
    std::uint32_t v = 0;
    std::memcpy(&v, luaL_checkudata(L, 1, "raw.prop_unit"), sizeof v);
    const char* key = luaL_checkstring(L, 2);
    if (std::strcmp(key, "id") == 0) {
        lua_pushinteger(L, v);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int raw_first_prop_unit(lua_State* L) {
    const std::uint32_t v = 7;
    std::memcpy(lua_newuserdatauv(L, sizeof v, 0), &v, sizeof v);
    luaL_setmetatable(L, "raw.prop_unit");
    return 1;
}

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
function M.method() local u = bench.first_unit() local s = 0 for i = 1, 10000 do s = s + u:number() end return s end
function M.property() local u = bench.first_unit() local s = 0 for i = 1, 10000 do s = s + u.id end return s end
function M.ready() local s = 0 for i = 1, 10000 do s = bench.ready_add(s, 1) end return s end
return M
)";

constexpr std::string_view kRawCalls = R"(
local M = {}
function M.add() local s = 0 for i = 1, 10000 do s = bench.add(s, 1) end return s end
function M.add_local() local add = bench.add local s = 0 for i = 1, 10000 do s = add(s, 1) end return s end
function M.read_var() local s = 0 for i = 1, 10000 do s = s + bench.speed end return s end
function M.method() local u = bench.first_unit() local s = 0 for i = 1, 10000 do s = s + u:number() end return s end
function M.property() local u = bench.first_prop_unit() local s = 0 for i = 1, 10000 do s = s + u.id end return s end
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
    lua_pushcfunction(raw.get(), &raw_first_unit);
    lua_setfield(raw.get(), -2, "first_unit");
    lua_pushcfunction(raw.get(), &raw_first_prop_unit);
    lua_setfield(raw.get(), -2, "first_prop_unit");
    lua_setglobal(raw.get(), "bench");
    luaL_newmetatable(raw.get(), "raw.unit");
    lua_newtable(raw.get());
    lua_pushcfunction(raw.get(), &raw_unit_number);
    lua_setfield(raw.get(), -2, "number");
    lua_setfield(raw.get(), -2, "__index");
    lua_pop(raw.get(), 1);
    luaL_newmetatable(raw.get(), "raw.prop_unit");
    lua_pushcfunction(raw.get(), &raw_prop_index);
    lua_setfield(raw.get(), -2, "__index");
    lua_pop(raw.get(), 1);
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
    BENCHMARK("bindings raw: 10k method calls on a handle") {
        return call_raw("method");
    };
    BENCHMARK("bindings rhp: 10k method calls on a handle") {
        return call_box("method");
    };
    BENCHMARK("bindings raw: 10k property reads on a handle") {
        return call_raw("property");
    };
    BENCHMARK("bindings rhp: 10k property reads on a handle") {
        return call_box("property");
    };
    BENCHMARK("bindings rhp: 10k async calls already ready") {
        return call_box("ready");
    };

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
