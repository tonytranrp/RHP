// V: typed views, struct views and buffers. A span a binding returns (re-found on every access,
// writes journaled) next to a raw userdata with a hand-written __index / __newindex over the same
// memory and a plain Lua table; a struct view's fields next to a raw userdata and a table's fields;
// a span handed to C++ next to a C function reading a table; buffer reads next to string.unpack.
// "unchecked" runs the same calls in a sandbox with limits.cancel_checks = kNone.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/script/lib.hpp>

namespace bench_views_fixture {

constexpr std::size_t kCount = 10000;

std::vector<float> g_floats(kCount, 0.5f);

std::span<float> floats() {
    return g_floats;
}

double sum(std::span<const float> v) {
    return std::accumulate(v.begin(), v.end(), 0.0);
}

struct particle {
    float x = 0;
    float y = 0;
    float vx = 1;
    float vy = 2;
};

particle g_particle{};

particle& the_particle() {
    return g_particle;
}

using bench_lib = Rhp::lib<"bench">                                                                                                          //
    ::fn<"floats", &floats>::fn<"sum", &sum>                                                                                                 //
    ::view<"particle", particle>::field<"x", &particle::x>::field<"y", &particle::y>::field<"vx", &particle::vx>::field<"vy", &particle::vy> //
    ::fn<"get_particle", &the_particle>;

// The raw twin of a typed view: a userdata holding the pointer and the length, a C __index and
// __newindex that check the index and convert the element.
struct raw_floats {
    float* data;
    std::size_t size;
};

int raw_floats_index(lua_State* L) {
    const auto* v = static_cast<const raw_floats*>(luaL_checkudata(L, 1, "raw.floats"));
    const lua_Integer i = luaL_checkinteger(L, 2);
    if (i < 1 || static_cast<std::size_t>(i) > v->size) {
        return luaL_error(L, "index %d out of range", static_cast<int>(i));
    }
    lua_pushnumber(L, v->data[i - 1]);
    return 1;
}

int raw_floats_newindex(lua_State* L) {
    const auto* v = static_cast<const raw_floats*>(luaL_checkudata(L, 1, "raw.floats"));
    const lua_Integer i = luaL_checkinteger(L, 2);
    if (i < 1 || static_cast<std::size_t>(i) > v->size) {
        return luaL_error(L, "index %d out of range", static_cast<int>(i));
    }
    v->data[i - 1] = static_cast<float>(luaL_checknumber(L, 3));
    return 0;
}

int raw_floats_len(lua_State* L) {
    lua_pushinteger(L, static_cast<lua_Integer>(static_cast<const raw_floats*>(luaL_checkudata(L, 1, "raw.floats"))->size));
    return 1;
}

std::vector<float> g_raw_floats(kCount, 0.5f);
std::vector<float> g_raw_buffer(kCount, 0.0f);

int raw_new_floats(lua_State* L, std::vector<float>& memory) {
    auto* v = static_cast<raw_floats*>(lua_newuserdatauv(L, sizeof(raw_floats), 0));
    *v = raw_floats{memory.data(), memory.size()};
    luaL_setmetatable(L, "raw.floats");
    return 1;
}

int raw_floats_fn(lua_State* L) {
    return raw_new_floats(L, g_raw_floats);
}

int raw_buffer_fn(lua_State* L) {
    return raw_new_floats(L, g_raw_buffer);
}

// The raw twin of a C++ function taking a span: a C function summing a table.
int raw_sum(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    const lua_Integer n = luaL_len(L, 1);
    double s = 0;
    for (lua_Integer i = 1; i <= n; ++i) {
        lua_rawgeti(L, 1, i);
        s += lua_tonumber(L, -1);
        lua_pop(L, 1);
    }
    lua_pushnumber(L, s);
    return 1;
}

// The raw twin of a struct view: a userdata pointing at the object, fields found by name.
particle g_raw_particle{};

int raw_particle_index(lua_State* L) {
    auto* p = *static_cast<particle**>(luaL_checkudata(L, 1, "raw.particle"));
    const char* key = luaL_checkstring(L, 2);
    float* field = std::strcmp(key, "x") == 0 ? &p->x : std::strcmp(key, "y") == 0 ? &p->y
                                                    : std::strcmp(key, "vx") == 0  ? &p->vx
                                                                                   : &p->vy;
    lua_pushnumber(L, *field);
    return 1;
}

int raw_particle_newindex(lua_State* L) {
    auto* p = *static_cast<particle**>(luaL_checkudata(L, 1, "raw.particle"));
    const char* key = luaL_checkstring(L, 2);
    float* field = std::strcmp(key, "x") == 0 ? &p->x : std::strcmp(key, "y") == 0 ? &p->y
                                                    : std::strcmp(key, "vx") == 0  ? &p->vx
                                                                                   : &p->vy;
    *field = static_cast<float>(luaL_checknumber(L, 3));
    return 0;
}

int raw_particle_fn(lua_State* L) {
    *static_cast<particle**>(lua_newuserdatauv(L, sizeof(particle*), 0)) = &g_raw_particle;
    luaL_setmetatable(L, "raw.particle");
    return 1;
}

constexpr std::string_view kViews = R"(
local M = {}
function M.sum() local v = bench.floats() local s = 0 for i = 1, #v do s = s + v[i] end return s end
function M.sum_table() local s = 0 for i = 1, #T do s = s + T[i] end return s end
function M.write() local v = bench.floats() for i = 1, #v do v[i] = i end return 0 end
function M.write_buffer() local v = B for i = 1, #v do v[i] = i end return 0 end
function M.sum_cpp() return bench.sum(bench.floats()) end
function M.sum_cpp_table() return bench.sum(T) end
function M.fields() local p = bench.get_particle() for i = 1, 10000 do p.x = p.x + p.vx end return p.x end
function M.fields_table() local p = P for i = 1, 10000 do p.x = p.x + p.vx end return p.x end
function M.field_reads() local p, s = bench.get_particle(), 0 for i = 1, 10000 do s = s + p.vx end return s end
function M.field_reads_table() local p, s = P, 0 for i = 1, 10000 do s = s + p.vx end return s end
function M.write10() local v = bench.floats() for k = 1, 10 do for i = 1, #v do v[i] = i end end return 0 end
function M.read_buffer() local b, s = U, 0 for i = 1, 4 * 10000, 4 do s = s + b:read_u32(i) end return s end
function M.read_string() local b, s, unpack = S, 0, string.unpack for i = 1, 4 * 10000, 4 do s = s + unpack('<I4', b, i) end return s end
return M
)";

constexpr std::string_view kRawViews = R"(
local M = {}
function M.sum() local v = bench.floats() local s = 0 for i = 1, #v do s = s + v[i] end return s end
function M.sum_table() local s = 0 for i = 1, #T do s = s + T[i] end return s end
function M.write() local v = bench.floats() for i = 1, #v do v[i] = i end return 0 end
function M.write_buffer() local v = bench.buffer() for i = 1, #v do v[i] = i end return 0 end
function M.sum_cpp() return bench.sum(T) end
function M.fields() local p = bench.get_particle() for i = 1, 10000 do p.x = p.x + p.vx end return p.x end
function M.fields_table() local p = P for i = 1, 10000 do p.x = p.x + p.vx end return p.x end
function M.field_reads() local p, s = bench.get_particle(), 0 for i = 1, 10000 do s = s + p.vx end return s end
function M.field_reads_table() local p, s = P, 0 for i = 1, 10000 do s = s + p.vx end return s end
function M.write10() local v = bench.floats() for k = 1, 10 do for i = 1, #v do v[i] = i end end return 0 end
function M.read_string() local b, s, unpack = S, 0, string.unpack for i = 1, 4 * 10000, 4 do s = s + unpack('<I4', b, i) end return s end
return M
)";

// Globals both sides use: a table of 10k numbers, a table particle, a 40000-byte string of u32s.
constexpr std::string_view kGlobals = R"(
T = {} for i = 1, 10000 do T[i] = 0.5 end
P = {x = 0, y = 0, vx = 1, vy = 2}
local parts = {} for i = 1, 10000 do parts[i] = string.pack('<I4', i) end
S = table.concat(parts)
)";

} // namespace bench_views_fixture

using namespace bench_views_fixture;

TEST_CASE("bench views: spans struct views and buffers next to raw userdata and tables", "[bench][views]") {
    rhp_bench::raw_lua raw;
    lua_State* R = raw.get();
    lua_newtable(R);
    lua_pushcfunction(R, &raw_floats_fn);
    lua_setfield(R, -2, "floats");
    lua_pushcfunction(R, &raw_buffer_fn);
    lua_setfield(R, -2, "buffer");
    lua_pushcfunction(R, &raw_sum);
    lua_setfield(R, -2, "sum");
    lua_pushcfunction(R, &raw_particle_fn);
    lua_setfield(R, -2, "get_particle");
    lua_setglobal(R, "bench");
    luaL_newmetatable(R, "raw.floats");
    lua_pushcfunction(R, &raw_floats_index);
    lua_setfield(R, -2, "__index");
    lua_pushcfunction(R, &raw_floats_newindex);
    lua_setfield(R, -2, "__newindex");
    lua_pushcfunction(R, &raw_floats_len);
    lua_setfield(R, -2, "__len");
    lua_pop(R, 1);
    luaL_newmetatable(R, "raw.particle");
    lua_pushcfunction(R, &raw_particle_index);
    lua_setfield(R, -2, "__index");
    lua_pushcfunction(R, &raw_particle_newindex);
    lua_setfield(R, -2, "__newindex");
    lua_pop(R, 1);
    REQUIRE(luaL_dostring(R, std::string{kGlobals}.c_str()) == LUA_OK);
    raw.define("M", kRawViews);
    const auto call_raw = [&](const char* fn) {
        lua_getglobal(R, "M");
        lua_getfield(R, -1, fn);
        lua_remove(R, -2);
        REQUIRE(lua_pcall(R, 0, 1, 0) == LUA_OK);
        const lua_Number r = lua_tonumber(R, -1);
        lua_pop(R, 1);
        return r;
    };

    // The module's globals: the same tables, plus a buffer (B: a typed view of it) and U (u32s).
    const std::string globals = std::string{kGlobals} + R"(
local buf = rhp.buffer.new(4 * 10000)
B = buf:view('f32')
U = rhp.buffer.from(S)
)";
    const auto make = [&](Rhp::script::sandbox& box) {
        REQUIRE(box.install<bench_lib>());
        return rhp_bench::load(box, "bench.views", globals + std::string{kViews});
    };
    Rhp::script::sandbox box{rhp_bench::quiet()};
    const auto mod = make(box);
    const auto call_box = [&](std::string_view fn) {
        auto r = box.call(mod, fn);
        REQUIRE(r);
        return r->size();
    };
    Rhp::script::sandbox_options fast = rhp_bench::quiet();
    fast.limits.cancel_checks = Rhp::cancel_scope::kNone;
    Rhp::script::sandbox unchecked{std::move(fast)};
    const auto fast_mod = make(unchecked);
    const auto call_unchecked = [&](std::string_view fn) {
        auto r = unchecked.call(fast_mod, fn);
        REQUIRE(r);
        return r->size();
    };

    BENCHMARK("views raw: sum 10k floats in a table") {
        return call_raw("sum_table");
    };
    BENCHMARK("views raw: sum 10k floats through a span") {
        return call_raw("sum");
    };
    BENCHMARK("views rhp: sum 10k floats through a span") {
        return call_box("sum");
    };
    BENCHMARK("views unchecked: sum 10k floats through a span") {
        return call_unchecked("sum");
    };
    BENCHMARK("views raw: write 10k floats into a buffer view") {
        return call_raw("write_buffer");
    };
    BENCHMARK("views rhp: write 10k floats into a buffer view") {
        return call_box("write_buffer");
    };
    BENCHMARK("views unchecked: write 10k floats into a buffer view") {
        return call_unchecked("write_buffer");
    };
    BENCHMARK("views raw: sum 10k floats in C++") {
        return call_raw("sum_cpp");
    };
    BENCHMARK("views rhp: sum 10k floats in C++") {
        return call_box("sum_cpp");
    };
    BENCHMARK("views rhp: sum 10k floats of a table in C++") {
        return call_box("sum_cpp_table");
    };
    BENCHMARK("views raw: 10k field reads and writes of a table") {
        return call_raw("fields_table");
    };
    BENCHMARK("views raw: 10k field reads and writes") {
        return call_raw("fields");
    };
    BENCHMARK("views raw: 10k field reads of a table") {
        return call_raw("field_reads_table");
    };
    BENCHMARK("views raw: 10k field reads") {
        return call_raw("field_reads");
    };
    BENCHMARK("views rhp: 10k field reads") {
        return call_box("field_reads");
    };
    BENCHMARK("views unchecked: 10k field reads") {
        return call_unchecked("field_reads");
    };
    // The raw twin reads a string with string.unpack, RHP a buffer with read_u32.
    BENCHMARK("views raw: 10k u32 reads") {
        return call_raw("read_string");
    };
    BENCHMARK("views rhp: 10k u32 reads") {
        return call_box("read_buffer");
    };
    BENCHMARK("views unchecked: 10k u32 reads") {
        return call_unchecked("read_buffer");
    };

    // Host memory: every write is journaled, so these include undoing them (one journal entry per
    // request and span or object: revert_to restores the bytes each request changed). The raw twin
    // writes without a journal.
    REQUIRE(box.checkpoint("bench"));
    REQUIRE(unchecked.checkpoint("bench"));
    BENCHMARK("views raw: write 10k floats through a span") {
        return call_raw("write");
    };
    BENCHMARK("views rhp: write 10k floats through a span") {
        const auto n = call_box("write");
        return n + box.revert_to("bench")->undone;
    };
    BENCHMARK("views unchecked: write 10k floats through a span") {
        const auto n = call_unchecked("write");
        return n + unchecked.revert_to("bench")->undone;
    };
    BENCHMARK("views raw: write 10k floats through a span 10 times") {
        return call_raw("write10");
    };
    BENCHMARK("views rhp: write 10k floats through a span 10 times") {
        const auto n = call_box("write10");
        return n + box.revert_to("bench")->undone;
    };
    BENCHMARK("views rhp: 10k field reads and writes") {
        const auto n = call_box("fields");
        return n + box.revert_to("bench")->undone;
    };
    BENCHMARK("views unchecked: 10k field reads and writes") {
        const auto n = call_unchecked("fields");
        return n + unchecked.revert_to("bench")->undone;
    };
}
