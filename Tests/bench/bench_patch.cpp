// C: patch points from C++. Unpatched (the cost every call site pays forever) next to a direct
// call, and patched by a Lua handler with and without `original`, next to lua_pcall of the same
// handler by hand. Every patch is reverted before the case ends (patch points are process-wide).
#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/script/patch_point.hpp>

namespace bench_patch_fixture {

int damage_default(int base, int target) {
    return base * 2 + target;
}
inline constexpr Rhp::patch_point<"bench.patch.damage", &damage_default> damage{};

// Keeps the optimizer from folding the direct call away.
int (*volatile g_direct)(int, int) = &damage_default;

} // namespace bench_patch_fixture

using namespace bench_patch_fixture;

TEST_CASE("bench patch: unpatched and patched patch points", "[bench][patch]") {
    int i = 0;
    BENCHMARK("patch raw: call of the C++ default") {
        return g_direct(++i, 3);
    };
    BENCHMARK("patch rhp: call of the C++ default") {
        return damage(++i, 3);
    };

    rhp_bench::raw_lua raw;
    raw.define("handler", "return function(original, base, target) return base end");
    BENCHMARK("patch raw: call into a Lua handler") {
        lua_getglobal(raw.get(), "handler");
        lua_pushnil(raw.get());
        lua_pushinteger(raw.get(), ++i);
        lua_pushinteger(raw.get(), 3);
        lua_pcall(raw.get(), 3, 1, 0);
        const auto r = lua_tointeger(raw.get(), -1);
        lua_pop(raw.get(), 1);
        return r;
    };

    Rhp::script::sandbox box{rhp_bench::quiet()};
    const auto replace = rhp_bench::load(box, "bench.patch.replace", R"(rhp.patch("bench.patch.damage", function(original, base, target) return base end))");
    BENCHMARK("patch rhp: call into a Lua handler") {
        return damage(++i, 3);
    };
    REQUIRE(box.unload(replace));

    const auto wrap = rhp_bench::load(box, "bench.patch.wrap", R"(rhp.patch("bench.patch.damage", function(original, base, target) return original(base, target) + 1 end))");
    BENCHMARK("patch rhp: call into a Lua handler calling original") {
        return damage(++i, 3);
    };
    REQUIRE(box.unload(wrap));

    CHECK(damage.depth() == 0);
}
