// D: events. A C++ lua_event fired with nobody listening (the cost game code pays by default),
// fired to N Lua handlers, and rhp.publish delivered at pump(); next to calling N Lua functions
// by hand.
#include <format>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/script/lua_event.hpp>

namespace bench_events_fixture {

inline constexpr Rhp::lua_event<"bench.events.nobody", int> nobody{};
inline constexpr Rhp::lua_event<"bench.events.tick", int> tick{};

} // namespace bench_events_fixture

using namespace bench_events_fixture;

TEST_CASE("bench events: firing and publishing", "[bench][events]") {
    int i = 0;
    BENCHMARK("events rhp: lua_event fire with no listener") {
        nobody.fire(++i);
        return i;
    };

    for (const int handlers : {1, 10, 100}) {
        rhp_bench::raw_lua raw;
        raw.define("handlers", std::format("local t = {{}} for i = 1, {} do t[i] = function(v) end end return t", handlers));
        BENCHMARK(std::format("events raw: deliver to {} handlers", handlers)) {
            lua_getglobal(raw.get(), "handlers");
            for (int h = 1; h <= handlers; ++h) {
                lua_rawgeti(raw.get(), -1, h);
                lua_pushinteger(raw.get(), ++i);
                lua_pcall(raw.get(), 1, 0, 0);
            }
            lua_pop(raw.get(), 1);
            return i;
        };

        Rhp::script::sandbox box{rhp_bench::quiet()};
        REQUIRE(box.exec(std::format("for i = 1, {} do rhp.on('bench.events.tick', function(v) end) end", handlers)));
        BENCHMARK(std::format("events rhp: deliver to {} handlers", handlers)) {
            tick.fire(++i);
            return i;
        };

        REQUIRE(box.exec(std::format("for i = 1, {} do rhp.on('bench.events.script', function(v) end) end", handlers)));
        REQUIRE(box.exec("rhp.every_frame(function() rhp.publish('bench.events.script', 1) end)"));
        box.pump();
        BENCHMARK(std::format("events rhp: pump delivering a publish to {} handlers", handlers)) {
            box.pump();
            return box.frame();
        };
    }
}
