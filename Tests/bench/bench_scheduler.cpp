// E: the scheduler. One pump() with N frame callbacks, N idle timers, N sleeping tasks or N tasks
// resuming every frame, for N in {0, 100, 1000, 10000}. Idle work should cost close to nothing;
// per-callback work should stay near a Lua call.
#include <format>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("bench scheduler: pump with N timers callbacks and tasks", "[bench][scheduler]") {
    for (const int n : {0, 100, 1000, 10000}) {
        {
            Rhp::script::sandbox box{rhp_bench::quiet()};
            REQUIRE(box.exec(std::format("for i = 1, {} do rhp.every_frame(function() end) end", n)));
            box.pump();
            BENCHMARK(std::format("scheduler rhp: pump with {} frame callbacks", n)) {
                box.pump();
                return box.frame();
            };
        }
        {
            Rhp::script::sandbox box{rhp_bench::quiet()};
            REQUIRE(box.exec(std::format("for i = 1, {} do rhp.after(1e9, function() end) end", n)));
            box.pump();
            BENCHMARK(std::format("scheduler rhp: pump with {} idle timers", n)) {
                box.pump();
                return box.frame();
            };
        }
        {
            Rhp::script::sandbox box{rhp_bench::quiet()};
            REQUIRE(box.exec(std::format("for i = 1, {} do rhp.spawn(function() rhp.sleep(1e9) end) end", n)));
            box.pump();
            box.pump();
            BENCHMARK(std::format("scheduler rhp: pump with {} sleeping tasks", n)) {
                box.pump();
                return box.frame();
            };
        }
        {
            Rhp::script::sandbox box{rhp_bench::quiet()};
            REQUIRE(box.exec(std::format("for i = 1, {} do rhp.spawn(function() while true do rhp.next_frame() end end) end", n)));
            box.pump();
            box.pump();
            BENCHMARK(std::format("scheduler rhp: resume {} tasks", n)) {
                box.pump();
                return box.frame();
            };
            box.revert_all();
        }
    }
}

TEST_CASE("bench scheduler: raw coroutine resume twin", "[bench][scheduler]") {
    for (const int n : {100, 1000}) {
        rhp_bench::raw_lua raw;
        raw.define("tasks", std::format(R"(
local t = {{}}
for i = 1, {} do t[i] = coroutine.create(function() while true do coroutine.yield() end end) end
return t)",
                                        n));
        raw.define("step", "return function(t) for i = 1, #t do coroutine.resume(t[i]) end end");
        BENCHMARK(std::format("scheduler raw: resume {} tasks", n)) {
            lua_getglobal(raw.get(), "step");
            lua_getglobal(raw.get(), "tasks");
            lua_pcall(raw.get(), 1, 0, 0);
            return n;
        };
    }
}
