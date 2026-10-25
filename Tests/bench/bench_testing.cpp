// Stage 12 test engine: what the exact instruction meter and line coverage cost on script work, what
// the runner spends per test file and per test, and what spies and assertions cost inside tests.
// Each group's raw twin runs the same work on a plain lua_State; groups ending in -off are the
// sandbox (or the runner) without the feature, so the feature's cost is the difference.
#include <chrono>
#include <filesystem>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/script/lib.hpp>
#include <rhp/test/detail/framework.hpp>
#include <rhp/test/test.hpp>

namespace bench_testing_fixture {

namespace fs = std::filesystem;

constexpr std::string_view kWork = R"(
local M = {}
function M.loop() local s = 0 for i = 1, 100000 do s = s + (i % 7) end return s end
local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
function M.fib() return fib(22) end
return M
)";

inline int g_calls = 0;
inline int bump(int x) {
    ++g_calls;
    return x + 1;
}

using bench_lib = Rhp::lib<"benchtest">::fn<"bump", &bump>;

// A folder of spec files for the runner benchmarks, removed afterwards.
struct specs {
    fs::path root = fs::temp_directory_path() / std::format("rhp_bench_testing_{}", std::chrono::steady_clock::now().time_since_epoch().count());

    specs() {
        fs::create_directories(root);
        write("empty_spec.lua", "-- no tests\n");
        std::string many;
        for (int i = 0; i < 100; ++i) {
            many += std::format("it(\"test {}\", function() end)\n", i);
        }
        write("many_spec.lua", many);
        write("work_spec.lua", R"(
it("calls 10k", function() for i = 1, 10000 do benchtest.bump(i) end end)
it("spies 10k", function() spy.on(benchtest, "bump") for i = 1, 10000 do benchtest.bump(i) end end)
it("plain checks 10k", function() for i = 1, 10000 do if i ~= i then error("x") end end end)
it("asserts 10k", function() for i = 1, 10000 do assert.equals(i, i) end end)
it("expects 10k", function() for i = 1, 10000 do expect(i).to.equal(i) end end)
)");
    }
    ~specs() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    specs(const specs&) = delete;
    specs& operator=(const specs&) = delete;

    void write(std::string_view name, std::string_view text) const { std::ofstream{root / name, std::ios::binary} << text; }

    // Runs the runner over one file (optionally one test), returns how many tests passed.
    [[nodiscard]] std::size_t run(std::string_view file, std::string_view only = {}, bool measure = true) const {
        Rhp::test::run_options o;
        o.root = root;
        o.tests.push_back(root / file);
        o.seed = 1;
        o.measure = measure;
        if (!only.empty()) {
            o.filters.push_back(std::format("/^{}$/", only));
        }
        Rhp::test::runner r{o, [](Rhp::script::sandbox& box) { return box.install<bench_lib>(); }};
        silent out;
        return r.run(out).totals.passed;
    }

private:
    struct silent final : Rhp::test::reporter {};
};

} // namespace bench_testing_fixture

using namespace bench_testing_fixture;

TEST_CASE("bench testing: the instruction meter and coverage on script work", "[bench][testing]") {
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
    Rhp::script::sandbox off{rhp_bench::quiet()};
    const auto off_mod = rhp_bench::load(off, "bench.work", kWork);
    Rhp::script::sandbox metered{rhp_bench::quiet()};
    const auto metered_mod = rhp_bench::load(metered, "bench.work", kWork);
    metered.start_metering();
    Rhp::script::sandbox covered{rhp_bench::quiet()};
    REQUIRE(covered.start_coverage());
    const auto covered_mod = rhp_bench::load(covered, "bench.work", kWork);
    Rhp::script::sandbox both{rhp_bench::quiet()};
    REQUIRE(both.start_coverage());
    const auto both_mod = rhp_bench::load(both, "bench.work", kWork);
    both.start_metering();

    const auto call = [](Rhp::script::sandbox& box, Rhp::module_id mod, std::string_view fn) {
        auto r = box.call(mod, fn);
        REQUIRE(r);
        return r->size();
    };

    BENCHMARK("metering raw: 100k arithmetic loop") {
        return call_raw("loop");
    };
    BENCHMARK("metering-off rhp: 100k arithmetic loop") {
        return call(off, off_mod, "loop");
    };
    BENCHMARK("metering rhp: 100k arithmetic loop") {
        return call(metered, metered_mod, "loop");
    };
    BENCHMARK("coverage rhp: 100k arithmetic loop") {
        return call(covered, covered_mod, "loop");
    };
    BENCHMARK("coverage-metered rhp: 100k arithmetic loop") {
        return call(both, both_mod, "loop");
    };
    BENCHMARK("metering raw: fib(22)") {
        return call_raw("fib");
    };
    BENCHMARK("metering-off rhp: fib(22)") {
        return call(off, off_mod, "fib");
    };
    BENCHMARK("metering rhp: fib(22)") {
        return call(metered, metered_mod, "fib");
    };
    BENCHMARK("coverage rhp: fib(22)") {
        return call(covered, covered_mod, "fib");
    };
    BENCHMARK("coverage-metered rhp: fib(22)") {
        return call(both, both_mod, "fib");
    };
}

TEST_CASE("bench testing: the runner per file and per test", "[bench][testing]") {
    const specs s;
    REQUIRE(s.run("many_spec.lua") == 100);
    REQUIRE(s.run("work_spec.lua") == 5);

    BENCHMARK("test-file raw: a state compiling the framework") {
        rhp_bench::raw_lua raw;
        int loaded = 0;
        for (const auto& source : Rhp::test::detail::framework_sources()) {
            loaded += luaL_loadbuffer(raw.get(), source.text.data(), source.text.size(), source.name.data()) == LUA_OK ? 1 : 0;
            lua_pop(raw.get(), 1);
        }
        return loaded;
    };
    BENCHMARK("test-file rhp: a file with no tests") {
        return s.run("empty_spec.lua");
    };
    BENCHMARK("test-run rhp: 100 empty tests") {
        return s.run("many_spec.lua");
    };
    BENCHMARK("test-run-unmeasured rhp: 100 empty tests") {
        return s.run("many_spec.lua", {}, false);
    };
    BENCHMARK("test-run raw: 100 pcalls of empty functions") {
        rhp_bench::raw_lua raw;
        raw.define("F", "return function() for i = 1, 100 do pcall(function() end) end return 100 end");
        return raw.call("F");
    };
}

TEST_CASE("bench testing: spies and assertions inside a test", "[bench][testing]") {
    const specs s;
    BENCHMARK("spy-off rhp: 10k lib calls") {
        return s.run("work_spec.lua", "calls 10k");
    };
    BENCHMARK("spy rhp: 10k lib calls through spy.on") {
        return s.run("work_spec.lua", "spies 10k");
    };
    BENCHMARK("assert-off rhp: 10k plain checks") {
        return s.run("work_spec.lua", "plain checks 10k");
    };
    BENCHMARK("assert rhp: 10k assert.equals") {
        return s.run("work_spec.lua", "asserts 10k");
    };
    BENCHMARK("expect rhp: 10k expect().to.equal") {
        return s.run("work_spec.lua", "expects 10k");
    };
}
