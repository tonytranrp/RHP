// F: requests a host makes on a sandbox: call with arguments, load, reload, revert.
#include <format>
#include <vector>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

TEST_CASE("bench requests: call load reload and revert", "[bench][requests]") {
    Rhp::script::sandbox box{rhp_bench::quiet()};
    const auto mod = rhp_bench::load(box, "bench.requests.add", "local M = {} function M.add(a, b) return a + b end return M");
    const std::vector<Rhp::value> args{Rhp::value{1}, Rhp::value{2}};
    BENCHMARK("requests rhp: call with two arguments") {
        return box.call(mod, "add", args)->size();
    };

    int revision = 0;
    BENCHMARK("requests rhp: reload of a small module") {
        return box.reload(mod, std::format("local M = {{}} M.v = {} function M.add(a, b) return a + b end return M", ++revision)).has_value();
    };

    BENCHMARK("requests rhp: load then unload of a small module") {
        const auto m = box.load("bench.requests.tmp", "local M = {} M.x = 1 return M");
        REQUIRE(m);
        return box.unload(*m).has_value();
    };

    BENCHMARK("requests rhp: checkpoint and revert_to over 100 scratch effects") {
        REQUIRE(box.checkpoint("bench"));
        REQUIRE(box.exec("for i = 1, 100 do rhp.after(1e9, function() end) end"));
        return box.revert_to("bench")->undone;
    };
}
