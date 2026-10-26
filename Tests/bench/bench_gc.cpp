// G: Lua's garbage collector under a frame loop. Catch2's benchmarks report means; a frame budget
// cares about the slowest frames, so the latency case times every pump() and prints percentiles for
// both collector modes, with and without sandbox::collect_idle after each frame. It is hidden (run it
// with rhp_bench "[gc]"); the BENCHMARK cases are part of "[bench]".
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <format>
#include <numeric>
#include <utility>
#include <vector>

#include "bench_support.hpp"
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

namespace bench_gc_fixture {

using steady = std::chrono::steady_clock;

// A live heap of `keep` small tables and strings, and 1000 frame callbacks that each make a small
// table and a string per frame and now and then store one in the live heap (an old object pointing
// at a young one, as game state does).
std::string frame_script(int keep) {
    return std::format(R"(
keep = {{}}
for i = 1, {0} do keep[i] = {{i, tostring(i)}} end
local n = 0
for i = 1, 1000 do
    rhp.every_frame(function()
        n = n + 1
        local t = {{x = n, y = n}}
        local s = "f" .. n
        if n % 64 == 0 then keep[n % {0} + 1] = {{t.x, s}} end
    end)
end
)",
                       keep);
}

struct latency {
    double p50 = 0, p99 = 0, p999 = 0, max = 0, mean = 0, idle_mean = 0;
};

latency measure(Rhp::script::gc_mode mode, std::chrono::microseconds idle, int keep, int frames) {
    Rhp::script::sandbox_options o = rhp_bench::quiet();
    o.gc = mode;
    Rhp::script::sandbox box{std::move(o)};
    REQUIRE(box.exec(frame_script(keep)));
    for (int i = 0; i < 300; ++i) { // past the first cycles
        box.pump();
        (void)box.collect_idle(idle);
    }
    std::vector<double> us;
    us.reserve(static_cast<std::size_t>(frames));
    double idle_total = 0;
    for (int i = 0; i < frames; ++i) {
        const auto t0 = steady::now();
        box.pump();
        const auto t1 = steady::now();
        REQUIRE(box.collect_idle(idle));
        const auto t2 = steady::now();
        us.push_back(std::chrono::duration<double, std::micro>(t1 - t0).count());
        idle_total += std::chrono::duration<double, std::micro>(t2 - t1).count();
    }
    std::ranges::sort(us);
    const auto at = [&](double q) { return us[std::min(us.size() - 1, static_cast<std::size_t>(q * static_cast<double>(us.size())))]; };
    latency l;
    l.p50 = at(0.50);
    l.p99 = at(0.99);
    l.p999 = at(0.999);
    l.max = us.back();
    l.mean = std::accumulate(us.begin(), us.end(), 0.0) / static_cast<double>(us.size());
    l.idle_mean = idle_total / static_cast<double>(frames);
    return l;
}

} // namespace bench_gc_fixture

using namespace bench_gc_fixture;

TEST_CASE("bench gc: pump latency by collector mode", "[.][gc]") {
    using Rhp::script::gc_mode;
    // Every configuration once per round, in turn, so a noisy stretch of the machine hits them all;
    // each statistic is the median over the rounds.
    constexpr int kRounds = 7;
    constexpr int kFrames = 1000;
    struct config {
        int keep;
        gc_mode mode;
        int idle_us;
        std::vector<latency> runs{};
    };
    std::vector<config> configs;
    for (const int keep : {0, 200000}) {
        for (const gc_mode mode : {gc_mode::kIncremental, gc_mode::kGenerational}) {
            for (const int idle_us : {0, 250, 1000}) {
                configs.push_back(config{keep, mode, idle_us});
            }
        }
    }
    for (int round = 0; round < kRounds; ++round) {
        for (config& c : configs) {
            c.runs.push_back(measure(c.mode, std::chrono::microseconds{c.idle_us}, c.keep, kFrames));
        }
    }
    const auto median = [](std::vector<double> v) {
        std::ranges::sort(v);
        return v[v.size() / 2];
    };
    std::printf("%-30s %8s %8s %8s %8s %8s %8s %10s\n", "median of rounds (us)", "p50", "p99", "p99.9", "max", "mean", "idle", "pump+idle");
    for (const config& c : configs) {
        const auto stat = [&](double latency::* field) {
            std::vector<double> v;
            for (const latency& l : c.runs) {
                v.push_back(l.*field);
            }
            return median(std::move(v));
        };
        std::vector<double> total;
        for (const latency& l : c.runs) {
            total.push_back(l.mean + l.idle_mean);
        }
        const std::string name = std::format("{} keep {} idle {}", c.mode == gc_mode::kIncremental ? "inc" : "gen", c.keep, c.idle_us);
        std::printf("%-30s %8.1f %8.1f %8.1f %8.1f %8.1f %8.1f %10.1f\n", name.c_str(), stat(&latency::p50), stat(&latency::p99),
                    stat(&latency::p999), stat(&latency::max), stat(&latency::mean), stat(&latency::idle_mean), median(std::move(total)));
    }
}
