# rhp_bench: Catch2 benchmarks of RHP's hot paths, each next to a raw-Lua (or raw-C++) twin doing
# the same work without RHP, so the overhead RHP adds is a ratio rather than a guess. Build with
# RHP_BUILD_BENCH=ON and run a Release build (see Docs/benchmarks.md and Tools/bench/).
#
# ctest only runs a smoke pass (two samples, no analysis) so the benchmarks keep compiling and
# running; real numbers come from running rhp_bench directly.
add_executable(rhp_bench
    bench_lua.cpp
    bench_bindings.cpp
    bench_patch.cpp
    bench_events.cpp
    bench_scheduler.cpp
    bench_requests.cpp
    bench_wire.cpp
    bench_security.cpp
    bench_e2e.cpp
)
# Raw-Lua twins need lua.h: the bench is the one place outside Rhp::script that includes it.
target_link_libraries(rhp_bench PRIVATE Rhp::rhp Rhp::lua Catch2::Catch2WithMain)
rhp_set_warnings(rhp_bench)
set_target_properties(rhp_bench PROPERTIES FOLDER "tests/bench")

add_test(NAME bench.smoke
    COMMAND rhp_bench "[bench]" --benchmark-samples 2 --benchmark-no-analysis --benchmark-warmup-time 0)
set_tests_properties(bench.smoke PROPERTIES LABELS bench TIMEOUT 1800)
