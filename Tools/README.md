# Tools

| Tool | What |
|---|---|
| [`rhp-cli/`](rhp-cli) | the REPL and scripting client: keys, scripts, modules, blobs, events, discovery, fleets, releases, revocations, rollouts, tunables, the profiler, a Debug Adapter Protocol server and the Lua test runner ([README](rhp-cli/README.md)) |
| [`bench/summarize.py`](bench/summarize.py) | turns `rhp_bench`'s Catch2 XML report into a Markdown table; each `rhp` / `local` / `unchecked` mean as a multiple of its `raw` twin |
| [`bench/compare.py`](bench/compare.py) | compares two `rhp_bench` reports (before / after); a change counts only when the confidence intervals don't overlap and the means differ by more than `--threshold` percent (default 5) |
| [`android/run_tests.py`](android/run_tests.py) | runs a build's test executables on an Android device or emulator over adb |
| [`ios/simctl_run.sh`](ios/simctl_run.sh) | the `ios-sim` preset's `CMAKE_CROSSCOMPILING_EMULATOR`: runs simulator executables with `xcrun simctl spawn` |

Benchmarks (from a **Release** build with `-DRHP_BUILD_BENCH=ON`; results in [Docs/benchmarks.md](../Docs/benchmarks.md)):

```bash
rhp_bench "[bench]" --reporter xml::out=after.xml --benchmark-samples 100
python Tools/bench/summarize.py after.xml > after.md
python Tools/bench/compare.py before.xml after.xml --threshold 5
```

Android (set `ANDROID_NDK_HOME`, NDK r29 or newer):

```bash
cmake --preset android-arm64 -B build/android-arm64-tests -DRHP_BUILD_TESTS=ON
cmake --build build/android-arm64-tests --config Debug
python Tools/android/run_tests.py build/android-arm64-tests
```

iOS simulator: `ctest --preset ios-sim` runs every suite through `simctl_run.sh`.

## Rules

- Tools are clients of the public API like any user program.
- `rhp-cli` is built when `RHP_BUILD_TOOLS=ON` (default for a top-level build; the mobile presets turn it off) and `RHP_ENABLE=ON`; replxx and CLI11 are fetched only then.
- Benchmark names are `<group> <raw|rhp|local|unchecked>: <work>` (`summarize.py` parses them; `unchecked` is a sandbox with `cancel_checks = kNone`). A new RHP path gets a raw-Lua (or raw-C++) twin of the same group and work.
