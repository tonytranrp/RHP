# test — layer 4

`Rhp::test`: runs Lua test files against a program's API, offline (Stage 12). Namespace `Rhp::test`. Target `Rhp::test`; depends on `script`, `platform` and `core`. Usage: [testing scripts](../../../Docs/guide/testing-scripts.md); decisions: [Stage 12](../../../Docs/decisions/stage12-test-engine.md).

| Header | What |
|---|---|
| `test.hpp` | the umbrella |
| `runner.hpp` | `runner` (`run(reporter&)`, `list()`: discovery, a sandbox per file or per test, the fake clock, each test between a checkpoint and a revert, leak checks, snapshots, fuzz corpus, coverage), `install_fn`, `describe_api` |
| `options.hpp` | `run_options`, `cli_options`, `report_spec`, `coverage_spec`; the command line (`parse_args`, `usage`) |
| `report.hpp` | what a run produces: `test_result` (outcome, place, expected / actual, cost, measures, benches, output, notes, profile), `file_result`, `run_result`, `counts`, `file_coverage` |
| `reporter.hpp` | the `reporter` interface, `reporter_list`, `make_text_reporter` / `make_tap_reporter` / `make_junit_reporter` / `make_json_reporter` / `make_github_reporter`, `lcov_text`, `cobertura_text`, `folded_text` |
| `cli.hpp` | `run_cli(args, install, program, out, err, api)` (any streams; `api`: a description to fake, as `--api FILE` would), `run_cli(args, install, program)` (`std::cout` / `std::cerr`), and `Rhp::test::main(argc, argv, install)`: a test executable in one line |
| `fake.hpp` | `fake<L>`: a lib with L's shape whose functions record their calls |
| `fake_registry.hpp` | what `fake<L>` functions were called with and return (process-wide, thread-safe) |
| `detail/framework.hpp` | the framework's Lua sources, embedded at configure time |
| `lua/*.lua` | the framework: `core` (DSL, protocol), `format` (display, deep equality, serializer), `assert`, `spy`, `test` (clock, measuring), `expect`, `property` (snapshots, properties, fuzzing), `fakes` (from an API description) |

Private (not installed): `detail/support.hpp` (helpers the runner, the reporters and the command line share), `detail/snapshots.hpp` (a test file's snapshot store), `detail/fuzz_corpus.hpp` (saved fuzz inputs), `detail/coverage.hpp` (a run's coverage totals); `fake_registry.cpp` implements `fake_registry.hpp`.

```cpp
// lua_tests_main.cpp: the program's real libs, its own test executable
int main(int argc, char** argv) {
    return Rhp::test::main(argc, argv, [](Rhp::script::sandbox& box) { return box.install<game_lib>(); });
}
```

```cmake
rhp_add_lua_tests(game TARGET game_lua_tests SCRIPTS scripts FILES tests/combat_spec.lua)   # one ctest per file
```

The same runner is `rhp-cli test` (the `rhp` API only, or fakes from `--api FILE.json` / `--api-from HOST:PORT`) and drives the [VS Code extension](../../../clients/vscode).

## Rules

- The framework is Lua, run in each test sandbox's scratch environment, loaded through `sandbox::exec_cached` (compiled once per process). It reaches the sandbox only through the `__rhp_test` bridge (`script/puc_lua/testing.cpp`); anything that changes the sandbox (a swap, a patch) goes through the ledger, so a test's revert undoes it.
- The Lua files are listed in `CMakeLists.txt` and embedded by `cmake/RhpEmbed.cmake`; a change to one re-runs the configure step. Chunk names start with `rhp.test/`: tracebacks and frames leave those out.
- One runner, one thread: the runner pumps its sandboxes itself and steps their fake clock. Process-wide state (patch points, events, `fake_registry`) is shared with the rest of the test executable.
- The meter is exact (count-hook ticks plus each thread's countdown remainder) and never changes what a script does; swaps made by spies and stubs are ledger effects.
- Lua files: names in `snake_case`, locals for globals the hot paths use, no `debug` library (the sandbox has none). Failures are tables from `T.fail` (`rhp_failure`), errors anything else.
- Messages are built for failures only: passing assertions format nothing.
- `cli.hpp` includes `<iosfwd>`, not `<iostream>`: keep heavy standard headers out of it.
- Exit status of `run_cli` / `main`: 0 everything passed, 1 a test or a file failed, 2 bad arguments.
- `RHP_ENABLE=OFF`: files report that Lua is compiled out; options, `describe_api` and `fake<L>` still work.
