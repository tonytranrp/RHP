# test — layer 4

`Rhp::test`: runs Lua test files against a program's API, offline. Namespace `Rhp::test`. Depends on `script`, `platform` and `core`. Usage: [Testing scripts](../../../Docs/guide/testing-scripts.md); decisions: [Stage 12](../../../Docs/decisions/stage12-test-engine.md).

| Header | What |
|---|---|
| `test.hpp` | the umbrella |
| `runner.hpp` | `runner` (one run: discovery, a sandbox per file or per test, the fake clock, each test between a checkpoint and a revert, leak checks, snapshots, fuzz corpus, coverage), `install_fn`, `describe_api` |
| `options.hpp` | `run_options` and the command line (`parse_args`, `usage`) |
| `report.hpp` | what a run produces: `test_result` (outcome, place, expected / actual, cost, measures, benches, output, notes, profile), `file_result`, `run_result`, coverage |
| `reporter.hpp` | the `reporter` interface, `reporter_list`, text / TAP / JUnit / JSON / GitHub reporters, LCOV / Cobertura / folded text |
| `cli.hpp` | `run_cli` and `Rhp::test::main(argc, argv, install)`: a test executable in one line |
| `fake.hpp` | `fake<L>`: a lib with L's shape whose functions record their calls |
| `fake_registry.hpp` | what `fake<L>` functions were called with and return (process-wide, thread-safe) |
| `detail/framework.hpp` | the framework's Lua sources, embedded at configure time |
| `lua/*.lua` | the framework: `core` (DSL, protocol), `format` (display, deep equality, serializer), `assert`, `spy`, `test` (clock, measuring), `expect`, `property` (snapshots, properties, fuzzing), `fakes` (from an API description) |

## Rules

- The framework is Lua, run in each test sandbox's scratch environment, loaded through `sandbox::exec_cached` (compiled once per process). It reaches the sandbox only through the `__rhp_test` bridge (`script/puc_lua/testing.cpp`); anything that changes the sandbox (a swap, a patch) goes through the ledger, so a test's revert undoes it.
- The Lua files are listed in `CMakeLists.txt` and embedded by `cmake/RhpEmbed.cmake`; a change to one re-runs the configure step. Chunk names start with `rhp.test/`: tracebacks and frames leave those out.
- One runner, one thread: the runner pumps its sandboxes itself. Process-wide state (patch points, events, `fake_registry`) is shared with the rest of the test executable.
- Lua files: names in `snake_case`, locals for globals the hot paths use, no `debug` library (the sandbox has none). Failures are tables from `T.fail` (`rhp_failure`), errors anything else.
- Messages are built for failures only: passing assertions format nothing.
- `RHP_ENABLE=OFF`: files report that Lua is compiled out; options, `describe_api` and `fake<L>` still work.
