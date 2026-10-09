# Tests

```bash
ctest --preset windows-msvc
```

| Folder | Kind | Notes |
|---|---|---|
| `unit/<module>/` | Catch2 v3 unit tests, mirroring `Src/rhp/<module>/` | one executable per module (`rhp_<module>_tests`); every `TEST_CASE` is its own ctest entry |
| `compile_fail/` | code that must **not** compile | each file compiles cleanly as-is and must fail with `RHP_COMPILE_FAIL` defined, proving the guarded line is what breaks |
| `unit/script/` | the script engine (needs `RHP_ENABLE=ON`) | with `RHP_ENABLE=OFF` the suite builds `disabled_tests.cpp` instead (inert sandbox, direct-call patch points) |
| `integration/` | `Rhp::host` ↔ `Rhp::client` over loopback and TCP on 127.0.0.1 (`rhp_integration_tests`, needs `RHP_ENABLE=ON`) | roles, the whole module lifecycle, output routing, suspended requests, cancel, disconnect = revert, idempotent retries, frame limits, handshake caps, `throwing` and `zero_threads` configs |
| `support/rhp_test/` | header-only helpers shared by suites (`poll_until`, a recording `link_handler`) | on every suite's include path |
| `fuzz/` | libFuzzer targets | Stage 5 |
| `bench/` | Google Benchmark | when there's a hot path to measure |

## Rules

- Test files are named `<thing>_tests.cpp`.
- Tag every test case `[module][thing]`.
- Prefer `STATIC_REQUIRE` for anything checkable at compile time.
- Cover boundaries, not just the happy path: empty packs, minimal types satisfying a concept, out-of-range values.
- Anything touching threads must stay clean under the `*-tsan` preset.
- Network tests use loopback channel names and ports unique to their test case, TCP on `127.0.0.1` port 0 (a free port), and generous timeouts; they read game state through a client (or after the pumping thread has joined), never straight from another thread.
- Globals, patch points, events and lib names are process-wide: give each test file its own fixture namespace, globals and point / event ids, and leave every point unpatched (a destroyed sandbox reverts everything).
- Script time: inject `sandbox_options::clock` for `rhp.sleep` / `rhp.timer`; use real time only where it is the subject (slicing, `wall_ms`, cross-thread cancel) and keep bounds generous for sanitizer builds.
