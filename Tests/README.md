# Tests

```bash
ctest --preset windows-msvc
```

| Folder | Kind | Notes |
|---|---|---|
| `unit/<module>/` | Catch2 v3 unit tests, mirroring `Src/rhp/<module>/` | one executable per module (`rhp_<module>_tests`); every `TEST_CASE` is its own ctest entry |
| `compile_fail/` | code that must **not** compile | each file compiles cleanly as-is and must fail with `RHP_COMPILE_FAIL` defined, proving the guarded line is what breaks |
| `integration/` | host ↔ client over real transports | Stage 3+ |
| `fuzz/` | libFuzzer targets | Stage 5 |
| `bench/` | Google Benchmark | when there's a hot path to measure |

## Rules

- Test files are named `<thing>_tests.cpp`.
- Tag every test case `[module][thing]`.
- Prefer `STATIC_REQUIRE` for anything checkable at compile time.
- Cover boundaries, not just the happy path: empty packs, minimal types satisfying a concept, out-of-range values.
- Anything touching threads must stay clean under the `*-tsan` preset.
