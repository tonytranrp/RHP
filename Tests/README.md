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
| `integration/stage4_tests.cpp` | signing, audit events, blobs, pin, reverse mode, async calls, the kill switch | loopback and TCP |
| `integration/stage5_tests.cpp` | resume through cut connections (exactly once, expiry, reverse mode, over TLS), TLS over TCP and a custom transport, certificate checks, a TLS-terminating relay refused, the TLS policy, the host's goodbye | a `cuttable` transport cuts live connections |
| `integration/stage6_tests.cpp` | signed scripts over WebSocket/UDP/IPC, TLS tunneling, HTTP identity/role/signature/cancel/expiry, discovery and collect-all fleet outcomes | real transport backends; real multicast DNS-SD |
| `unit/net/websocket_tests.cpp`, `udp_reliable_tests.cpp`, `local_ipc_tests.cpp`, `http_tests.cpp`, `mdns_tests.cpp` | the sans-IO codecs (frames, packets, HTTP heads, DNS), stream contract and close/drain per transport, loss/corruption/duplication/reorder, DNS conflicts/updates/goodbyes, native discovery | `datagram_relay.cpp` injects UDP faults; `support/rhp_test/stream_roundtrip.hpp` is the shared transport contract |
| `unit/security/tls_tests.cpp` | every backend pair (OpenSSL ↔ Mbed TLS where both exist): handshake, data, channel binding, close_notify, CA and name checks, bad PEM | certificates in `support/rhp_test/tls_fixtures.hpp` (test-only) |
| `tools/` | `rhp-cli` (`rhp_cli_tests`, needs `RHP_BUILD_TOOLS`) | the shell in-process over loopback; then the real `rhp-cli` and `headless_server` binaries as processes over TCP |
| `support/rhp_test/` | header-only helpers shared by suites (`poll_until`, a recording `link_handler`, `stream_roundtrip`) | on every suite's include path |
| `fuzz/` | frame, envelope, msgpack, sandbox_escape, network: replay drivers in ctest (`fuzz.*`), libFuzzer with `RHP_FUZZ=ON` | see [fuzz/README.md](fuzz/README.md) |
| `bench/` | Google Benchmark | when there's a hot path to measure |

## Rules

- Test files are named `<thing>_tests.cpp`.
- Cases that use real multicast DNS-SD are tagged `[multicast]`: ctest gives them one `RESOURCE_LOCK`, since they share UDP 5353.
- Tag every test case `[module][thing]`.
- Prefer `STATIC_REQUIRE` for anything checkable at compile time.
- Cover boundaries, not just the happy path: empty packs, minimal types satisfying a concept, out-of-range values.
- Anything touching threads must stay clean under the `*-tsan` preset.
- On Android, `python Tools/android/run_tests.py <build dir>` runs every suite on a device or emulator; on the iOS simulator `ctest --preset ios-sim` runs through `Tools/ios/simctl_run.sh`.
- Catch2 test names: no commas or non-ASCII characters (ctest passes the name back as a filter).
- Network tests use loopback channel names and ports unique to their test case, TCP on `127.0.0.1` port 0 (a free port), and generous timeouts; they read game state through a client (or after the pumping thread has joined), never straight from another thread.
- Globals, patch points, events and lib names are process-wide: give each test file its own fixture namespace, globals and point / event ids, and leave every point unpatched (a destroyed sandbox reverts everything).
- Script time: inject `sandbox_options::clock` for `rhp.sleep` / `rhp.timer`; use real time only where it is the subject (slicing, `wall_ms`, cross-thread cancel) and keep bounds generous for sanitizer builds.
