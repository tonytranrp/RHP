# Tests

Catch2 suites, compile-fail checks, fuzz replays, benchmarks and a package consumer, all run by ctest. Every Catch2 `TEST_CASE` is its own ctest entry, named `<suite>.<test name>`.

## Running

```bash
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

```bash
ctest --preset windows-msvc -R "some test name"          # one test (a regex)
ctest --preset windows-msvc -R "^rhp_script_tests\."     # one suite
ctest --preset windows-msvc -L fuzz                      # one label
ctest --preset windows-msvc -LE multicast                # without the cases that need a LAN
ctest --test-dir build/windows-msvc -C Debug -R stage5
```

Labels: `fuzz`, `compile_fail`, `multicast`, `process` (separate `rhp-cli` / `headless_server` / runner processes), `bench`, `package`, `python`, `vscode`, `hygiene`, `lua`. Windows presets need the MSVC environment (`vcvars64.bat`); Linux presets run in WSL. On Android, `python Tools/android/run_tests.py <build dir>` runs every suite on a device or emulator; on the iOS simulator `ctest --preset ios-sim` runs through `Tools/ios/simctl_run.sh`. `RHP_ENABLE=OFF` must build and pass too:

```bash
cmake --preset windows-msvc -B build/off-msvc -DRHP_ENABLE=OFF
ctest --test-dir build/off-msvc -C Debug
```

So must every hardening level (`RHP_HARDENING`, default `dev`; CI's `hardened` job builds `production` with linux-clang). A test whose subject a level leaves out calls `rhp_test::needs(level, what)` first and is skipped there; the refusals themselves are tested at the stricter levels (`host_options::hardening` raises a host's level in any build):

```bash
cmake --preset windows-msvc -B build/production-msvc -DRHP_HARDENING=production
ctest --test-dir build/production-msvc -C Debug
```

## Layout

| Folder | What |
|---|---|
| `unit/<module>/` | one executable per module (`rhp_<module>_tests`), mirroring `Src/rhp/<module>/`. With `RHP_ENABLE=OFF`: `rhp_script_tests` and `rhp_test_tests` build their `disabled_tests.cpp` instead (inert sandbox, direct-call patch points), `rhp_security_tests` keeps the key tests plus `signing_disabled_tests.cpp`, and `rhp_host_tests` (`unit/host/disabled_tests.cpp`: the inert host) exists only then; the net, session and release suites need the live engine |
| `unit/script/yield_tests.cpp` | also built as `rhp_script_cet_tests` on x64 MSVC (not sanitizer builds), linked `/CETCOMPAT`: under a CET shadow stack coroutine yields must throw instead of jumping |
| `unit/net/` | the sans-IO codecs (WebSocket frames, UDP packets, HTTP heads, DNS), each transport's stream contract and close / drain, loss / corruption / duplication / reorder (`datagram_relay.cpp` injects UDP faults), reliable UDP's stateless cookies (bound to the source, valid for one to two periods; a Hello without one creates nothing), DNS conflicts / updates / goodbyes, native discovery; `address_tests.cpp`: `ip_address` parsing (host names aren't addresses), local addresses, per-source keys |
| `unit/session/` | `admission_tests.cpp` (the total and per-source caps, eviction of the oldest silent connection, an IPv6 /64 as one source, the first-byte deadline, a cap of zero), `channel_policy_tests.cpp` (`insecure_lan` with local peers only: literal and resolved dials, listeners with and without TLS), `session_tests.cpp` |
| `unit/core/hardening_tests.cpp`, `unit/utils/siphash_tests.cpp`, `unit/platform/platform_tests.cpp` | the build's level and `capped()`, the observe and production caps; SipHash-2-4 against the reference vectors; owner-only atomic files (`write_private_file`, `readable_by_others`) and `user_config_dir` |
| `unit/script/` (Stage 13a cases) | `limits_tests.cpp`: instruction, wall-time and cancel stops in pattern matching and plain find, results unchanged (compared with a plain Lua state), `limits.handlers`; `sandbox_tests.cpp`: hardened admin's libraries, no `__gc` below admin's full library, hashed addresses (compared with a plain Lua state), shared library tables restored by `revert_all`; `schedule_tests.cpp`: observe can't register handlers |
| `unit/security/key_file_tests.cpp`, `unit/release/manager_tests.cpp` | owner-only identity files and their warnings, keyring warnings, dev session files; seq caps (`max_seq_jump`) on releases, revocation lists and floors |
| `unit/security/` (Stage 13b) | `key_handle_tests.cpp` (Ed25519 against RFC 8032 and P-256 against RFC 6979, in software and through a sign callback, fingerprints), `key_store_tests.cpp` (owner-only files, the passphrase seal, app wrapping, DPAPI, callbacks; the Keychain store only as disabled off Apple), `split_key_file_tests.cpp` (`.rhpid` / `.rhpsign`, `env=` tags, the combined format from before), `operator_cert_tests.cpp` and `certified_tests.cpp` (certificates, claims, replayed nonces, `max_role`, scopes, dev tags at production), `device_keys_tests.cpp` (the handshake, allow-lists, `known_hosts`, trust on first use), `pairing_cpace_tests.cpp` (draft-irtf-cfrg-cpace-21's test vectors) and `pairing_tests.cpp` (`rhp-pair://` links, the one-time secret book, codes) |
| `unit/release/root_tests.cpp`, `root_manager_tests.cpp`, `identity_revocation_tests.cpp` | root documents and their canonical encoding, thresholds, rotation that needs the old and the new root keys, expiry; a manager on a root (trust from its roles, versions stored and walked again on restore, compromised keys' lists dropped and their fast-forwards undone, retired keys keeping what they signed); identity revocation lists and their seq caps |
| `unit/core/scopes_tests.cpp`, `unit/script/scope_tests.cpp` | scope patterns (parsing, deny wins, intersections); a sandbox's scopes (libs left out, `Rhp::cap<>` bindings, patch points, events) and narrowing |
| `unit/security/tls_tests.cpp` | every backend pair (OpenSSL ↔ Mbed TLS where both exist): handshake, data, channel binding, close_notify, CA and name checks, bad PEM |
| `unit/test/` | `Rhp::test` end to end (`rhp_test_tests`): Lua specs in `fixtures/specs` run through the runner against the `arena` fixture lib. A spec's test names end with the outcome they must have, `(ok)` / `(fails)` / `(errors)` (`check_conventions`); `golden/` holds normalized reports (a mismatch writes `<file>.actual` next to it for review); the fixtures are embedded too (list new ones in `rhp_test_fixture_files`), so the suite runs where the source tree isn't reachable; snapshot and fuzz cases work in a temporary copy |
| `integration/` | `rhp_integration_tests` (needs `RHP_ENABLE=ON`): `Rhp::host` ↔ `Rhp::client` over loopback and TCP on 127.0.0.1, one file per stage (below) |
| `compile_fail/` | code that must **not** compile: each file compiles as-is and must fail with `RHP_COMPILE_FAIL` defined, proving the guarded line is what breaks (`compile_fail.<name>`), and the failing build's output must name why: the unsatisfied concept (`CONSTRAINT`) or another diagnostic (`EXPECT`), matched in both MSVC's and clang's wording (`rhp_add_compile_fail` in `Tests/CMakeLists.txt`). The as-is builds aren't in the default build: `compile_fail.fixtures_compile` builds them all in one run, and each `compile_fail.<name>` waits for it. Hardening fixtures: `build_config_hardening_mismatch` (a translation unit defining another `RHP_HARDENING`), `host_unsigned_hardened` (`signer<unsigned_scripts>` above `dev`), `config_hardening_below_build` (a level below the build's; only in `lan` and `production` builds) |
| `support/rhp_test/` | header-only helpers on every suite's include path: `poll_until` (`net_support.hpp`), `eventually` (`eventually.hpp`: wait for another thread), `stream_roundtrip.hpp` (the shared transport contract), `datagram_relay.hpp`, `tls_fixtures.hpp` (test-only certificates), `hardening.hpp` (`needs(level, what)`: skips a test whose subject the build's `RHP_HARDENING` leaves out) |
| `tools/` | `rhp_cli_tests` (needs `RHP_BUILD_TOOLS`): the shell in-process over loopback; the `[process]` cases (label `process`, also need `RHP_BUILD_EXAMPLES`) run the real `rhp-cli` and `headless_server` binaries over TCP (keygen's output and files, `connect --dev` against a dev session included) |
| `fuzz/` | frame, msgpack, envelope, sandbox_escape, network, release: replay drivers in ctest (`fuzz.<name>`), libFuzzer with `RHP_FUZZ=ON` ([fuzz/README.md](fuzz/README.md)) |
| `bench/` | `rhp_bench` (`RHP_BUILD_BENCH=ON`): every hot path next to a raw twin; ctest runs a smoke pass (`bench.smoke`) |
| `package/` | a consumer project built against the installed package (`package.install`, `package.find_package`; `RHP_INSTALL`, skipped for sanitizer, fuzz and cross builds): `find_package(rhp)`, `<windows.h>` first, a Lua test executable through `rhp_add_lua_tests` |
| `hygiene/` | `hygiene.ascii_headers`: public headers (and the generated `build_config.hpp`) stay ASCII |

Outside this folder ctest also runs `python.client` (`clients/python`, when Python 3 with pytest is found) and `vscode.unit` / `vscode.protocol` (`clients/vscode`, with `node --test` when Node.js is found).

| Integration file | Covers |
|---|---|
| `host_client_tests.cpp` | roles, the whole module lifecycle, output routing, suspended requests, cancel, disconnect = revert, idempotent retries, frame limits, handshake caps, `throwing` and `zero_threads` configs |
| `stage4_tests.cpp` | signing, audit events, blobs, pin, reverse mode, async calls, the kill switch |
| `stage5_tests.cpp` | resume through cut connections (exactly once, expiry, reverse mode, over TLS), TLS over TCP and a custom transport, certificate checks, a TLS-terminating relay refused, the TLS policy, the host's goodbye (a `cuttable` transport and a `tls_relay`) |
| `stage6_tests.cpp` | signed scripts over WebSocket / UDP / IPC, TLS tunneling, HTTP identity / role / signature / cancel / expiry, discovery and collect-all fleet outcomes (real backends, real multicast DNS-SD) |
| `stage6_fleet_tests.cpp` | fleet `load` / `call` broadcasts, signing, a shared deadline across stalled hosts, one network thread for every member (and the caller's thread with zero threads) |
| `stage7_tests.cpp` | client events from the pump and other threads, identity isolation, unsubscribe / detach, `host.on_script_event`, `handler_failed`, tasks across sessions, flood caps with `dropped`, reverse-mode resubscription |
| `stage9_tests.cpp` | asynchronous bindings over the wire: completion on a worker thread, cancel, disconnect, revert of a kept result |
| `stage10_tests.cpp` | releases over the wire (apply, refusals, manual and health confirmation, revocations, restart), rollouts (stages, reruns, failing canaries) |
| `stage11_tests.cpp` | tunables, the profiler and the debugger of a client's own sandbox; debugging sessions that go away; auditing; truncated profiles |
| `stage13_hardening_tests.cpp` | hardening levels over the wire: what `lan` and `production` refuse (raised with `host_options::hardening` in every build), the observe and production caps, `observe_limits`, dev sessions (the connect file, a client made from it, refusals) |
| `stage13_network_tests.cpp` | admission (one source can't take every slot, the first-byte deadline, a resume through slots full of silent connections, `auth_failed`'s key), a listening client with stalled candidates, CA name checks for names that look like addresses, the kill switch (sessions closed and identities reverted except pinned modules, no handlers, tasks or release channels, reverse-mode dialing stopped and resumed) |
| `stage13_limits_tests.cpp` | `limits.request_rate` (refusals, refill on the host's clock) and `limits.pump_requests` (identities served in turn) |
| `stage13_device_keys_tests.cpp` | device keys over TCP with TLS (the welcome's host key), plaintext and unlisted keys refused, a TLS-terminating relay refused and a plain relay passed, changed and new host keys, revoked device keys, `env=dev` PSKs, device keys and signers refused at production and accepted below |
| `stage13_certified_tests.cpp` | certified clients (the audit names `principal#serial`), claims for another app or host, a `max_role` below the session's, dev-tagged CAs at production, a P-256 operator key, certificate scopes narrowing a request and a module's handlers |
| `stage13_operator_trust_tests.cpp` | operator CAs from the root of trust (rotation moves them, at the next pump for a root the app rotates), certificate serials revoked by identity revocations, a trust without a root |
| `stage13_trust_tests.cpp` | `kTrust` pushing a root and identity revocations, refused without a release manager |
| `stage13_scopes_tests.cpp` | identities without scopes, a keyring line's scopes in the sandbox, ops denied after the role check, remote subscriptions to denied events |

## Writing tests

- Test files are named `<thing>_tests.cpp`. Tag every test case `[module][thing]`.
- Catch2 test names: no commas or non-ASCII characters (ctest passes the name back as a filter).
- Globals, patch points, events and lib names are process-wide: give each test file its own fixture namespace, globals and point / event ids, and leave every point unpatched (a destroyed sandbox reverts everything). The script and integration suites are never unity-built because their fixture namespaces share names.
- Network tests use loopback channel names and ports unique to their test case, TCP on `127.0.0.1` port 0 (a free port), and generous timeouts; they read game state through a client (or after the pumping thread has joined), never straight from another thread.
- Cases that use real multicast DNS-SD are tagged `[multicast]`: ctest gives them one `RESOURCE_LOCK` (they share UDP 5353) and the label `multicast`. They depend on the machine's network (and on Windows the system DNS-SD service). Cases that start other processes are tagged `[process]`.
- Script time: inject `sandbox_options::clock` for `rhp.sleep` / `rhp.timer`; use real time only where it is the subject (slicing, `wall_ms`, cross-thread cancel) and keep bounds generous for sanitizer builds.
- Prefer `STATIC_REQUIRE` for anything checkable at compile time. Cover boundaries, not just the happy path: empty packs, minimal types satisfying a concept, out-of-range values.
- Anything touching threads must stay clean under `linux-clang-tsan`. CI's `linux-clang-asan` builds without the shared precompiled header, so a missing `#include` shows there.
- A test passing doesn't make an open issue in `Docs/TODO.md` fixed.

## Benchmarks

`rhp_bench` puts every hot path next to a raw twin doing the same work without RHP, so the overhead is a ratio. Names are `<group> <raw|rhp|local|unchecked>: <work>` (`raw`: plain Lua or C++; `local`: the same work on a sandbox directly; `unchecked`: a sandbox with `cancel_checks = kNone`); give a new RHP path a raw twin of the same group and work. Run a **Release** build:

```bash
cmake --preset windows-msvc -DRHP_BUILD_BENCH=ON
cmake --build --preset windows-msvc --config Release
rhp_bench "[bench]" --reporter xml::out=after.xml
python Tools/bench/summarize.py after.xml
python Tools/bench/compare.py before.xml after.xml
```

`bench_e2e.cpp` measures whole requests on one thread (`io<zero_threads>` on both ends): a signed exec and a module call over the loopback transport next to the same exec on a sandbox (`e2e local`), and 32 module calls sent before any reply is read over TCP and reliable UDP on 127.0.0.1 (`e2e rhp: 32 pipelined module calls over ...`), where frames queue behind each other on both ends. Results and their history live in [Docs/benchmarks.md](../Docs/benchmarks.md).
