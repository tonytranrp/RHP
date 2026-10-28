# Status and TODO

Last updated 2026-10-27. Stages 0–12 are implemented, merged and tagged (`stage-0` … `stage-12`). `stage-13` tags the first part of Stage 13: 13a and the first wave of 13b are merged; the rest of 13b and 13c are open. Progress is tracked as "Stage N" only (no `v1` / `v2` naming anywhere). Known limits are in [the guide's limitations page](guide/limitations.md).

## Stage 13 — security for every deployment

Done when: *one RHP serves a developer's PC, test phones, QA builds and store apps, each with the posture it needs: what a build doesn't allow isn't in it, untrusted code is bounded, and production devices trust only what an offline root of trust allows.* Decisions: [Stage 13](decisions/stage13-security.md), ARCHITECTURE §39 (AL1–AL16). Usage: [Security](guide/security.md).

13a — hardening, sandbox, network, dev (implemented, merged, in `stage-13`):

- [x] Hardening levels: `RHP_HARDENING=dev|lan|production`, `config<>::hardening`, `host_options::hardening` (strictest wins; a config below the build doesn't compile); dev-only and production-excluded code compiled out (AL1, AL2)
- [x] Sandbox: no `__gc` for non-admin, pattern matching and plain find charged to the run (`lstrlib.c` patch), observe can't register handlers, hashed addresses, shared library tables restored on `revert_all` (AL3)
- [x] Limits per role: `observe_limits`, `kObserveCaps`, `kProductionCaps`; per-identity `request_rate`, `pump_requests`, `handlers` (AL4)
- [x] Network: admission control (per-source caps, first-byte deadline, eviction, `auth_failed.key`), reliable UDP stateless cookie, listening clients authenticate candidates side by side, `insecure_lan` with local peers only, IP-literal `server_name` check (a CA-checked dial to an IP address checks the certificate's IP addresses), Python client host-name check (AL5)
- [x] `set_enabled(false)` as a hard kill switch (AL6)
- [x] Dev sessions: `host_options::dev_session`, connect files, `rhp-cli connect --dev`, `headless_server --dev-session` (AL7)
- [x] Owner-only key files on every OS, file and PSK warnings, keygen defaults to patch and keeps the PSK in the file (AL8)
- [x] Release and revocation seq caps (`max_seq_jump`) (AL9)
- [x] Tests: `stage13_hardening_tests`, `stage13_network_tests`, `stage13_limits_tests`, admission / channel-policy / address / hardening / SipHash unit tests, compile-fail fixtures for the levels, every suite at every level; CI's `hardened` job (`production`)

13b — identities and trust (protocol revision 7; the first wave is merged, in `stage-13`):

- [x] Key handles (Ed25519, P-256 in software or through a sign callback for hardware keys), `key_store` (owner-only files with optional Argon2i passphrase, DPAPI, Apple Keychain, app callbacks), split `.rhpid` / `.rhpsign` files tagged `env=dev|prod`, `rhp-cli keygen --env --passphrase --device` (AL10, AL11)
- [x] Operator CAs and short-lived operator certificates, the `certified` signer with claims (expiry, app, env, audience, nonce, identity), signature contexts on the host, `rhp-cli ca` / `cert` / `--cert-file` (AL11)
- [x] Root of trust (threshold-signed, rotation with old and new thresholds, compromised keys' lists dropped on restore), identity revocations, `kTrust` (op 44), `rhp-cli root` / `revoke-identity` / `trust push` (AL12)
- [x] Capability scopes (`Rhp::scope_set`, `Rhp::cap<>`, a keyring scopes column; lib, cap, patch, event and op checks) (AL13)
- [x] The device-key authenticator (`security::device_keys`, host allow-lists, client `known_hosts` and trust on first use), and production refusing `env=dev` keys (AL10, AL11)
- [ ] Pairing wired into hosts: `kEnroll`, `rhp-cli pair`, on-device approval (AL10). The primitives are merged: CPace over X25519 (draft-21 vectors), `rhp-pair://` links, a one-time secret book, six-digit codes.
- [x] Certificates joined up: certificate scopes narrowing requests, operator CAs and serial revocation from the root, operator keys as key handles (AL11–AL13); `--sign-cmd` still open
- Untested so far: the Apple Keychain store, the typed passphrase prompt.

13c — production delivery (planned):

- [ ] Releases pulled over HTTPS with a signed channel index, keystore-MAC'd release state, support sessions through `Tools/rhp-relay`, a `mobile` limits preset, `pause_network()` / `resume_network()` (AL14)
- [ ] Hash-chained, forwarded audit; attestation hooks; a signed, persisted remote disable; hybrid ML-KEM (AL15)
- [ ] Store tiers and disclosure guidance (AL16)

Stage 13a follow-ups:

- The host doesn't print `keyring::warnings()` itself (callers show them).
- A connection that has sent part of a frame holds its handshake slot for a quarter of `handshake_timeout_ms` before a newcomer may take it, and until `handshake_timeout_ms` when no one needs the slot.
- Caps bound one identity, not the host.
- `table.sort` without a comparator, `load` of a huge chunk and `<` between long strings run in C without a cancel or limit check ([script README, "Known limits: other work in C"](../Src/rhp/script/README.md#what-untrusted-code-cant-do-stage-13-al3)).
- `lauxlib`'s `luaL_loadfilex` (file I/O) is still compiled and linked above `dev` (`lauxlib.c` is built whole), though no sandbox can reach it.
- The OpenSSL path of the IP-address certificate check isn't built on the Windows development machine (no OpenSSL there); Linux CI builds and tests it.

## Stage 12 — a test engine for Lua scripts

Done when: *the Lua a user writes against their API can be tested offline like any modern codebase (busted or Jest style, spies and fakes, a fake clock), with exact costs, coverage, snapshots, property tests and fuzzing, from a test executable, `rhp-cli`, ctest and an editor.* Decisions: [Stage 12](decisions/stage12-test-engine.md), ARCHITECTURE §38. Usage: [Testing scripts](guide/testing-scripts.md).

- [x] Sandbox test tools: exact instruction meter, allocation counters, line coverage from the compiled code, the `__rhp_test` bridge (journaled swaps of lib members, module exports, handle methods and variables), `sandbox::api` / `rhp.api()`, patch points and events callable by name, `exec_cached`
- [x] `Rhp::test`: runner (sandbox per file or per test, fake clock, checkpoint / revert per test, leak checks), busted DSL, luassert-compatible `assert` and matchers, Jest-style `expect`, spies / stubs / mocks, `test.*` (clock, events, points, measure, bench, budgets, deferred), snapshots, property tests with shrinking, fuzzing with a corpus, fakes (`fake<L>` and from a description)
- [x] Reports: text, TAP 14, JUnit, JSON events, GitHub annotations; LCOV, Cobertura; folded profiles
- [x] Entry points: `Rhp::test::main`, `rhp-cli test` (`--api`, `--api-from`, `--exe`), `rhp_add_lua_tests` (installed), `Examples/lua_tests`, the VS Code extension (`clients/vscode`)
- [x] Tests: fixture specs with known outcomes for every feature, golden reports, CLI and process tests, the package consumer, compile-fail cases for `fake<L>`, the `RHP_ENABLE=OFF` build, the extension with `node --test`; benchmarks (`[testing]`) and the optimizations they led to
- Stage 12 follow-ups: running test files in parallel; a watch mode in the runner; mutation testing; publishing the VS Code extension. (Module bytecode caching for `--isolation test`: done, each scripts-folder module is compiled once per run.)

## Stage 11 — debugger, profiler and tunables

Done when: *a developer can see and change a running program's tunables, see where its scripts spend their instructions, and stop one script at a breakpoint and inspect it while the program keeps running, from rhp-cli and an editor.* Decisions: [Stage 11](decisions/stage11-tools.md), ARCHITECTURE §37. Usage: [Tools](guide/tools.md).

- [x] Tunables: `Rhp::range` (enforced) / `step` / `unit` / `doc` tags on lib variables; `sandbox::tunables` / `tune` (journaled); `rhp.tunables()`; described stubs
- [x] Sampling profiler in the count hook (folded stacks, request-named outer frames), limits and cancels unchanged
- [x] Debugger: breakpoints, pause, step into / over / out by suspending the request coroutine from the line hook; stacks, locals, upvalues, module globals, path evaluation without running Lua; hits where a script can't pause; `rhp.debug` events
- [x] Wire revision 6 (`tunables`, `tune`, `profile`, `debug`), host routing per identity, owner session resets, client calls
- [x] rhp-cli: `tune`, `profile`, shell debugger commands, `dap` (Debug Adapter Protocol)
- [x] Tests: sandbox tools, wire messages, host/client integration, CLI shell and DAP; benchmarks of an armed debugger and the profiler
- Stage 11 follow-ups: conditional breakpoints; setting variables from the debugger; tools for release channels over the wire; a packaged VS Code extension for `rhp-cli dap`.

## Stage 10 — release manifests, persistence and rollout

Done when: *a host keeps a signed release across restarts, refuses old, foreign, expired or revoked ones, can watch a candidate and roll it back, and a fleet can spread a release stage by stage and pull it back.* Decisions: [Stage 10](decisions/stage10-releases.md), ARCHITECTURE §36. Usage: [Releases](guide/releases.md).

- [x] `Rhp::release`: canonical manifests, envelopes, revocation lists, release trust (channel patterns, thresholds), stores (memory, directory with synced renames)
- [x] `release::manager`: channels, checks, anti-rollback floors, in-place swaps, confirm modes (now / health / manual), restore with boot-attempt quarantine, revocation, expiry, events
- [x] Wire revision 5 (release ops), `host.serve`, client calls, `release_changed` host event
- [x] `fleet::rollout` (canaries, stages, health-watched, rollback on failure), `fleet::release_status`
- [x] `rhp-cli release` / `revoke` / `rollout`; `headless_server --releases`
- [x] Tests: unit (codecs, trust, manager), host/client integration, rollout over three TCP hosts, a CLI process test across a restart
- Stage 10 follow-ups: release ops on the HTTP gateway; delta updates; a host-side rollout coordinator. (The Python client's release calls and protocol revision 6: done.)

## Stage 9 — asynchronous bindings and methods on handles

Done when: *a binding can finish later on any thread while its script waits without blocking the game, everything it did stays revertible, and a handle carries its own methods and properties.* Decisions: [Stage 9](decisions/stage9-script-ergonomics.md), ARCHITECTURE §35.

- [x] `Rhp::async<T>` / `Rhp::promise<T>` (`core/async.hpp`), thread-safe, with stop requests
- [x] Asynchronous bindings: the request suspends, `pump()` wakes it, errors at the call site, undo journaled on arrival, orphaned results taken back, `limits.async_ms`, stats, `---@async` stubs
- [x] `lib::method<>` / `lib::property<>` on handles: one trampoline with `fn`, read-only members, names unique per handle, stubs
- [x] Tests: unit (core, script), compile-fail, host/client integration; benchmarks for methods, properties and ready async calls
- Stage 9 follow-ups: a host-side wake for asynchronous results (a headless host polls `pump()` anyway); writable properties (a setter with its own undo).

## Stage 8 — packaging, hardening and performance

Done when: *a stranger can install RHP with `find_package`, the reproduced threading and lifetime defects are fixed with regressions, and the hot paths have benchmarks and the optimizations they justify.* Decisions: [Stage 8](decisions/stage8-packaging-performance.md), ARCHITECTURE §34.

- [x] Documentation matches the code (audit of every page against the sources)
- [x] Hardening: logger level race, `network` required on transports (+ `link_decorator`), pump-thread checks for setup calls, `pending::request()` after `co_await`, `var` writes across threads, unsubscribe and detach barriers, blocking calls and destruction on the client's network thread, throwing callbacks
- [x] One generated build header (`<rhp/build_config.hpp>`) instead of per-header `RHP_ENABLE` / `RHP_TLS_HAS_*` fallbacks
- [x] Packaging: `install()` + exported `rhp-config.cmake`, a consumer test (`Tests/package`), third-party notices, hashed dependency pins
- [x] CI: `RHP_ENABLE=OFF`, MSVC ASan, fuzz smoke and package-consumer jobs (they run on GitHub Actions with the rest of `ci.yml`)
- [x] Benchmarks (`Tests/bench`) and the optimizations they justify, results in [benchmarks](benchmarks.md)
- Stage 8 follow-ups: coroutine yields still throw with the MSVC ABI outside x64 (on x64 they jump, `RHP_LUA_JUMP_YIELDS`); binding calls cost about 3x a raw C function (argument conversion through `result<T>`, role and label lookups). Done since: `msgpack` encoding appends whole values (`byte_buffer` appends with `memcpy`); an optional LTO build, `RHP_LTO` (off by default: static libraries built with LTO tie consumers to one compiler version). A `zero_threads` client may destroy itself from a callback its `poll()` runs; a fleet member destroyed from its own callback is not covered. Mbed TLS builds as `rhp_mbedtls_*` targets so a parent project can build its own copy; OpenSSL is found with `find_package` and shared with the parent.

## Open items

- [ ] **macOS: cross-process CLI tests.** On the hosted macOS runner the three `[process]` cases fail: a separately launched `headless_server` accepts one connection (an in-process probe from the test connects), then nothing listens on its port any more (`lsof` is empty, later connects are refused) while the process keeps running to its time limit; in reverse mode the host's dial never reaches `rhp-cli`'s listener. In-process TCP host/client tests pass on the same runner, and the cases pass on Windows, Linux and Android. Needs a Mac to debug; until then CI leaves out the `process` label on macOS (`ctest -LE "multicast|process"`).
- [ ] **Apple DNS-SD backend** (`net/mdns/native.cpp`): built by hosted CI (macOS, iOS simulator, iOS device), never run against real multicast: the multicast cases are left out on Apple runners. Run it on a Mac / iPhone.
- [ ] Real multicast cases are left out on hosted Windows and Apple runners. `[multicast]` tests use the real LAN (and on Windows the system DNS-SD service); they are serialized under ctest and carry the label `multicast` (`ctest -LE multicast` leaves them out).
- [ ] **TLS: one OpenSSL-client / Mbed TLS-server handshake failed once** (`a TLS handshake with an ephemeral certificate carries data both ways`, hosted `windows-clang-cl`, 2026-10-25); the rerun passed, and 150 local runs of every backend pair passed. Likely cause found and fixed: the Mbed TLS ephemeral certificate's serial was written raw with only its top bit cleared, so about 1 in 256 certificates had a first serial byte of 0x00 before a byte under 0x80, an INTEGER with padding DER forbids, which OpenSSL refuses (Mbed TLS reads it back); the first byte now always has bit 6 set. Not proven to be this failure (it wasn't reproduced): the test still prints the TLS error when the handshake fails, so if it happens again, start from that message.
- [ ] **ARM CRC32C at run time: verify on devices.** Verified on Android (Galaxy SM-S948U1, arm64-v8a, API 37, 2026-10-26: the runtime check compiled in, the CPU reports `crc32`, the CRC32C vector and split tests pass); Linux arm64 hardware, iOS and MSVC ARM64 remain. Linux and Android arm64 builds check the CPU at run time (`__builtin_cpu_supports("crc")`, enabled by a configure check in `Src/rhp/utils/CMakeLists.txt`: NDK 29 passes it); the path is built (android-arm64) but has not run on an ARM device. iOS uses the tables (`__ARM_FEATURE_CRC32` isn't defined for `arm64-apple-ios`, and Xcode's runtime may lack `__aarch64_cpu_features`); MSVC ARM64 isn't handled.
- [ ] Verify macOS and iOS (simulator and device) on real hardware; update `decisions/platforms-and-toolchains.md` afterwards.
- [ ] Release-build validation and long libFuzzer runs (recorded checks are Debug builds and replay drivers).
- [ ] Branch hygiene: completed stage branches (`stage-0-scaffold` … `stage-7-scheduling-events`, `stage-6-finish`, `codex/stage6`) and the agent worktree branch can be pruned once their PRs are merged; inspect the live remote refs first.
- [ ] Optional: a second script engine behind a `config<>::engine<>` slot (the `engine` concept is deferred until a second engine exists). Luau was re-examined for speed in the Lua speed pass and deferred ([lua-runtime](decisions/lua-runtime.md)): a build-time engine choice if ever, behind a one-week benchmark gate.
- Stage 7 follow-ups: a per-task `on_error` (tasks take the sandbox default because `rhp.spawn`'s varargs leave no room for an options table); `task:join(timeout)`; remote `stats`; an HTTP event stream; `sandbox.publish(name, values)` from C++ into script events.
- Stage 6 follow-ups: close fleet members in parallel at teardown (now one after another, each with the existing 1 s close wait); with a custom `config<>::clock`, re-arm the gateway's idle timer when `pump()` samples a new offset instead of re-checking every 25 ms; `rhp-cli fleet` `load`/`call` modes; carry `http_grant::bound` into audit events.

`CLAUDE.md` is committed; `.claude/handoff.md` (written by a local hook) and `.claude/worktrees/` are ignored.

Process for every stage: one branch + PR per stage, conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`), rebase-merge only when told to.

## Recorded validation

### Stage 13a (2026-10-27)

Debug builds of the `stage-13a-hardening` branch on this Windows/WSL host:

| Check | Result |
|---|---|
| `windows-msvc` | 1026/1026 |
| `windows-msvc`, unity build | 1026/1026 |
| `windows-msvc`, `RHP_HARDENING=lan` | 1027/1027 (tests needing dev features skip with a reason) |
| `windows-msvc`, `RHP_HARDENING=production` | 1027/1027 (same) |
| `windows-msvc`, `RHP_ENABLE=OFF` | 244/244 |
| `windows-clang-cl` | 1026/1026 |
| `windows-msvc-asan` | 1021/1021 |
| `linux-clang` (WSL, unity build) | 1026/1026 |
| `linux-clang`, `RHP_HARDENING=production` (WSL) | 1027/1027 |
| `linux-clang-asan` (WSL, no PCH) | 1024/1024 |
| `linux-clang-tsan` (WSL) | 1024/1024 after the pump-turn test waits for its requests to arrive (it failed once under load); the 154 integration tests then passed 3 runs in a row at `-j 8` |
| Pattern-matching runaways (`[b...a]*` over 128 KiB, a 1 MiB near-miss find) | 18.8 s / 25.4 s past a 100 ms wall before the fix; all 8 runaway patterns stop in 0.82 s after |
| Libraries above dev | `dumpbin /symbols` on the production `rhp_luad.lib`: no `luaopen_io` / `luaopen_debug` / `luaopen_package`, no `os.execute` / `getenv` / `exit` |

Not run locally: the OpenSSL path of the IP-address certificate check on Windows (no OpenSSL here; the Linux builds run it), hosted CI's new `hardened` job, Android and Apple.

### Cleanup pass (2026-10-27)

Debug builds of the `refactor-cleanup` branch (section-by-section cleanup, 33 bug fixes) on this Windows/WSL host, plus hosted CI:

| Check | Result |
|---|---|
| `windows-msvc` | 938/938 |
| `windows-msvc`, unity build | 932/932 |
| `windows-msvc`, `RHP_ENABLE=OFF` | 230/230 |
| `windows-clang-cl` | 932/932 |
| `windows-msvc-asan` | 927/927 |
| `linux-clang` (WSL, unity build) | 932/932 |
| `linux-clang-asan` (WSL, no PCH) | 930/930 |
| `linux-clang-tsan` (WSL) | 930/930 |
| Hosted CI (Linux, Windows, Apple, Android, fuzz) | all 15 jobs pass |
| Release benchmarks against `main` | within noise; the one regression found (an empty test file) fixed ([benchmarks](benchmarks.md#cleanup-pass)) |

### Lua speed pass (2026-10-26)

Debug builds of the `perf-lua-engine` branch on this Windows/WSL host and on a phone:

| Check | Result |
|---|---|
| `windows-msvc` | 916/916 |
| `windows-msvc`, `RHP_ENABLE=OFF` | 227/227 |
| `linux-clang` (WSL) | 904/904 |
| `linux-clang-asan` (WSL) | 902/902 after the misaligned-span fix (UBSan found it) |
| `linux-clang-tsan` (WSL) | 902/902 |
| `android-arm64` on a Galaxy SM-S948U1 (API 37) over adb | all 20 executables (14 suites, 6 fuzz replay drivers) pass |
| Release benchmarks, quiet machine | [benchmarks](benchmarks.md#lua-speed-pass) |

### Stage 8 (2026-10-24)

Debug builds on this Windows/WSL host, after the review fixes (`b59f3c4`):

| Check | Result |
|---|---|
| MSVC x64 (fresh build directory) | 595/595 |
| clang-cl x64 | 595/595 |
| MSVC x64 + ASan | 593/593 (the two `package` cases are skipped for sanitizer builds) |
| `RHP_ENABLE=OFF`, MSVC | 188/188 |
| Linux Clang 21 | 595/595 |
| Linux Clang ASan + UBSan | 593/593 |
| Linux Clang TSan (Mbed TLS) | 593/593, no TSan reports |
| Release benchmarks, Windows (MSVC) and WSL (Clang), each pinned to one core | [benchmarks](benchmarks.md) |

A read-only review of the branch found eleven defects (cancel checks lost inside handlers a pumped request reaches, a request pool that allocated while ending requests, a coroutine leaked by a failed start, a client destroyed by its own `poll()` callback, blocking calls on the client's network thread, Mbed TLS target names clashing with a parent's, ...); all are fixed, with regression tests where a test can observe them. Not run: Android (no device attached this time), macOS/iOS (hosted CI covers them), long libFuzzer runs.

### Stage 7 (2026-10-17)

Debug builds on this Windows/WSL host, after the review fixes (`ebc63c6`):

| Check | Result |
|---|---|
| MSVC x64 | 560/560 |
| clang-cl x64 | 560/560 |
| MSVC x64 + ASan | 560/560 |
| `RHP_ENABLE=OFF`, MSVC | 169/169 |
| Linux Clang 21 (`-Wconversion -Wsign-conversion -Wshadow -Werror`) | 560/560 (one `[multicast]` mDNS case failed once under `-j 8` on the real LAN and passed three reruns) |
| Linux Clang ASan + UBSan | 560/560 |
| Linux Clang TSan (Mbed TLS) | 560/560; the Stage 7 integration cases also repeated 5 times |

A read-only review of the branch found two crash-class defects (coroutine stacks overflowed by many arguments, effects recorded by finalizers during `lua_close`) and six edge-case bugs; all are fixed with regression tests. Not run: Android, macOS/iOS (hosted CI covers them), long libFuzzer runs, Release builds.

### Stage 6 completion (2026-10-16)

Debug builds on this Windows/WSL host and an Android phone. Desktop results are at `1b77c4b`; the one later commit only changes the expiry assertion of one HTTP unit test (a timing flake the phone found), and the phone was rerun after it:

| Check | Result |
|---|---|
| MSVC x64 (fresh build directory) | 459/459 |
| clang-cl x64 | 459/459 |
| MSVC x64 + ASan | 459/459 |
| `RHP_ENABLE=OFF`, MSVC | 161/161 |
| Linux Clang 21 (`-Wconversion -Wsign-conversion -Wshadow -Werror`) | 459/459 |
| Linux Clang ASan + UBSan | 459/459 |
| Linux Clang TSan (Mbed TLS) | 459/459; fleet, async and pending cases also repeated 10–25 times |
| Android arm64, NDK 29, SM-S948U1, API 36 | all 17 executables pass: 12 Catch2 suites and 5 fuzz replay drivers |
| Guide snippets (`networking.md` HTTP proofs) | compile under MSVC `/W4 /WX` |

Not run locally: macOS/iOS (no Apple host), long libFuzzer runs (the replay drivers ran), Release builds. Hosted CI (GitHub Actions, run 39022109410 at `edea41c`) then passed all seven runs: Windows MSVC and clang-cl, Linux Clang / ASan+UBSan / TSan, Android, and Apple (macOS without the `multicast` and `process` labels, the iOS simulator 445/445 without `multicast`, the iOS device build).

Hosted CI first runs (2026-10-16): fixed for it were Apple deployment targets 13.3 / 16.3 (floating-point `std::to_chars`), no floating-point `std::from_chars` in `rhp-cli`, no separate `dns_sd` library on Apple, Asio included from its real `include/` (clang-cl can't read the `asio/include` symlink on Windows runners), and the iOS simulator preset on Ninja (the Xcode generator's per-SDK paths hid every suite from ctest).

### Stage 6 (2026-10-09)

Before the review rewrite (the code has changed since; the post-review checks follow this table):

| Check | Result |
|---|---|
| MSVC x64 Debug | 425/425 full-suite baseline before the final two added cases |
| clang-cl x64 Debug | 425/425 full-suite baseline |
| MSVC x64 Debug + ASan | 427/427 full suite; final affected Stage 6 rerun 27/27 after the mobile fixes |
| Linux Clang 21 Debug | 425/425 full-suite baseline |
| Linux Clang ASan + UBSan | 427/427 full suite; final affected Stage 6 rerun 27/27 |
| Linux Clang TSan (Mbed TLS) | 427/427 full suite; final affected Stage 6 rerun 27/27 |
| `RHP_ENABLE=OFF`, MSVC | 157/157, including inert gateway/discovery/fleet APIs |
| Android arm64, NDK 29, SM-S948U1, API 36 | all 17 executables pass: 12 Catch2 suites and 5 fuzz replay drivers |
| Separate consumer builds | checked fleet guide function compiles on Windows/Linux; separate-process named pipe and AF_UNIX exec returns 42 and reuses the endpoint after shutdown; abstract AF_UNIX also passes across processes |
| Seeded libFuzzer + ASan/UBSan, RelWithDebInfo | frame 828021; msgpack 87141; envelope 80800; sandbox_escape 20195; network 682429; total 1698586 inputs, no crashes |
| Documentation/workflow | local links/anchors, fences, whitespace and CI YAML checked |

After the review (Debug, this Windows/WSL host only): MSVC x64 441/441 with `ctest -j 8`; Linux Clang 21 441/441; Clang ASan + UBSan 441/441; Clang TSan (Mbed TLS) 441/441; `RHP_ENABLE=OFF` 157/157; the `networking.md` guide examples compile under MSVC `/W4 /WX`.

The Android run found and fixed a libc++ portability defect: moving a `std::function` did not guarantee an empty source, allowing UDP's consumed dial callback to fire again on close. Callback consumption now clears it explicitly. The device's pathname-socket permission denial is handled through the standard abstract AF_UNIX mode with kernel peer-UID checks.

### Stage 5

The Stage 5 implementation notes record 398 tests on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan and Clang TSan; `RHP_ENABLE=OFF` has 155. They also record Android arm64 suites on a device and about 13 million libFuzzer inputs. The 2026-10-09 source review independently rebuilt MSVC x64 Debug and the OFF configuration and passed 398/398 and 155/155 tests. Those results describe exercised cases, not absence of defects. See [platform decisions](decisions/platforms-and-toolchains.md) for toolchains and unverified platforms.

## Closed

### Stage 7 — scheduling and events (2026-10-17)

Done when: *scripts schedule work and talk through events without a client request held open* ([decisions](decisions/stage7-scheduling-events.md), ARCHITECTURE §33 AF1–AF12): frame callbacks and timer control, `rhp.spawn` tasks, script events with `rhp.wait_event`, C++ listeners, subscription options and drop counts, remote subscription (wire revision 4), the handler error policy, and `rhp-cli` `subscribe` / `events`.

### Stage 6 — networking, discovery and fleet (2026-10-09 / 2026-10-16)

Done when: *a fleet finds hosts via mDNS and broadcasts a script* ([decisions](decisions/stage6-networking.md), ARCHITECTURE §30–§32): WebSocket, reliable UDP and local IPC transports, the HTTP/1.1 gateway (with answer proofs and optional channel binding), mDNS discovery behind `Rhp::net::discovery`, `Rhp::fleet<Cfg>` on one shared reactor, and `headless_server` / `rhp-cli` options. The 2026-10-09 review rewrote the transports' protocol code into sans-IO codecs; its follow-ups were finished on 2026-10-16 (AE1–AE7).

### Defects fixed after the 2026-10-09 review (§32 AE1)

- **P1 — async coroutine lifetime:** [`pending.hpp`](../Src/rhp/client/pending.hpp)'s awaiter unregisters its handle when a suspended coroutine is destroyed.
- **P1 — borrowed patch results:** patch points whose default returns `std::string_view` (also inside `std::optional`) are rejected at compile time.
- **P2 — ledger replacement:** `ledger` move assignment undoes the destination's effects first.
- **P2 — deferred audit outcomes:** a suspended request's `script_executed` is published when it finishes, with its final outcome.
- **CI syntax:** the macOS step name is quoted.
