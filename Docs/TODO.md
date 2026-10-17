# Status and TODO

Last updated 2026-10-16. Stages 0–6 are implemented, the Stage 6 acceptance workflow passes, and the Stage 6 review follow-ups and the four reproduced runtime defects are fixed (ARCHITECTURE §32). Progress is tracked as "Stage N" only (no `v1` / `v2` naming anywhere). What remains is platform verification (macOS/iOS, hosted CI) and the optional items below.

## Stage 6 — complete

Done when: *a fleet finds hosts via mDNS and broadcasts a script.* Per `ARCHITECTURE.md` §16 and `decisions/networking.md`:

- [x] WebSocket transport (own RFC 6455 binary framing; proxy traversal; session TLS inside the tunnel)
- [x] UDP-reliable transport (fragmentation, seq/selective ACK/resend, CRC and congestion backoff; FEC remains optional)
- [x] Local IPC transport (owner-restricted named pipes, pathname AF_UNIX, same-UID abstract AF_UNIX on Linux/Android)
- [x] HTTP/1.1 gateway (exec, load/reload, call, revert/unload, introspection and cancel; request MAC, script signature, logical-session idle expiry)
- [x] mDNS discovery behind `Rhp::net::discovery` (`config<>::discovery<>`, `no_discovery`, explicit publication and separate library-name opt-in)
- [x] `Rhp::fleet<Cfg>`: discover hosts and collect every signed result, including per-host errors/deadlines and terminal recovery
- [x] `headless_server` and `rhp-cli` discovery/fleet options, including TLS/deadline controls
- [x] Stage 6 decisions, implementation notes, usage guide and module READMEs

Acceptance is exercised by the real CLI discovering two separately running hosts through DNS-SD and receiving `{42}` from both after a signed TLS broadcast. Both constrained-address and wildcard publication are covered. See [networking and fleet](guide/networking.md) and [Stage 6 decisions](decisions/stage6-networking.md).

### Stage 6 review (2026-10-09)

A code review of the Stage 6 working tree rewrote the transports' protocol code into sans-IO codecs and fixed what it found (ARCHITECTURE §31, AD6–AD10). Its follow-ups were finished on 2026-10-16 (ARCHITECTURE §32, AE1–AE7):

- [x] **HTTP answer integrity:** every authenticated answer carries `X-RHP-Proof` (MAC over status, content type and body under a key derived from the request's MAC; `security::verify_http_answer`), and proofs can be bound to the TLS channel (`X-RHP-Channel: tls-exporter`; `host_options::http_require_binding` makes it mandatory). A TLS-terminating relay test covers both.
- [x] **HTTP audit attribution:** `script_executed` carries the `peer` of each request.
- [x] **Gateway clock:** idle expiry follows `config<>::clock` through an offset `pump()` samples (the network thread never calls the user's clock); expiry tests advance a test clock. Proof freshness and the replay window deliberately stay on the system clock.
- [x] **Fleet engine:** `fleet.cpp` compiled engine; every member on one shared `io_context` with one I/O thread per fleet (none with `zero_threads`); `load` and `call` broadcasts (`stage6_fleet_tests.cpp`).
- [x] **Fleet recovery test** keeps one listener bound for the whole test (`tcp_gate`); no port number is released and re-bound.
- [ ] **Apple DNS-SD backend** (`mdns/native.cpp`) has been checked against the header only: build and run it on macOS/iOS.
- [ ] `[multicast]` tests use the real LAN (and on Windows the system DNS-SD service); they are serialized under ctest and now carry the ctest label `multicast`, so `ctest -LE multicast` leaves them out on machines without usable multicast. They still depend on the machine's network when run; hosted CI leaves them out on Windows and macOS/iOS, where the runners can't pass real multicast, so the Apple DNS-SD backend's runtime behaviour is still only checked by building it.

Possible follow-ups (not required for Stage 6): close fleet members in parallel at teardown (now one after another, each with the existing 1 s close wait); with a custom `config<>::clock`, re-arm the gateway's idle timer when `pump()` samples a new offset instead of re-checking every 25 ms; share one TLS-relay test fixture between `stage5_tests.cpp` and `stage6_tests.cpp`; `rhp-cli fleet` `load`/`call` modes; carry `http_grant::bound` into audit events.

Process for the stage: one branch + PR per stage, conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`), rebase-merge only when told to.

## Confirmed issues at the current commit

These issues were reproduced during the 2026-10-09 review of `8ffc954` and fixed on 2026-10-16 with regressions (ARCHITECTURE §32 AE1):

- [x] **P1 — async coroutine lifetime:** [`pending.hpp`](../Src/rhp/client/pending.hpp)'s awaiter unregisters its handle when a suspended coroutine is destroyed; the result is kept instead of resuming freed memory (`pending: destroying a suspended coroutine unregisters it`). Destroying the coroutine must still not race with its completion on the network thread.
- [x] **P1 — borrowed patch results:** [`patch_layers.hpp`](../Src/rhp/script/detail/patch_layers.hpp) rejects patch points whose default returns `std::string_view` (also inside `std::optional`) at compile time (`compile_fail/patch_point_borrowed_*.cpp`). User `convert<T>::pull` types must own their data.
- [x] **P2 — ledger replacement:** [`ledger.hpp`](../Src/rhp/script/ledger.hpp) move assignment undoes the destination's effects first; moved-from ledgers are empty.
- [x] **P2 — deferred audit outcomes:** [`host.cpp`](../Src/rhp/host/host.cpp) publishes a suspended request's `script_executed` when it finishes, with its final outcome, or as `kCancelled` when the identity is torn down first.
- [x] **CI syntax:** the macOS step name containing `TLS: ` in [ci.yml](../.github/workflows/ci.yml) is quoted, and the workflow parses with all four platform jobs. This fixes the syntax failure independently of the account billing block.

The 398-test suite of that review did not cover these cases; the regressions named above do.

## Hosted CI (first runs, 2026-10-16)

GitHub Actions runs again. Fixed for it: Apple deployment targets 13.3 / 16.3 (floating-point `std::to_chars`), no floating-point `std::from_chars` in `rhp-cli`, no separate `dns_sd` library on Apple, Asio included from its real `include/` (clang-cl can't read the `asio/include` symlink on Windows runners), and the iOS simulator preset on Ninja (the Xcode generator's per-SDK paths hid every suite from ctest). Windows, Linux (Clang, ASan+UBSan, TSan), Android, the iOS simulator (445/445) and the iOS device build pass there.

- [ ] **macOS: cross-process CLI tests.** On the hosted macOS runner the three `[process]` cases fail: a separately launched `headless_server` accepts one connection (an in-process probe from the test connects), then nothing listens on its port any more (`lsof` is empty, later connects are refused) while the process keeps running to its time limit; in reverse mode the host's dial never reaches `rhp-cli`'s listener. In-process TCP host/client tests pass on the same runner, and the cases pass on Windows, Linux and Android. Needs a Mac to debug; until then CI leaves out the `process` label on macOS (`ctest -LE "multicast|process"`).
- [ ] Real multicast cases are left out on hosted Windows and macOS/iOS runners (see the Stage 6 review list).

## Open items before or alongside Stage 6

- [x] **Hosted platform verification:** the Actions block is gone and the full matrix runs (see Hosted CI above); macOS runs except the `[process]` and multicast cases, iOS simulator tests pass, the hosted Android job passes.
- [ ] Verify macOS and iOS (simulator and device) on real hardware; update `decisions/platforms-and-toolchains.md` afterwards.
- [x] Run the TSan preset on resume, cancellation, TLS and Stage 6: full 427-test suite and final affected-case rerun pass.
- [x] Isolate the concrete Stage 6 host responsibility boundary: HTTP routing/logical sessions live in `host/gateway.cpp`; script dispatch and identity ownership remain in the existing engine.
- [ ] Branch hygiene: inspect current local and live remote refs before deciding which completed-stage branches to keep or prune; cached tracking refs can outlive deleted remote branches.
- [ ] Decide whether `CLAUDE.md` and `.claude/` are committed or ignored (inspect the current tracked/ignored state before changing policy). Agent worktrees (`.claude/worktrees/`) are ignored; `.claude/handoff.md` is a tracked, hook-generated file.
- [ ] Benchmarks: `Tests/bench` is planned ("when there is a hot path to measure"); nothing there yet.
- [ ] Optional: a second script engine behind a `config<>::engine<>` slot (the `engine` concept is deferred until a second engine exists).

## Known limits (documented, not bugs)

- Scripts run to completion with no execution budgets by default. Set host `instructions`, `wall_ms`, `memory` and optional `slice_us` for the workload. A sandbox slice is cooperative and does not bound an entire host pump containing several operations/identities.
- A count hook cannot interrupt a long C++ call: bound functions must return.
- Idle unauthenticated connections count against `pending_handshakes` and can delay a resume; a probe can tell a known session id from an unknown one.
- Mbed TLS calls are serialized by a process-wide lock (its PSA core is not thread-safe in the default build).
- A `zero_threads` host with a script stuck in `pump()` also stops its network (cancel cannot reach it).
- Handles are limited to trivially copyable, equality-comparable, non-arithmetic value types; there is no class or inheritance binding (`Rhp::lib` covers functions, variables and handles).
- Builds that must not accept remote code should use `RHP_ENABLE=OFF`; enabled builds need their own deployment/distribution review.

## Documentation

- [x] User guide: [`guide/`](guide/README.md) (getting started, exposing C++, scripts, host and client, connecting, configuration, security, reference)
- [x] Top-level README stage table and layout corrected
- [x] Current API documentation separated from roadmap sketches: architecture §6 links to the guide; implemented configuration slots, allocation scope and platform verification are stated explicitly. Historical decision logs retain their stage context.
- [x] Add the [networking guide](guide/networking.md) and transport-local READMEs for Stage 6.
- [x] Update the guide's available API table through Stage 6.

## Recorded validation (Stage 6 completion, 2026-10-16)

Debug builds on this Windows/WSL host and an Android phone. Desktop results are at `7cbcf88`; the one later commit only changes the expiry assertion of one HTTP unit test (a timing flake the phone found), and the phone was rerun after it:

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

Not run: macOS/iOS (no Apple host), hosted CI (billing block), long libFuzzer runs (the replay drivers ran), Release builds.

## Recorded validation (Stage 6)

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

After the review (2026-10-09; Debug, this Windows/WSL host only):

| Check | Result |
|---|---|
| MSVC x64 | 441/441 with `ctest -j 8` (before the review: 425/427 under `-j 8`, the two multicast cases colliding on UDP 5353) |
| Linux Clang 21 (`-Wconversion -Wsign-conversion -Wshadow -Werror`) | 441/441 |
| Linux Clang ASan + UBSan | 441/441 |
| Linux Clang TSan (Mbed TLS) | 441/441 |
| `RHP_ENABLE=OFF`, MSVC | 157/157 |
| Guide examples (`networking.md`) | compile under MSVC `/W4 /WX` |

Not rerun after the review: clang-cl, MSVC ASan, Android, libFuzzer long runs (the replay drivers ran), separate consumer builds, macOS/iOS.

The Android run found and fixed a libc++ portability defect: moving a `std::function` did not guarantee an empty source, allowing UDP's consumed dial callback to fire again on close. Callback consumption now clears it explicitly. The device's pathname-socket permission denial is handled through the standard abstract AF_UNIX mode with kernel peer-UID checks.

Apple DNS-SD backend syntax/warning checks pass against the official C API header. Actual macOS/iOS builds and runtime tests were not available on this Windows/WSL host; those platform checks remain open above. Debug results do not establish Release validation. The four earlier reproduced runtime defects remain open.

## Recorded validation (Stage 5)

The Stage 5 implementation notes record 398 tests on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan and Clang TSan; `RHP_ENABLE=OFF` has 155. They also record Android arm64 suites on a device and about 13 million libFuzzer inputs. The 2026-10-09 source review independently rebuilt MSVC x64 Debug and the OFF configuration and passed 398/398 and 155/155 tests. Those results describe exercised cases, not absence of defects. See [platform decisions](decisions/platforms-and-toolchains.md) for toolchains and unverified platforms.
