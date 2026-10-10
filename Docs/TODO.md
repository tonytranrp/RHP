# Status and TODO

Last updated 2026-10-09. Stages 0–6 are implemented and the Stage 6 acceptance workflow passes. Progress is tracked as "Stage N" only (no `v1` / `v2` naming anywhere). Platform verification and earlier runtime defects are recorded separately below.

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

A code review of the Stage 6 working tree rewrote the transports' protocol code into sans-IO codecs and fixed what it found (ARCHITECTURE §31, AD6–AD10). Still open from that review:

- [ ] **HTTP answer integrity:** proofs aren't bound to the TLS channel and answers carry no MAC, so an HTTP client that doesn't verify the host certificate can be fooled by a TLS-terminating relay. Add `X-RHP-Proof` (MAC over request nonce, status, content type and body) and an optional channel-bound proof; add the Stage 5 relay test for HTTP.
- [ ] **HTTP audit attribution:** `script_executed` names the logical session; the peer recorded is the first HTTP caller of that key. Carry the peer per request.
- [ ] **Gateway clock:** idle expiry and the replay window use the system clocks, not the host's injectable clock, so expiry tests wait on real time.
- [ ] **Fleet engine:** fleets are header-only with one client (and, by default, one I/O thread) per member. Move the loop into a compiled engine on one shared I/O context; add `call`/`load` broadcasts.
- [ ] **Fleet recovery test** reserves a TCP port, closes it, then listens on that number again; another process can take it in between.
- [ ] **Apple DNS-SD backend** (`mdns/native.cpp`) has been checked against the header only: build and run it on macOS/iOS.
- [ ] `[multicast]` tests use the real LAN (and on Windows the system DNS-SD service); they are serialized under ctest but still depend on the machine's network.

Process for the stage: one branch + PR per stage, conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`), rebase-merge only when told to.

## Confirmed issues at the current commit

These issues were reproduced during the 2026-10-09 review of `8ffc954`. They remain unfixed in the implementation; documentation changes do not close them.

- [ ] **P1 — async coroutine lifetime:** [`pending.hpp`](../Src/rhp/client/pending.hpp) retains a raw waiter handle after its coroutine is destroyed; later completion resumes freed memory. Until fixed, keep an awaiting coroutine alive until completion, including cancellation completion.
- [ ] **P1 — borrowed patch results:** [`patch_layers.hpp`](../Src/rhp/script/detail/patch_layers.hpp) accepts `std::string_view` results backed by an unrooted Lua string. Later garbage collection invalidates the view. Use owning strings for patched return values; define/restrict the supported borrowed-result contract.
- [ ] **P2 — ledger replacement:** [`ledger.hpp`](../Src/rhp/script/ledger.hpp) default move assignment discards a nonempty destination's effects without undoing them. Avoid move-assigning over live effects; add cleanup semantics and a nonempty-destination regression.
- [ ] **P2 — deferred audit outcomes:** [`host.cpp`](../Src/rhp/host/host.cpp) publishes `script_executed` before a suspended request completes; a later failure can leave an `ok` audit event. Retain audit state through final completion; until then, the client result is authoritative.
- [x] **CI syntax:** the macOS step name containing `TLS: ` in [ci.yml](../.github/workflows/ci.yml) is quoted, and the workflow parses with all four platform jobs. This fixes the syntax failure independently of the account billing block.

The existing 398-test suite passed in the review, but it did not cover the four reproduced runtime cases above. Add focused regressions when fixing them.

## Open items before or alongside Stage 6

- [ ] **Hosted platform verification:** resolve the recorded Actions billing/spending-limit block and run the full matrix; macOS, iOS and the hosted Android emulator remain unverified until their jobs actually pass. The workflow syntax is corrected.
- [ ] Verify macOS and iOS (simulator and device) on real hardware; update `decisions/platforms-and-toolchains.md` afterwards.
- [x] Run the TSan preset on resume, cancellation, TLS and Stage 6: full 427-test suite and final affected-case rerun pass.
- [x] Isolate the concrete Stage 6 host responsibility boundary: HTTP routing/logical sessions live in `host/gateway.cpp`; script dispatch and identity ownership remain in the existing engine.
- [ ] Branch hygiene: inspect current local and live remote refs before deciding which completed-stage branches to keep or prune; cached tracking refs can outlive deleted remote branches.
- [ ] Decide whether `CLAUDE.md` and `.claude/` are committed or ignored (inspect the current tracked/ignored state before changing policy).
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
