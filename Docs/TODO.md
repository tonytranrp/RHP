# Status and TODO

Last updated 2026-10-09. Stages 0–5 are done; Stage 6 is not started. Progress is tracked as "Stage N" only (no `v1` / `v2` naming anywhere).

## Next: Stage 6

Done when: *a fleet finds hosts via mDNS and broadcasts a script.* Per `ARCHITECTURE.md` §16 and `decisions/networking.md`:

- [ ] WebSocket transport (own RFC 6455 framing; for proxy traversal only)
- [ ] UDP-reliable transport (seq/ack/resend, FEC lives here only)
- [ ] Local IPC transport (AF_UNIX / named pipe)
- [ ] HTTP/1.1 REST gateway (`POST /exec`, `/modules/{name}`, ...; `Authorization: RHP ...` + `X-RHP-Signature`; `limits.gateway_idle_ms` already reserved)
- [ ] mDNS discovery behind `Rhp::net::discovery` (`config<>::discovery<>` slot, `no_discovery` opt-out; advertise only on opt-in)
- [ ] `Rhp::fleet<Cfg>`: discover hosts, `fleet.exec<T>(...)` returns one result per host
- [ ] `headless_server` and `rhp-cli` discovery options
- [ ] Stage 6 decisions, implementation notes and READMEs in the usual shape

Process for the stage: one branch + PR per stage, conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`), rebase-merge only when told to.

## Confirmed issues at the current commit

These issues were reproduced during the 2026-10-09 review of `8ffc954`. They remain unfixed in the implementation; documentation changes do not close them.

- [ ] **P1 — async coroutine lifetime:** [`pending.hpp`](../Src/rhp/client/pending.hpp) retains a raw waiter handle after its coroutine is destroyed; later completion resumes freed memory. Until fixed, keep an awaiting coroutine alive until completion, including cancellation completion.
- [ ] **P1 — borrowed patch results:** [`patch_layers.hpp`](../Src/rhp/script/detail/patch_layers.hpp) accepts `std::string_view` results backed by an unrooted Lua string. Later garbage collection invalidates the view. Use owning strings for patched return values; define/restrict the supported borrowed-result contract.
- [ ] **P2 — ledger replacement:** [`ledger.hpp`](../Src/rhp/script/ledger.hpp) default move assignment discards a nonempty destination's effects without undoing them. Avoid move-assigning over live effects; add cleanup semantics and a nonempty-destination regression.
- [ ] **P2 — deferred audit outcomes:** [`host.cpp`](../Src/rhp/host/host.cpp) publishes `script_executed` before a suspended request completes; a later failure can leave an `ok` audit event. Retain audit state through final completion; until then, the client result is authoritative.
- [ ] **CI syntax:** quote the macOS step name containing `TLS: ` in [ci.yml](../.github/workflows/ci.yml). A YAML parse error at that line prevents jobs from being created, independently of the account billing block.

The existing 398-test suite passed in the review, but it did not cover the four reproduced runtime cases above. Add focused regressions when fixing them.

## Open items before or alongside Stage 6

- [ ] **CI cannot establish platform verification:** fix the workflow syntax above and resolve the account Actions billing/spending-limit block. Then run the full matrix; macOS, iOS and the hosted Android emulator remain unverified until their jobs actually pass.
- [ ] Verify macOS and iOS (simulator and device) on real hardware; update `decisions/platforms-and-toolchains.md` afterwards.
- [ ] Run the TSan preset (`linux-clang-tsan`) on the resume, cancel-relay and TLS paths before adding more transports.
- [ ] Reassess the large host/sandbox translation units when Stage 6 introduces a concrete responsibility boundary or measured build cost; file size alone does not require a refactor.
- [ ] Branch hygiene: inspect current local and live remote refs before deciding which completed-stage branches to keep or prune; cached tracking refs can outlive deleted remote branches.
- [ ] Decide whether `CLAUDE.md` and `.claude/` are committed or ignored (both are untracked).
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
- [ ] Add a short `Docs/guide/` page per transport when WebSocket, UDP and IPC land.
- [ ] Keep the guide's "available today" table (`guide/README.md`) in step with each stage.

## Recorded validation (Stage 5)

The Stage 5 implementation notes record 398 tests on MSVC, clang-cl, MSVC-ASan, Linux Clang, Clang ASan+UBSan and Clang TSan; `RHP_ENABLE=OFF` has 155. They also record Android arm64 suites on a device and about 13 million libFuzzer inputs. The 2026-10-09 source review independently rebuilt MSVC x64 Debug and the OFF configuration and passed 398/398 and 155/155 tests. Those results describe exercised cases, not absence of defects. See [platform decisions](decisions/platforms-and-toolchains.md) for toolchains and unverified platforms.
