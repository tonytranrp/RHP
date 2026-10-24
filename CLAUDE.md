# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

RHP ("Remote Hot Patch") is a portable C++23 static library: a running program accepts authenticated, signed Lua scripts over pluggable transports, runs them in a sandbox against a C++-declared API, and can undo everything they did. Lua is glue; scripts only reach what C++ exposes via `Rhp::lib<>` / `Rhp::patch_point<>`. `Docs/ARCHITECTURE.md` is the source of truth (decision ids (S*, T*, U*, W*…AF*) refer to its §21–§33, e.g. AA §28, AF §33); `Docs/decisions/*.md` hold per-topic decisions; every `Src/rhp/<module>/README.md` states that module's rules.

## Rules that are easy to break

- **Never** name anything `v1`/`v2`/`V*` (identifiers, files, folders, tags). Progress is "Stage N" (Stages 0–7 implemented; validation and platform limits are in Docs/TODO.md). The only numbers allowed are the wire `protocol_revision` and per-module `revision` counters.
- Work is one branch + PR per stage, conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`). Merge only when the user says so; stage PRs are rebase-merged.
- Style (`.clang-format`, `Docs/decisions/naming-and-style.md`): `snake_case` everything, `kPascal` constants/enumerators, trailing `_` on private data members, short PascalCase template params constrained in the parameter list, `#pragma once`, no column limit, heavy `Rhp::config<>::x<..>::y<..>` / `Rhp::lib<"n">::fn<..>` type-level DSLs. Strings: `string_view` in, `std::string` out, UTF-8. Errors are `Rhp::result<T>` (`fail(errc::kX, "msg", "where")`); `error::message`, `where` and `traceback` are owning `std::string`s.
- Warnings are errors (`RHP_WARNINGS_AS_ERRORS`); `-Wmissing-field-initializers` bites designated/aggregate inits like `error{}`.
- No `file(GLOB)`; each module has its own `CMakeLists.txt` using `rhp_add_module` (`cmake/RhpModule.cmake`). Dependencies are pinned in one file, `cmake/Dependencies.cmake`, fetched with CPM.
- OS `#ifdef`s only in `Src/rhp/platform/` (`os.hpp` reads `RHP_PLATFORM_*`; `random.cpp`) and backend `.cpp`s (`net/local/local.cpp`, `net/mdns/*.cpp`). Asio headers only in network backend `.cpp` files and native test backends; they stay out of public headers. Lua and Monocypher C sources are compiled as C++ through wrapper `.cpp`s. Mbed TLS is the Stage 5 exception: `cmake/RhpMbedtls.cmake` enables C for its upstream subproject; presets supply matching C/C++ compilers. Do not introduce a second dependency build or change this boundary casually.
- Never `using Rhp::net::link;` at global scope (POSIX `::link()`); tests use a `net_link` alias.
- Lua runs only on the thread that calls `pump()`; the network has its own I/O thread; request/reply rings, cancel relays, queued Lua events and mutex-protected pending results carry cross-thread state (`Docs/decisions/threading-model.md`).

## Build & test

Presets (Ninja Multi-Config except `ios-device`, which is Xcode; build presets for all, test presets for the desktop presets, `macos` and `ios-sim`): `windows-msvc`, `windows-clang-cl`, `windows-msvc-asan`, `linux-clang`, `linux-clang-asan`, `linux-clang-tsan`, `linux-clang-fuzz`, `macos`, `ios-sim`, `ios-device`, `android-x64`, `android-arm64`.

```bash
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

Single test / suite (every Catch2 `TEST_CASE` is its own ctest entry; suites are `rhp_<module>_tests`, plus `rhp_integration_tests`, `rhp_cli_tests`, fuzz `fuzz.<name>`, `compile_fail.<name>`, `example.<name>`; labels `fuzz`, `compile_fail`, `multicast`, `process`):

```bash
ctest --preset windows-msvc -R "some test name"
ctest --preset windows-msvc -L fuzz
ctest --test-dir build/windows-msvc -C Debug -R stage5
```

- `RHP_ENABLE=OFF` (hosts become inert stubs, patch points direct calls) must still build and pass: `cmake --preset windows-msvc -B build/off-msvc -DRHP_ENABLE=OFF`, then `ctest --test-dir build/off-msvc -C Debug`.
- TLS: `RHP_WITH_TLS`, `RHP_TLS_OPENSSL=AUTO|ON|OFF`, `RHP_TLS_MBEDTLS`. The TSan preset uses Mbed TLS (system libcrypto isn't instrumented → false races).
- Fuzzing: `RHP_FUZZ=ON` (Clang, preset `linux-clang-fuzz`) builds libFuzzer executables `rhp_fuzz_<frame|msgpack|envelope|sandbox_escape|network>`; without it they are ctest replay drivers (`Tests/fuzz/README.md`).
- Android: set `ANDROID_NDK_HOME`; `python Tools/android/run_tests.py build/<dir>` pushes and runs every suite over adb. iOS simulator tests run through `Tools/ios/simctl_run.sh`.
- Windows presets need the MSVC environment (`vcvars64.bat`, which needs `vswhere` on PATH) — wrap commands in a `.bat` that calls it. Linux presets run in WSL (`Ubuntu`); run WSL scripts from files (`wsl ... bash script.sh < /dev/null`) because `bash -c` mangles `$vars`. `CPM_SOURCE_CACHE` is shared; a first configure can fail on a cached git update — rerun.
- Windows builds sometimes fail with `C1083`/`LNK1104` file locks (especially while a WSL build reads the same tree); retry. After interrupted builds, ninja deps can go stale and produce bogus failures: verify from a clean build dir. Don't build Windows and Linux presets at once.
- Catch2 test names must not contain commas or non-ASCII characters (ctest passes the name back as a filter).
- Hosted CI (`.github/workflows/ci.yml`: linux, windows, apple, android jobs) passes; it leaves out `multicast` on Windows/Apple and `process` on macOS (open issue in Docs/TODO.md). macOS/iOS have not run on real hardware. Open reproduced runtime issues are in `Docs/TODO.md`; do not describe them as fixed merely because existing tests pass.

## Architecture (big picture)

Library code lives in `Src/rhp/<module>/` (included as `<rhp/<module>/x.hpp>`, targets `Rhp::<module>`, umbrella `Rhp::rhp` / `<rhp/rhp.hpp>`). **Layer order and dependencies are maintained in `Src/rhp/CMakeLists.txt` and each module's target declarations. Declaration order alone does not enforce the dependency graph; inspect `DEPS` / `PRIVATE_DEPS` when changing boundaries.**

`utils`(0) → `core`(1: result, value, role, limits; ledger lives in script) → `platform`, `wire`(2) → `net`, `security` (+`security/tls`), `exec`, `script`, `event`(3) → `audit`, `session`(4) → `config`, `host`, `client`(5).

How the pieces fit across modules:

- **Config DSL** (`config/config.hpp`): `Rhp::config<>::transport<..>::auth<..>::executor<..>::tls<B>…` supplies defaults for every implemented policy slot; each slot is validated by a concept. `Rhp::host<Cfg>` / `Rhp::client<Cfg>` are thin templates over **type-erased engines** (`host/host.cpp`, `client/client.cpp` — the big translation units) so template cost stays out of user code.
- **Script engine** (`script`): `sandbox` = one Lua 5.5 state + undo ledger per key identity; `Rhp::lib<>` binds C++ functions/vars (with `undo<>` inverses), `patch_point<>` is the hookable call site, modules have revisions, `reload` calls `on_save`→`on_restore`, a scheduler time-slices coroutine-like scripts from `pump()`. Instruction/memory/wall limits come from `core/limits.hpp`.
- **Wire** (`wire`): frames (CRC32C omitted on encrypted links), MessagePack values, typed envelopes in `messages.{hpp,cpp}`, `protocol_revision` in `ops.hpp` (currently 4).
- **Transport** (`net`): `transport` concept + `transport_ops`; `link` (connected byte stream; `loopback()`, `encrypted()`, `channel_binding()`), `listener`, `io_context` (Asio behind a wall). Transports: loopback, TCP, WebSocket, reliable UDP and IPC; custom ones are first-class (`Examples/custom_transport`). Discovery is a separate opt-in publication policy; the HTTP gateway is a host frontend feeding the existing dispatcher.
- **Security**: PSK keyring → identity → role (`observe`/`patch`/`admin`); mutual BLAKE2b challenge-response (Monocypher); patch/admin scripts must be Ed25519-signed by a trusted signer. `security/tls` is a sans-IO TLS 1.3 engine/context abstraction with OpenSSL ≥3.0 and Mbed TLS backends; `session::tls_client/tls_server` wrap any `link`, the accepting side sniffs `0x16` to tell TLS from plaintext, and the RFC 9266 tls-exporter value is mixed into the PSK transcript and the resume proofs (so a TLS-terminating relay can't authenticate). TLS applies to non-loopback dials over network transports (TCP, WebSocket, reliable UDP) and `require_tls`; plaintext from non-loopback peers is refused unless `insecure_lan`.
- **Session** (`session`): framing + auth + MAC + ack/nack/resend + heartbeat. A lost link detaches the session for `limits.resume_ms`; the dialing side redials and sends a sealed `kResume` (proof bound to the new link); both sides resend unacked frames so calls run exactly once. Works in reverse mode (host dials the client); a dialing host opens with a ping because the accepting side waits to speak first; hosts send `goodbye()` on shutdown.
- **Events/audit**: host events are published on the pump thread through a thread-safe hub (`session_opened`, `session_resumed`, `handler_failed`, …); `audit` sinks subscribe. Script events (`rhp.publish`) stay inside one identity's sandbox; C++ hears them through `sandbox::on_script_event` / `host.on_script_event`, clients through `client.on` (wire `kSubscribe` / `kEvent`; the host engine is itself a `lua_event` listener for remote subscriptions).
- **Scheduling** (`script/puc_lua/schedule.cpp`, `tasks.cpp`, `script_events.cpp`): timers and frame callbacks share one schedule entry (no overlapping calls); `rhp.spawn` tasks are requests of their own owned by the spawning module; a failing handler follows `handler_error_policy` (`report` by default undoes only that call; patch handlers still fault). Every request's end goes through `request_ended`.

Tests (`Tests/README.md`): `unit/<module>/` mirrors `Src/rhp/<module>/`; `integration/` (`host_client_tests`, `stage4_tests`, `stage5_tests` with a `cuttable` transport and a `tls_relay`, `stage6_tests`, `stage6_fleet_tests`, `stage7_tests`) runs host↔client over loopback/TCP; `compile_fail/` files must fail to compile with `RHP_COMPILE_FAIL` defined; `support/rhp_test/` has shared helpers. Globals, patch points, events and lib names are process-wide — give each test file its own fixture namespace/ids and leave every point unpatched. Tag test cases `[module][thing]`; network tests use unique loopback names and TCP port 0.

For current usage, start at `Docs/guide/README.md`. Compile complete guide examples when changing them, check setup results and callback lifetimes, and keep unimplemented slots/API sketches out of runnable examples.

`Examples/` (hello_console, frame_loop, remote_exec, custom_transport, headless_server) and `Tools/rhp-cli` (REPL and subcommands `keygen`, `pubkey`, `sign`, `connect`, `run`, `exec`, `stubs`, `blob`, `watch`, `events`, `discover`, `fleet`; `--tls/--ca/--cert/--key` flags) are the end-user entry points.
