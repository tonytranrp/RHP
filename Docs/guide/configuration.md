# Configuration

Three places to configure RHP: the type-level `Rhp::config<>` (policies), run-time option structs, and CMake switches.

## `Rhp::config<>`

A policy pack with defaults for every implemented slot. Each link fills one slot and is checked by a concept on the line where you write it; anything unset keeps its default. A later link overrides an earlier one for the same slot.

```cpp
using my_cfg = Rhp::config<>::transport<Rhp::net::tcp> // Rhp::net::transport
    ::tls<Rhp::security::tls::auto_backend>            // Rhp::security::tls::backend
    ::codec<Rhp::wire::msgpack>                        // Rhp::wire::codec
    ::auth<Rhp::security::psk_keyring>                 // Rhp::security::authenticator
    ::signer<Rhp::security::ed25519>                   // Rhp::security::signer
    ::executor<Rhp::exec::pumped>                      // Rhp::exec::executor
    ::io<Rhp::exec::owned_io_thread>                   // Rhp::exec::io_runner
    ::limits<Rhp::limits{.slice_us = 2'000}>           // value
    ::errors<Rhp::errors::expected>                    // Rhp::errors::mode
    ::clock<Rhp::exec::steady_clock>                   // Rhp::exec::clock_source
    ::logger<Rhp::core::stderr_logger>                 // Rhp::core::logger
    ::discovery<Rhp::net::mdns>;                       // Rhp::net::discovery

// Use my_cfg as Rhp::host<my_cfg> / Rhp::client<my_cfg>'s template argument.
```

That chain is exactly `Rhp::config<>`; write only the links you change:

```cpp
using lan_cfg  = Rhp::config<>::transport<Rhp::net::websocket>;                 // everything else default
using test_cfg = Rhp::config<>::transport<Rhp::net::loopback>::io<Rhp::exec::zero_threads>;
using throw_cfg = Rhp::config<>::errors<Rhp::errors::throwing>;
```

Inside your own templates (a dependent context) write `Cfg::template transport<X>`.

A clock and a logger are default-constructible types the host creates itself; reach them with `host.clock()` and `host.logger()`:

```cpp
struct game_clock { // script time follows the game's clock (paused while the game is paused)
    [[nodiscard]] std::chrono::steady_clock::time_point now() const { return game::time_now(); }
};

struct engine_log {
    [[nodiscard]] bool enabled(Rhp::log_level level) const { return level >= Rhp::log_level::kInfo; }
    void write(Rhp::log_level level, std::string_view message) { engine::log(static_cast<int>(level), message); }
};

using cfg = Rhp::config<>::clock<game_clock>::logger<engine_log>;
```

`game::time_now()` and `engine::log()` stand for your engine's own functions. `enabled` may be called from several threads at once; one host's `write` calls never overlap.

| Slot | Default | Alternatives and what they do |
|---|---|---|
| `transport` | `net::tcp` | `net::loopback` (in-process, for tests and embedding), `net::websocket`, `net::udp_reliable`, `net::local_ipc` ([networking](networking.md#transports)), or your own ([guide](connecting.md#your-own-transport)) |
| `tls` | `tls::auto_backend` | `tls::openssl`, `tls::mbedtls`, or `tls::none` (no TLS; non-loopback endpoints then need `insecure_lan`) |
| `codec` | `wire::msgpack` | any `wire::codec` (RHP's own MessagePack codec by default) |
| `auth` | `security::psk_keyring` | any `security::authenticator` (mutual PSK challenge-response by default) |
| `signer` | `security::ed25519` | `security::unsigned_scripts`: the explicit, typed opt-out of script signing |
| `executor` | `exec::pumped` | Lua runs on the thread that calls `pump()` (the only executor today) |
| `io` | `exec::owned_io_thread` | `exec::zero_threads`: no threads; `pump()` and blocking client calls poll the network |
| `limits` | `Rhp::limits{}` | see below |
| `errors` | `errors::expected` | `errors::throwing` |
| `clock` | `exec::steady_clock` | your game clock or a manual clock, for `rhp.sleep` / `rhp.timer` and deterministic tests |
| `logger` | `core::stderr_logger` (`set_min_level()`, through `host.logger()`) | `core::null_logger`, or any type with `enabled(level)` and `write(level, msg)` (spdlog, logcat, os_log, your engine log); `log_level::kOff` silences it |
| `discovery` | `net::mdns` | `net::no_discovery`, explicit `net::mdns_wire`, or a type satisfying `net::discovery`; advertisement remains an explicit runtime opt-in |

### Which `io` policy?

| | `owned_io_thread` (default) | `zero_threads` |
|---|---|---|
| Network runs on | one RHP-owned `std::jthread` | the caller (`pump()` / client calls / `poll()`) |
| A script stuck in `pump()` | cancel and disconnect still reach it, heartbeats keep flowing | the network stops too; cancel cannot get through |
| Use for | network progress independent of the application's pump | single-threaded integrations and deterministic tests whose loop explicitly polls |

### Error mode

`errors::expected` (default): result-bearing operations return `Rhp::result<T>` (a `std::expected<T, Rhp::error>`). `errors::throwing`: the same operations return `T` and throw `Rhp::exception`. Per call, `Rhp::unwrap(client.exec<int>(...))` converts one result. This selects how result-bearing host/client operations report ordinary errors; constructors, allocation failures and user code are not a blanket no-throw guarantee. `script::sandbox` returns `result<T>` directly and does not take a host/client error policy.

## Limits

`Rhp::limits` is a structural type: it is a template argument for `config<>::limits<>` and the same type configures a standalone sandbox. Configure each peer independently: a client's script-limit fields do not set the host's execution budgets. Zero has field-specific meaning; it is not universally unlimited.

```cpp
using cfg = Rhp::config<>::limits<Rhp::limits{.instructions = 50'000'000, .memory = 64u << 20, .wall_ms = 250, .slice_us = 2'000}>;
```

| Field | Default | What |
|---|---|---|
| `instructions` | 0 | total per run; once hit, sticky for the rest of that run |
| `memory` | 0 | bytes per Lua state; once hit, sticky for the run |
| `wall_ms` | 0 | execution time accumulated while a request runs, excluding suspension; count-hook checks report `kTimeout` |
| `slice_us` | 0 | opt-in cooperative slice for a sandbox operation/pump; 0 runs to completion. Only a yieldable request can be sliced |
| `max_frame` | 4 MiB | maximum payload bytes, excluding the header and trailers; 0 permits only empty payloads |
| `max_blob` | 256 MiB | largest blob per `on_blob` sink (0 = only empty blobs) |
| `revisions` | 8 | source revisions kept, including the current one; at least one is retained even when this is 0 |
| `pending_handshakes` | 64 | host's unauthenticated connection cap; 0 refuses new handshakes |
| `handshake_timeout_ms` | 5000 | initial-handshake timeout; 0 disables it. Resume attempts have a separate bounded timeout |
| `heartbeat_ms` | 2000 | ping/retry interval; 0 disables the heartbeat timer |
| `heartbeat_misses` | 3 | quiet heartbeat intervals before link loss; 0 disables this dead-peer threshold |
| `resume_ms` | 6000 | how long a lost link may come back; 0 = a lost link ends the session |
| `backoff_min_ms` / `backoff_max_ms` | 250 / 30000 | capped redial backoff for dialing hosts and resuming clients, with jitter |
| `gateway_idle_ms` | 5 min | logical HTTP identity idle expiry; stops pending requests too; 0 disables expiry |
| `cancel_check_instructions` | 1000 | count-hook interval for cancellation and budgets; 0 uses the default interval |
| `cancel_checks` | `kRequests` | which runs check for `cancel()` (an `Rhp::cancel_scope`): `kRequests` (exec / load / call / reload and tasks, plus the main thread while an operation runs), `kEverything` (handler calls too: timers, frame callbacks, events, patch handlers hit from game code), `kNone` (nothing: a cancel stops a request only before it starts or resumes). The instruction, wall-time and slice limits arm the check for every run whatever this says |
| `event_queue` | 65536 | events queued per sandbox for its next pump (C++ fires from other threads, `rhp.publish`); more are dropped and counted; 0 = unlimited |
| `async_ms` | 0 | script time an asynchronous binding (`Rhp::async<T>`) may take before the waiting script gets `kTimeout`; a result that arrives later is taken back through the binding's `undo<G>`; 0 = no limit |

Instruction, memory and execution-time limits default to unlimited; slicing defaults to off. Set budgets on the **host** that executes code. Instruction/time checks run at hook boundaries and cannot preempt C++ bindings. The hook counts at safe points while it is armed (each loop iteration is charged its body's length, each Lua call 1), so loop-heavy code runs at about raw Lua speed under it, and `instructions` is a bound counted that way rather than an exact instruction count (the test runner's meter and `measure` stay exact). `cancel_checks` confines it to requests by default: a host only ever cancels requests, and a handler that may loop forever needs a limit anyway. `kNone` buys only the last few percent ([performance](performance.md#the-cancel-hook-limitscancel_checks)). A host pump can dispatch several operations and pump several identity sandboxes, so `slice_us` is not a hard bound on the whole application frame.

```cpp
// A game host: budgets for every identity, 2 ms slices, handlers stoppable from a watchdog too.
using game_cfg = Rhp::config<>::limits<Rhp::limits{
    .instructions = 50'000'000, .memory = 64u << 20, .wall_ms = 250, .slice_us = 2'000,
    .cancel_checks = Rhp::cancel_scope::kEverything, .async_ms = 5'000}>;
```

`executor<pumped>` is the only implemented script execution model; accepting a custom marker does not install a scheduler. `clock` affects script sleep/timer time on a host or local sandbox, and the HTTP listener's idle expiry (`pump()` samples the clock's offset from `steady_clock` for the network thread, so the clock is only ever called on the pump thread); not protocol deadlines, heartbeats or HTTP proof freshness. The client logger/clock slots do not currently supply engine callbacks. `engine<>` is not a slot (Lua 5.5 is the only engine).

## Option structs

Passed to the constructors at run time: [`Rhp::host_options`](host-and-client.md#rhphost_options), [`Rhp::client_options`](host-and-client.md#rhpclient_options), and `Rhp::script::sandbox_options` for the standalone sandbox:

| `sandbox_options` field | What |
|---|---|
| `caller_role` | role of the identity (local default: patch) |
| `limits` | as above |
| `memory` | a `std::pmr::memory_resource*` for every Lua allocation; when null, the C heap (`malloc` / `realloc` / `free`, as Lua's own allocator: blocks grow in place). `limits.memory` applies either way |
| `output` / `on_output` | receive `print()` lines (with request and module for `on_output`) |
| `on_emit` | receive `rhp.emit` values |
| `on_result` | receive the final result of requests that suspended |
| `clock` | script time for `rhp.sleep` / `rhp.timer` / `rhp.after` / `rhp.every` / `rhp.wait_event` timeouts |
| `identity` | caller-supplied label for this local identity |
| `handler_errors` | what a failing timer, frame callback, event handler or task does when it sets no `on_error`: `report` (default), `remove` or `fault` |
| `on_handler_error` | receives each failed handler call (`handler_failure`); empty = one `[handler failed] ...` output line |

Fleets take `Rhp::fleet_options` (`client` options for every member, `timeout` 10 s shared per broadcast, `tls`, `insecure_lan`); see [networking](networking.md#fleets).

`sandbox::on_script_event(name, fn)` and `sandbox::stats()` complete the standalone sandbox's Stage 7 API (see [script events](writing-scripts.md#script-events)).

The supplied memory resource must outlive the sandbox. It covers Lua allocations, not every C++ container or effect allocation. The host does not expose a memory-resource constructor option. `on_result` runs for requests that suspended at least once; synchronous outcomes are returned by the operation itself.

## CMake options

| Option | Default | What |
|---|---|---|
| `RHP_ENABLE` | ON | OFF compiles hosts to inert stubs (`kDisabled`), patch points to direct calls, and skips Lua, Asio and Monocypher entirely |
| `RHP_BUILD_TESTS` | top-level only | build `Tests/` |
| `RHP_BUILD_EXAMPLES` | top-level only | build `Examples/` |
| `RHP_BUILD_TOOLS` | top-level only | build `Tools/` (`rhp-cli`; needs `RHP_ENABLE=ON`) |
| `RHP_WARNINGS_AS_ERRORS` | top-level only | warnings are errors in RHP's own targets (off when RHP is a subproject, so a newer compiler's new warning doesn't break the parent's build) |
| `RHP_INSTALL` | top-level only | install rules and the `rhp` CMake package (`find_package(rhp)`); see [getting started](getting-started.md#installed-package) |
| `RHP_BUILD_BENCH` | OFF | build `Tests/bench` (`rhp_bench`; needs `RHP_BUILD_TESTS`); see [performance](performance.md#measuring-your-own-case) and [benchmarks](../benchmarks.md) |
| `RHP_LUA_JUMP_YIELDS` | ON | coroutine yields jump (`_longjmp`) instead of throwing; errors still throw. With the MSVC ABI only on x64, and a Windows process running with a CET shadow stack still throws (checked once per process); ignored under ThreadSanitizer. See [performance](performance.md#coroutine-yields-rhp_lua_jump_yields) |
| `RHP_PCH` | ON for a top-level build, not cross-compiling, not clang-cl | one shared precompiled header of standard headers for RHP's libraries above `core` and one for its test suites (`cmake/RhpPch.cmake`) |
| `RHP_LTO` | OFF | link-time optimization of RHP's targets in `Release`, `RelWithDebInfo` and `MinSizeRel` (measured 10-35% on binding calls, variable and property reads, handle methods; under 5% on pure script work). LTO objects only link with the same compiler version, so an installed LTO package ties its consumers to that toolchain |
| `RHP_UNITY_BUILD` | OFF | compile RHP's libraries, tests and tools as unity files (16 sources each): about a third less wall time on clean builds (CI), slower edits |
| `RHP_WITH_TLS` | ON | TLS 1.3 for network endpoints |
| `RHP_TLS_OPENSSL` | AUTO | `AUTO` (use system OpenSSL ≥ 3.0 if found, desktop only), `ON` (required), `OFF` |
| `RHP_TLS_MBEDTLS` | ON | build the Mbed TLS backend (mobile, and the fallback) |
| `RHP_FUZZ` | OFF | build libFuzzer executables (Clang); otherwise they are ctest replay drivers |
| `RHP_SANITIZE` | empty | `address;undefined`, `address` (MSVC) or `thread` |

`CPM_SOURCE_CACHE` can be shared across builds. Dependency versions are pinned in one file, `cmake/Dependencies.cmake`: each git dependency's checkout must be the commit its tag named when it was pinned (a moved tag fails the configure), and CPM.cmake itself is checked against its SHA-256.

When RHP is the top-level project and the generator is Ninja, links share a job pool sized by the machine's memory (a full Debug build otherwise runs out of memory linking every test at once).

RHP's own targets also get these defaults, only when the including project hasn't set them: position-independent code; hidden symbol visibility (so a shared library that links RHP statically doesn't export, or clash on, RHP's, Lua's or Mbed TLS's symbols); a `d` postfix on Debug archives; and on MSVC, debug information inside the objects (`/Z7`), so an installed static library needs no PDB files. A parent's `CMAKE_CXX_STANDARD` below 23 stays its own: RHP's targets raise their users to C++23 through their compile features.

A disabled build can use a separate build directory:

```bash
cmake --preset windows-msvc -B build/off-msvc -DRHP_ENABLE=OFF
cmake --build build/off-msvc --config Debug
ctest --test-dir build/off-msvc -C Debug
```

Pass feature switches during configure, not as manual C++ macros in a consumer. Both TLS backends may be built: `auto_backend` picks OpenSSL when found, otherwise Mbed TLS. `RHP_WITH_TLS=OFF` skips both.

### Android and iOS

- Android: set `ANDROID_NDK_HOME`. `android-x64` builds tests for an emulator; `android-arm64` defaults to build only. For phone tests configure `cmake --preset android-arm64 -B build/android-arm64-tests -DRHP_BUILD_TESTS=ON`, build that directory with `--config Debug`, then run `python Tools/android/run_tests.py build/android-arm64-tests --serial DEVICE_SERIAL`. The runner executes the device suites and fuzz replays, not host-side compile-fail builds.
- iOS: `ios-device` (build) or `ios-sim` (tests through `Tools/ios/simctl_run.sh`). Mobile TLS uses Mbed TLS. Prefer [reverse mode](connecting.md#reverse-mode). Use `RHP_ENABLE=OFF` for builds that must not accept remote code. Check the relevant current distribution requirements before shipping an enabled build.
