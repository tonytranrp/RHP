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
    ::logger<Rhp::core::stderr_logger>;                // Rhp::core::logger

// Use my_cfg as Rhp::host<my_cfg> / Rhp::client<my_cfg>'s template argument.
```

Inside your own templates (a dependent context) write `Cfg::template transport<X>`.

| Slot | Default | Alternatives and what they do |
|---|---|---|
| `transport` | `net::tcp` | `net::loopback` (in-process, for tests and embedding), or your own ([guide](connecting.md#your-own-transport)) |
| `tls` | `tls::auto_backend` | `tls::openssl`, `tls::mbedtls`, or `tls::none` (no TLS; non-loopback endpoints then need `insecure_lan`) |
| `codec` | `wire::msgpack` | any `wire::codec` (RHP's own MessagePack codec by default) |
| `auth` | `security::psk_keyring` | any `security::authenticator` (mutual PSK challenge-response by default) |
| `signer` | `security::ed25519` | `security::unsigned_scripts`: the explicit, typed opt-out of script signing |
| `executor` | `exec::pumped` | Lua runs on the thread that calls `pump()` (the only executor today) |
| `io` | `exec::owned_io_thread` | `exec::zero_threads`: no threads; `pump()` and blocking client calls poll the network |
| `limits` | `Rhp::limits{}` | see below |
| `errors` | `errors::expected` | `errors::throwing` |
| `clock` | `exec::steady_clock` | your game clock or a manual clock, for `rhp.sleep` / `rhp.timer` and deterministic tests |
| `logger` | `core::stderr_logger` | `core::null_logger`, or any type with `enabled(level)` and `write(level, msg)` (spdlog, logcat, os_log, your engine log) |

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
| `gateway_idle_ms` | 5 min | reserved for the Stage 6 HTTP gateway |
| `cancel_check_instructions` | 1000 | count-hook interval for cancellation and budgets; 0 uses the default interval |

Instruction, memory and execution-time limits default to unlimited; slicing defaults to off. Set budgets on the **host** that executes code. Instruction/time checks run at hook boundaries and cannot preempt C++ bindings. A host pump can dispatch several operations and pump several identity sandboxes, so `slice_us` is not a hard bound on the whole application frame.

`executor<pumped>` is the only implemented script execution model; accepting a custom marker does not install a scheduler. `clock` affects script sleep/timer time on a host or local sandbox, not protocol deadlines. The client logger/clock slots do not currently supply engine callbacks. `engine<>` and `discovery<>` are not available slots.

## Option structs

Passed to the constructors at run time: [`Rhp::host_options`](host-and-client.md#rhphost_options), [`Rhp::client_options`](host-and-client.md#rhpclient_options), and `Rhp::script::sandbox_options` for the standalone sandbox:

| `sandbox_options` field | What |
|---|---|
| `caller_role` | role of the identity (local default: patch) |
| `limits` | as above |
| `memory` | a `std::pmr::memory_resource*` for every Lua allocation (default resource when null) |
| `output` / `on_output` | receive `print()` lines (with request and module for `on_output`) |
| `on_emit` | receive `rhp.emit` values |
| `on_result` | receive the final result of requests that suspended |
| `clock` | script time for `rhp.sleep` / `rhp.timer` |
| `identity` | caller-supplied label for this local identity |

The supplied memory resource must outlive the sandbox. It covers Lua allocations, not every C++ container or effect allocation. The host does not expose a memory-resource constructor option. `on_result` runs for requests that suspended at least once; synchronous outcomes are returned by the operation itself.

## CMake options

| Option | Default | What |
|---|---|---|
| `RHP_ENABLE` | ON | OFF compiles hosts to inert stubs (`kDisabled`), patch points to direct calls, and skips Lua, Asio and Monocypher entirely |
| `RHP_BUILD_TESTS` | top-level only | build `Tests/` |
| `RHP_BUILD_EXAMPLES` | top-level only | build `Examples/` |
| `RHP_BUILD_TOOLS` | top-level only | build `Tools/` (`rhp-cli`; needs `RHP_ENABLE=ON`) |
| `RHP_WARNINGS_AS_ERRORS` | ON | warnings are errors in RHP's own targets |
| `RHP_WITH_TLS` | ON | TLS 1.3 for network endpoints |
| `RHP_TLS_OPENSSL` | AUTO | `AUTO` (use system OpenSSL ≥ 3.0 if found, desktop only), `ON` (required), `OFF` |
| `RHP_TLS_MBEDTLS` | ON | build the Mbed TLS backend (mobile, and the fallback) |
| `RHP_FUZZ` | OFF | build libFuzzer executables (Clang); otherwise they are ctest replay drivers |
| `RHP_SANITIZE` | empty | `address;undefined`, `address` (MSVC) or `thread` |

`CPM_SOURCE_CACHE` can be shared across builds. Dependency versions are pinned in one file, `cmake/Dependencies.cmake`.

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
