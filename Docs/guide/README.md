# RHP user guide

How to use RHP, what it supports, and how to configure and connect it. For *why* it is built this way, see [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and [`../decisions/`](../decisions/).

| Guide | Read it to learn |
|---|---|
| [Getting started](getting-started.md) | add RHP to a CMake project, build, run the first host and client |
| [Exposing C++ to Lua](exposing-cpp.md) | `Rhp::lib`, `undo`, patch points, events, custom types |
| [Writing scripts](writing-scripts.md) | the `rhp` Lua API, modules, reload, undo, scheduling |
| [Scheduling and events](scheduling-and-events.md) | a walkthrough: per-frame work, background tasks, script events, C++ and tool listeners, handler failures |
| [Host and client](host-and-client.md) | the C++ API of `Rhp::host` / `Rhp::client`, async calls, blobs, audit |
| [Connecting](connecting.md) | endpoints, TLS, reverse mode, reconnect, `rhp-cli`, custom transports |
| [Python client](../../clients/python/README.md) | talk to a host from Python: `pip install ./clients/python`, signed scripts, events, resume |
| [Networking and fleet](networking.md) | WebSocket, UDP, IPC, HTTP, DNS-SD and collect-all execution |
| [Releases](releases.md) | signed releases a host keeps across restarts, health-checked candidates, revocation, staged rollout |
| [Testing scripts](testing-scripts.md) | test the Lua written against your API offline: busted / Jest style, spies and fakes, a fake clock, exact costs, coverage, snapshots, property tests, fuzzing, CI reports, VS Code |
| [Tools](tools.md) | tunables, the sampling profiler and the debugger (rhp-cli, DAP for editors, C++) |
| [Configuration](configuration.md) | `Rhp::config<>` slots, `Rhp::limits`, options, CMake switches |
| [Performance](performance.md) | what RHP costs, `cancel_checks`, Release and `RHP_LTO`, yields, signing cache, network batching, build speed |
| [Security](security.md) | keys, roles, signing, setting up a host safely |
| [Reference](reference.md) | error codes, host events, operations, wire protocol, Lua sandbox contents, threads |
| [Limitations](limitations.md) | what RHP doesn't do, or does only partly |
| [Status and TODO](../TODO.md) | what is built, what is next, recorded validation |

## What RHP is

A running C++ program (the **host**) accepts Lua scripts from a **client** (your editor tooling, `rhp-cli`, a test harness) and runs them against an API **you** declare in C++. RHP can undo its journaled variable writes, patches, timers, frame callbacks, subscriptions, tasks and functions with supplied inverses. Untagged functions are assumed pure; irreversible calls and arbitrary admin standard-library side effects are not automatically reversible. Non-admin scripts reach the bindings and sandbox libraries the host provides; an admin identity is fully trusted.

```text
 rhp-cli / your tool                       your game or app
┌────────────────────┐   authenticated   ┌─────────────────────────────┐
│ Rhp::client        │ ───── TLS ──────▶ │ Rhp::host                   │
│  signs each script │   signed Lua      │  network thread: frames,    │
│  with Ed25519      │                   │  acks, resume               │
└────────────────────┘                   │  host.pump() thread: runs   │
                                         │  Lua in one sandbox per key │
                                         │  → Rhp::lib / patch_point   │
                                         └─────────────────────────────┘
```

## What is available today (Stages 0–12)

| Area | Supported |
|---|---|
| Scripting | Lua 5.5 sandbox per identity; modules with their own `_ENV`; `exec`, `load`, `call`, `reload`, `rollback`, `checkpoint` / `revert_to`, `revert`, `unload`, `pin` / `unpin`, `revert_all`; `require`; coroutine scheduler (`rhp.wait`, `rhp.next_frame`, `rhp.sleep`, `rhp.timer`); frame callbacks and timer control (`rhp.every_frame(s)`, `rhp.after`, `rhp.every`, pause / resume / reschedule); background tasks (`rhp.spawn`); script events (`rhp.publish`, `rhp.once`, `rhp.wait_event`); a failing handler is reported and undoes only its own call; `on_save` / `on_restore` state hand-over; scripts wait for asynchronous bindings without blocking the game |
| C++ binding | `Rhp::lib<>` with `fn`, `var`, `ro`, `handle`, `sub`, and `method` / `property` on handles; asynchronous bindings returning `Rhp::async<T>`; `undo<>`, `irreversible`, `requires_role<>`; `Rhp::patch_point<>`; `Rhp::lua_event<>`; custom types through `Rhp::convert<T>`; LuaLS stub generation |
| Transports | in-process loopback, TCP, WebSocket binary tunnel, reliable UDP, local IPC; custom transports through `net::transport` |
| Network tooling | authenticated HTTP/1.1 gateway with signed answers and optional channel binding; opt-in DNS-SD discovery; `Rhp::fleet<Cfg>` `exec`/`load`/`call` broadcasts with one outcome per host, on one shared network thread |
| Directions | normal (client dials host) and **reverse** (host dials a listening client: phones, NAT) |
| Security | pre-shared-key mutual authentication, 3 roles, Ed25519 script signing, TLS 1.3 (OpenSSL or Mbed TLS), TLS channel binding, per-frame MAC |
| Reliability | CRC32C, seq / ack / nack / resend, heartbeat, **resume** after a lost link with exactly-once calls |
| Client | blocking, `then` callbacks, `std::future`, `co_await`; cancel; blobs; output and `rhp.emit` callbacks; `client.on` subscriptions to host events |
| Releases | signed release manifests (`Rhp::release`): channels, anti-rollback floors, validity windows, scope (app / build / platform), health-watched candidates, persistence across restarts with boot-attempt quarantine, revocation lists, staged fleet rollout with rollback |
| Tools | tunables (`Rhp::range` / `step` / `unit` / `doc` tags on lib variables, `tune` journaled), a sampling profiler with folded-stack output, a debugger (breakpoints, pause, step, stacks, variables) that pauses one script while the program runs, `rhp-cli dap` for editors |
| Testing scripts | `Rhp::test`: Lua specs run offline in real sandboxes (your libs, or `fake<L>` / fakes from an API description); `describe` / `it`, luassert-compatible `assert`, Jest-style `expect`, spies / stubs / mocks; a fake clock; exact instruction and memory costs, budgets, benches; leak checks; snapshots, property tests, fuzzing; text / TAP / JUnit / JSON / GitHub reports, LCOV / Cobertura coverage; `Rhp::test::main`, `rhp-cli test`, `rhp_add_lua_tests`, a VS Code extension |
| Operations | audit events and JSON-lines log (`handler_failed` included), `host.on_script_event`, runtime kill switch (`set_enabled`), compile-time kill switch (`RHP_ENABLE=OFF`) |
| Tooling | the pure-Python client `rhp_client` (`clients/python`); `rhp-cli` (REPL, `run`, `exec`, `stubs`, `blob`, `watch`, `events`, `keygen`, `pubkey`, `sign`, `discover`, `fleet`, `release`, `revoke`, `rollout`, `tune`, `profile`, `dap`, `test`), `headless_server`, six examples; the VS Code extension for Lua tests (`clients/vscode`) |
| Packaging | `find_package(rhp)` from an installed prefix (Debug and Release side by side), `add_subdirectory` or CPM; a generated `<rhp/build_config.hpp>`; dependency pins checked by commit and hash; third-party licenses installed |
| Performance | `rhp_bench` benchmarks every hot path against raw Lua ([benchmarks](../benchmarks.md)); the cancel hook counted down inline and armed only where a cancel can come from (`limits.cancel_checks`); coroutine yields as jumps; cached script signatures; gathered TCP / IPC writes and delayed acks; opt-in `RHP_LTO`; shared precompiled headers and unity builds ([performance](performance.md)) |
| Platforms | target presets for Windows, Linux, macOS, iOS and Android; verified builds and remaining platform checks are recorded in [platform decisions](../decisions/platforms-and-toolchains.md) |

Start with the [runnable CLI walkthrough](getting-started.md#first-run-host-plus-rhp-cli), then the [complete local sandbox example](getting-started.md#without-any-network). The guide describes the current Stage 12 API; historical architecture decisions retain their stage context. Open items and platform checks are in [Status and TODO](../TODO.md).
