# RHP user guide

How to use RHP, what it supports, and how to configure and connect it. For *why* it is built this way, see [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and [`../decisions/`](../decisions/).

| Guide | Read it to learn |
|---|---|
| [Getting started](getting-started.md) | add RHP to a CMake project, build, run the first host and client |
| [Exposing C++ to Lua](exposing-cpp.md) | `Rhp::lib`, `undo`, patch points, events, custom types |
| [Writing scripts](writing-scripts.md) | the `rhp` Lua API, modules, reload, undo, scheduling |
| [Host and client](host-and-client.md) | the C++ API of `Rhp::host` / `Rhp::client`, async calls, blobs, audit |
| [Connecting](connecting.md) | endpoints, TLS, reverse mode, reconnect, `rhp-cli`, custom transports |
| [Configuration](configuration.md) | `Rhp::config<>` slots, `Rhp::limits`, options, CMake switches |
| [Security](security.md) | keys, roles, signing, setting up a host safely |
| [Reference](reference.md) | error codes, events, Lua sandbox contents |
| [Status and TODO](../TODO.md) | what is built, what is next, known limits |

## What RHP is

A running C++ program (the **host**) accepts Lua scripts from a **client** (your editor tooling, `rhp-cli`, a test harness) and runs them against an API **you** declare in C++. RHP can undo its journaled variable writes, patches, timers, subscriptions and functions with supplied inverses. Untagged functions are assumed pure; irreversible calls and arbitrary admin standard-library side effects are not automatically reversible. Non-admin scripts reach the bindings and sandbox libraries the host provides; an admin identity is fully trusted.

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

## What is available today (Stages 0–5)

| Area | Supported |
|---|---|
| Scripting | Lua 5.5 sandbox per identity; modules with their own `_ENV`; `exec`, `load`, `call`, `reload`, `rollback`, `checkpoint` / `revert_to`, `revert`, `unload`, `pin` / `unpin`, `revert_all`; `require`; coroutine scheduler (`rhp.wait`, `rhp.next_frame`, `rhp.sleep`, `rhp.timer`); `on_save` / `on_restore` state hand-over |
| C++ binding | `Rhp::lib<>` with `fn`, `var`, `ro`, `handle`, `sub`; `undo<>`, `irreversible`, `requires_role<>`; `Rhp::patch_point<>`; `Rhp::lua_event<>`; custom types through `Rhp::convert<T>`; LuaLS stub generation |
| Transports | in-process `net::loopback`, `net::tcp` (IPv4 and IPv6), your own through the `net::transport` concept |
| Directions | normal (client dials host) and **reverse** (host dials a listening client: phones, NAT) |
| Security | pre-shared-key mutual authentication, 3 roles, Ed25519 script signing, TLS 1.3 (OpenSSL or Mbed TLS), TLS channel binding, per-frame MAC |
| Reliability | CRC32C, seq / ack / nack / resend, heartbeat, **resume** after a lost link with exactly-once calls |
| Client | blocking, `then` callbacks, `std::future`, `co_await`; cancel; blobs; output and `rhp.emit` callbacks |
| Operations | audit events and JSON-lines log, runtime kill switch (`set_enabled`), compile-time kill switch (`RHP_ENABLE=OFF`) |
| Tooling | `rhp-cli` (REPL, `run`, `exec`, `stubs`, `blob`, `watch`, `keygen`, `pubkey`, `sign`), `headless_server`, five examples |
| Platforms | target presets for Windows, Linux, macOS, iOS and Android; verified builds and remaining platform checks are recorded in [platform decisions](../decisions/platforms-and-toolchains.md) |

Start with the [runnable CLI walkthrough](getting-started.md#first-run-host-plus-rhp-cli), then the [complete local sandbox example](getting-started.md#without-any-network). The guide describes the Stage 5 source at `8ffc954`; diagrams and older examples in the architecture document also contain roadmap material. Reproduced implementation defects remain open in [Status and TODO](../TODO.md#confirmed-issues-at-the-current-commit).

**Not built yet (Stage 6):** WebSocket, UDP-reliable and local-IPC transports, the HTTP REST gateway, mDNS discovery and `Rhp::fleet`. Nothing in this guide depends on them.
