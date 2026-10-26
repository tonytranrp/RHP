# host — layer 5

`Rhp::host<Cfg>`: a program that accepts remote Lua. The template is a thin shell over an engine compiled once (`host.cpp`). Target `Rhp::host`; depends on `config`, `session`, `script`, `event` and `release`. Usage: [host and client guide](../../../Docs/guide/host-and-client.md).

| Header | What |
|---|---|
| `host.hpp` | `Rhp::host<Cfg>`: `install<Lib>()`, `pump()`, `on<E>()` / `on_any()`, `on_script_event()`, `on_blob()`, `serve(release::manager&)`, `set_enabled()` / `enabled()`, `port()`, `gateway_port()`, `advertise()`, `discovery_status()`, `sessions()`, `identities()` |
| `detail/engine.hpp` | `host_options` (idempotency cache, inbox capacity, `tls`, `gateway`, `http_require_binding`, `handler_errors`, `remote_events_per_pump`), `blob_view` / `blob_fn`, the type-erased `setup` and the engine's free functions |
| `detail/releases.hpp` | the bridge `serve` uses: answers the release ops with a `release::manager` (`releases.cpp`) |
| `gateway.cpp`, `detail/gateway.hpp` (private, not installed) | the HTTP listener: routing, per-key logical sessions, the replay guard; the engine implements its `gateway_sink` |

```cpp
Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 7777),
                 *Rhp::security::keyring::from_file("keys.txt"),
                 *Rhp::security::trusted_signers::from_file("signers.pub")};
(void)host.install<game_lib>();
auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
(void)host.on_blob("configs", [](const Rhp::blob_view& b) -> Rhp::result<void> { return game::load_config(b.bytes); });
while (running) { host.pump(); game::update(); }
```

## What it does

- **Sessions:** the network thread authenticates every connection (`config<>::auth`), at most `limits.pending_handshakes` at a time, and hands requests to `pump()` through SPSC rings.
- **Identities:** one sandbox per key identity, created on its first session. When its last session ends everything it did is reverted and the sandbox closed — unless an admin pinned some of its modules (`pin`): those, and the modules they require, stay (with the calls running in them); the rest is reverted. `revert` / `unload` / `revert_to` refuse to touch pinned modules. Asynchronous calls still running are handed on (`release_async`) so a late success is still taken back.
- **Roles and signatures:** each request's least role is checked (`wire::required_role`); `exec`, `load` and `reload` must carry a signature by a trusted signer (`config<>::signer`, Ed25519 by default) unless the session is observe. A signature that is present must verify.
- **Idempotent retries:** replies are kept per session by the client's idempotency key (`host_options::idempotency_cache` / `idempotency_bytes`), so a resent request runs once.
- **Cancels:** a client's cancel is relayed to the running request from the network thread; a cancel-enforcement timer re-applies recorded cancels to whatever runs inside `pump()`, and runs only while a cancel is recorded.
- **Events:** `script_executed` for every request that runs code or changes state (refused ones too), sessions, auth failures, blobs, reverts, `handler_failed`, `release_changed` — on the pump thread. `on_script_event` reports every identity's `rhp.publish` (each sandbox's script events are forwarded through `sandbox::on_script_event("*")`).
- **Subscriptions:** `kSubscribe` / `kUnsubscribe` (observe) name a C++ `lua_event` (the engine is itself an `event_listener`, attached while any session wants that event, detached when the last one unsubscribes or closes and when the engine stops) or the session's identity's script events. Deliveries are `kEvent` frames with `req` 0, at most `host_options::remote_events_per_pump` per session per pump; the next one reports how many were dropped. Subscriptions belong to the host session and survive a resume.
- **Handler failures:** `host_options::handler_errors` is every sandbox's default policy; a failure is logged, published as `handler_failed` and sent to the identity's sessions as an output line.
- **Blobs:** `on_blob(sink, fn, role)` (admin by default); chunks are checked (sink, role, `limits.max_blob`) on the first one, buffered, and the whole blob goes to `fn` on the pump thread. The sink's result is the client's answer. One transfer per session; a new one replaces a transfer the client gave up on.
- **Releases:** `serve(manager)` routes `release_apply` / `confirm` / `deactivate` (admin), `release_status` and `revoke` (observe) to a `release::manager` that `pump()` pumps; its changes are `release_changed` events. The manager must outlive the host.
- **Tools:** `tunables` / `tune`, `profile` and `debug` act on the caller's own identity sandbox. When the profiling session ends the profiler stops; when the last debugging session of an identity ends its breakpoints go and paused scripts run on. Debugger actions that change what a script does are audited.
- **Reverse mode:** with a dial endpoint the host dials a listening client and redials (capped exponential backoff, full jitter, `limits.backoff_min_ms` / `backoff_max_ms`) whenever that fails or the session ends; a lost link is redialed to resume the same session. A dialing host opens with a ping.
- **TLS:** non-loopback peers get TLS 1.3 (`config<>::tls<>`), `require_tls` everyone; `host_options::tls` holds the certificate (default: ephemeral self-signed). Events say `tls`.
- **Resume:** a lost link keeps the session for `limits.resume_ms`; the client's new connection takes it over (`session_resumed`), nothing is reverted or run twice. Shutting down sends every session a goodbye with a reason first.
- **Kill switch:** `set_enabled(false)` closes new connections (reported as `auth_failed`) and answers every request `kDisabled`.
- **HTTP:** `host_options::gateway` opens a separate TCP / HTTPS listener ([networking guide](../../../Docs/guide/networking.md)). Per-request proofs authenticate the same identities (optionally bound to the TLS channel; `http_require_binding` insists) and every authenticated answer carries an `X-RHP-Proof`; each key gets one logical session that ends after `limits.gateway_idle_ms` with nothing in flight, measured on the host's clock. Connections share the native unauthenticated-handshake budget until their proof checks out. Audit records carry each request's own caller.
- **Discovery:** `advertise(options)` publishes through `Cfg::discovery_t`; `include_libs` separately publishes library names. Later provider errors: `discovery_status()`.

## Rules

- `install`, `on_blob`, `serve`, `advertise` and `pump` belong to one thread (the pump thread; any one thread before the first `pump()`, `kInvalidArgument` from another after it); so does `discovery_status` with `io<zero_threads>`. `on` / `on_any` / `on_script_event`, `set_enabled` / `enabled`, `port`, `gateway_port`, `sessions`, `identities` are thread-safe.
- Lock order for C++ events: an event's own mutex, then the engine's `program_mutex_` (fires from other threads queue there); attach and detach never run under `program_mutex_`.
- Nothing from `session` or the engine leaks into `host.hpp`; config policies are type-erased into `setup`. Gateway types stay in the private `detail/gateway.hpp`.
- The destructor sends goodbyes, stops the network and reverts every identity, pinned modules included.
- `RHP_ENABLE=0`: the host is inert (every result-bearing call — `install`, `on_blob`, `serve`, `port`, `gateway_port`, `advertise`, `discovery_status` — reports `kDisabled`; `enabled()` is false; `sessions()` / `identities()` return 0), no engine is built.
