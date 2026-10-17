# host — layer 5

`Rhp::host<Cfg>`: a program that accepts remote Lua. The template is a thin shell over an engine compiled once (`host.cpp`).

| Header | What |
|---|---|
| `host.hpp` | `Rhp::host<Cfg>`: `install<Lib>()`, `pump()`, `on<E>()` / `on_any()`, `on_blob()`, `set_enabled()`, `port()`, `gateway_port()`, `advertise()`, `discovery_status()`, `sessions()`, `identities()` |
| `detail/engine.hpp` | `host_options`, `blob_view` / `blob_fn`, the type-erased `setup` and the engine's free functions |
| `gateway.cpp`, `detail/gateway.hpp` (private, not installed) | the HTTP listener: routing, per-key logical sessions, the replay guard; the engine implements its `gateway_sink` |

```cpp
Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 7777),
                 *Rhp::security::keyring::from_file("keys.txt"),
                 *Rhp::security::trusted_signers::from_file("signers.pub")};
host.install<game_lib>();
auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
host.on_blob("configs", [](const Rhp::blob_view& b) -> Rhp::result<void> { return game::load_config(b.bytes); });
while (running) { host.pump(); game::update(); }
```

## What it does

- **Sessions:** the network thread authenticates every connection (`config<>::auth`), at most `limits.pending_handshakes` at a time, and hands requests to `pump()` through SPSC rings.
- **Identities:** one sandbox per key identity, created on its first session. When its last session ends everything it did is reverted and the sandbox closed — unless an admin pinned some of its modules (`pin`): those, and the modules they require, stay (with the calls running in them); the rest is reverted. `revert` / `unload` / `revert_to` refuse to touch pinned modules.
- **Roles and signatures:** each request's least role is checked (`wire::required_role`); `exec`, `load` and `reload` must carry a signature by a trusted signer (`config<>::signer`, Ed25519 by default) unless the session is observe. A signature that is present must verify.
- **Events:** `script_executed` for every request that runs code or changes state (refused ones too), sessions, auth failures, blobs, reverts — on the pump thread.
- **Blobs:** `on_blob(sink, fn, role)`; chunks are checked (sink, role, `limits.max_blob`) on the first one, buffered, and the whole blob goes to `fn` on the pump thread. The sink's result is the client's answer. One transfer per session; a new one replaces a transfer the client gave up on.
- **Reverse mode:** with a dial endpoint the host dials a listening client and redials (capped exponential backoff, full jitter) whenever that fails or the session ends; a lost link is redialed to resume the same session.
- **TLS:** non-loopback peers get TLS 1.3 (`config<>::tls<>`), `require_tls` everyone; `host_options::tls` holds the certificate (default: ephemeral self-signed). Events say `tls`.
- **Resume:** a lost link keeps the session for `limits.resume_ms`; the client's new connection takes it over (`session_resumed`), nothing is reverted or run twice. Shutting down closes every session with a reason first.
- **Kill switch:** `set_enabled(false)` closes new connections (reported as `auth_failed`) and answers every request `kDisabled`.
- **HTTP:** `host_options::gateway` opens a separate TCP/HTTPS listener ([networking guide](../../../Docs/guide/networking.md#http-listener)). Per-request proofs authenticate the same identities (optionally bound to the TLS channel) and every authenticated answer carries an `X-RHP-Proof`; each key gets one logical session that ends after `limits.gateway_idle_ms` with nothing in flight, measured on the host's clock. Connections share the native unauthenticated-handshake budget until their proof checks out. Audit records carry each request's own caller.
- **Discovery:** `advertise(options)` publishes through `Cfg::discovery_t`; `include_libs` separately publishes library names. Later provider errors: `discovery_status()`.

## Rules

- `install`, `on_blob`, `advertise`, `discovery_status` and `pump` belong to one thread (the pump thread). `on` / `on_any`, `set_enabled`, `port`, `gateway_port`, `sessions`, `identities` are thread-safe.
- Nothing from `session` or the engine leaks into `host.hpp`; config policies are type-erased into `setup`. Gateway types stay in the private `detail/gateway.hpp`.
- `RHP_ENABLE=0`: the host is inert (`install`, `on_blob`, `port` report `kDisabled`), no engine is built.
