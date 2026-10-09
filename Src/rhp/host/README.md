# host — layer 5

`Rhp::host<Cfg>`: a program that accepts remote Lua. The template is a thin shell over an engine compiled once (`host.cpp`).

| Header | What |
|---|---|
| `host.hpp` | `Rhp::host<Cfg>`: `install<Lib>()`, `pump()`, `on<E>()` / `on_any()`, `on_blob()`, `set_enabled()`, `port()`, `sessions()`, `identities()` |
| `detail/engine.hpp` | `host_options`, `blob_view` / `blob_fn`, the type-erased `setup` and the engine's free functions |

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
- **Identities:** one sandbox per key identity, created on its first session. When its last session ends everything it did is reverted and the sandbox closed — unless an admin pinned some of its modules (`pin`): those, and the modules they require, stay; the rest is reverted.
- **Roles and signatures:** each request's least role is checked (`wire::required_role`); `exec`, `load` and `reload` must carry a signature by a trusted signer (`config<>::signer`, Ed25519 by default) unless the session is observe. A signature that is present must verify.
- **Events:** `script_executed` for every request that runs code or changes state (refused ones too), sessions, auth failures, blobs, reverts — on the pump thread.
- **Blobs:** `on_blob(sink, fn, role)`; chunks are checked (sink, role, `limits.max_blob`) on the first one, buffered, and the whole blob goes to `fn` on the pump thread. The sink's result is the client's answer.
- **Reverse mode:** with a dial endpoint the host dials a listening client and redials (capped exponential backoff, full jitter) whenever that fails or the session ends.
- **Kill switch:** `set_enabled(false)` closes new connections and answers every request `kDisabled`.

## Rules

- `install`, `on_blob` and `pump` belong to one thread (the pump thread). `on` / `on_any`, `set_enabled`, `sessions`, `identities` are thread-safe.
- Nothing from `net`, `session` or the engine leaks into `host.hpp`; config policies are type-erased into `setup`.
- `RHP_ENABLE=0`: the host is inert (`install`, `on_blob`, `port` report `kDisabled`), no engine is built.
