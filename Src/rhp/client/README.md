# client — layer 5

`Rhp::client<Cfg>`: talks to a host. `Rhp::fleet<Cfg>`: talks to many. Thin templates over engines compiled once (`client.cpp`, `fleet.cpp`, `rollout.cpp`); never links Lua. Target `Rhp::client`; depends on `config` and `session` only (not `release` or `test`: rollout reads release envelopes itself). Usage: [connecting](../../../Docs/guide/connecting.md), [networking and fleet](../../../Docs/guide/networking.md), [releases](../../../Docs/guide/releases.md).

| Header | What |
|---|---|
| `client.hpp` | `Rhp::client<Cfg>`: `connect()`; blocking calls for every op (`exec`, `load`, `call`, `reload`, `rollback`, `revert`, `unload`, `checkpoint`, `revert_to`, `revert_all`, `pin` / `unpin`, `list`, `status`, `describe`, `blob`, `release_apply` / `release_confirm` / `release_deactivate` / `release_status` / `revoke`, `tunables` / `tune`, `profile`, `debug`); `async()` (a `pending` for the script ops), `exec_async` / `exec_future`; `on` / `off` (host events); `cancel()` / `cancel(request)`; `port` (reverse mode); `poll`; `info()` / `connected()` |
| `pending.hpp` | `Rhp::pending<T, Errors>`: one async result: `then`, `get`, `future`, `co_await`, `ready`, `request()` |
| `fleet.hpp` | `Rhp::fleet<Cfg>`: `discover` / `add` members, `exec` / `load` / `call` start on every member and collect one `host_result<T>` per host within a shared deadline, `rollout`, `release_status`; `Rhp::discover<Cfg>()`; the `broadcastable` concept |
| `rollout.hpp` | `rollout_plan` (canaries, cumulative `rollout_stage`s with an observe time, `max_failures`, `rollback_on_failure`, `on_progress`), `rollout_host`, `rollout_report` |
| `detail/engine.hpp` | `client_options` (`connect_timeout`, `request_timeout`, `on_output`, `on_emit`, `blob_chunk`, `blob_window`, `tls`), `session_info` (what `info()` returns), `remote_event` (one `on` delivery; views valid during the callback), the type-erased `setup`, the engine's free functions |
| `detail/fleet_engine.hpp` | `fleet_options` (`client`, `timeout`, `tls`, `insecure_lan`), the fleet engine's `setup` and free functions |

```cpp
auto id = *Rhp::security::identity_file::load("dev.rhpid");
Rhp::client<> c{Rhp::endpoint::dial("127.0.0.1", 7777), id.credential(), *id.signer_key()};
auto g = c.exec<double>("return game.gravity");              // blocking: Rhp::result<double>
auto t = co_await c.async().exec<int>("return game.tick");   // any C++20 coroutine
c.async().load("low_grav", src).then([](Rhp::result<Rhp::module_id> m) { /* network thread */ });
(void)c.blob("configs", bytes, "game.ini");
auto cb = c.on("game.round_over", [](const Rhp::remote_event& e) { /* e.name, e.args; network thread */ });
(void)c.off(*cb);

Rhp::fleet<> all{id.credential(), *id.signer_key()};
(void)all.discover();                                         // DNS-SD: hosts that advertise
for (const auto& r : all.exec<int>("return game.players")) { /* r.host, r.outcome */ }
```

## Rules

- Every script (`exec`, `load`, `reload`) is signed with the client's signing key; without one, only an observe session (or an `unsigned_scripts` host) runs it.
- Blocking calls may come from any thread with `io<owned_io_thread>`. Async results, coroutine resumptions, `on_output`, `on_emit` and event callbacks run on the network thread: keep them short and never block on the same client there. With `io<zero_threads>` they run inside `poll()`, a blocking call, or `pending::get()`.
- An async call made before the session is ready waits for it; one that times out or is cancelled meanwhile is dropped, never sent later. When the session ends every call in flight fails (`kTransport`). A closed client answers new calls at once with why it closed. `cancel(0)` does nothing; `cancel()` stops every request in flight.
- A `pending` is move-only (one consumer); `request()` stays valid after the result is taken. Don't destroy a suspended coroutine while its call may complete on the network thread.
- Reverse mode (`Rhp::endpoint::listen`): the client listens and serves one host at a time; when that host's session ends the client keeps listening and the next call waits (`connect_timeout`) for a host to dial in. A connection that never authenticates fails nothing.
- TLS: dialing a non-loopback address over a network transport (or with `require_tls`) uses TLS; `client_options::tls.ca_pem` + `server_name` check the host's certificate (without them the key handshake is bound to the TLS channel instead). `info().tls` says whether the connection is encrypted.
- Resume: a dialing client whose link drops redials (backoff) and resumes the same session within `limits.resume_ms`; calls in flight are resent and run exactly once (`info().resumes` counts). A listening client waits for its host to dial back. `info().closed` tells a terminal failure from a resumable detach.
- Blobs go in chunks (`client_options::blob_chunk`, `blob_window` in flight); the last chunk's answer is the sink's verdict.
- `on(name, fn)`: the first callback for a name sends `kSubscribe` (blocking), the last `off` sends `kUnsubscribe`. `kEvent` deliveries call every matching callback (its name, or `*`) on the network thread, outside the client's lock. A reverse-mode client subscribes again whenever a new host session becomes ready.
- Fleet: its members are client engines on one shared `net::io_context` (`setup::shared_io`) run by one I/O thread for the whole fleet (none with `io<zero_threads>`). An engine on a shared reactor never runs or owns it, drops work queued for it once destroyed (a liveness token checked by its posts and dial completions), and is destroyed on the reactor's thread (or after it stopped). The public `client<Cfg>` never uses `shared_io`. Fleet replaces terminal members and keeps live sessions between broadcasts; `insecure_lan` is the caller's opt-in, never taken from discovery records.
- Rollout: canaries first, then cumulative fractions; each stage's hosts are watched (`observe`, polled every `poll`) before they are confirmed. More than `max_failures` failures stop it and, with `rollback_on_failure`, deactivate the release where it went.
- `RHP_ENABLE=0`: every call reports `kDisabled`.
