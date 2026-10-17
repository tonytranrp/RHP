# client — layer 5

`Rhp::client<Cfg>`: talks to a host. A thin template over an engine compiled once (`client.cpp`); never links Lua.

| Header | What |
|---|---|
| `client.hpp` | `Rhp::client<Cfg>`: blocking calls for every op, `async()`, `exec_async` / `exec_future`, `blob`, `pin` / `unpin`, `on` / `off` (host events), `cancel`, `port` (reverse mode), `poll` |
| `pending.hpp` | `Rhp::pending<T, Errors>`: one async result — `then`, `get`, `future`, `co_await`, `request()` |
| `fleet.hpp` | `Rhp::fleet<Cfg>` (`exec` / `load` / `call` start on every member, then collect one `host_result<T>` per host within a shared deadline), `Rhp::discover<Cfg>()`, the `broadcastable` concept |
| `detail/engine.hpp` | `client_options`, the type-erased `setup`, the engine's free functions |
| `detail/fleet_engine.hpp` | `fleet_options`, the fleet engine's `setup` and free functions (`fleet.cpp`) |

```cpp
auto id = *Rhp::security::identity_file::load("dev.rhpid");
Rhp::client<> c{Rhp::endpoint::dial("127.0.0.1", 7777), id.credential(), *id.signer_key()};
auto g = c.exec<double>("return game.gravity");              // blocking: Rhp::result<double>
auto t = co_await c.async().exec<int>("return game.tick");   // any C++20 coroutine
c.async().load("low_grav", src).then([](Rhp::result<Rhp::module_id> m) { /* network thread */ });
c.blob("configs", bytes, "game.ini");
```

## Rules

- Every script (`exec`, `load`, `reload`) is signed with the client's signing key; without one, only an observe session (or an `unsigned_scripts` host) runs it.
- Blocking calls may come from any thread with `io<owned_io_thread>`. Async results, `on_output` and `on_emit` run on the network thread — keep them short and never block on the same client there. With `io<zero_threads>` they run inside `poll()`, a blocking call, or `pending::get()`.
- An async call made before the session is ready waits for it; one that times out or is cancelled meanwhile is dropped, never sent later. When the session ends every call in flight fails (`kTransport`). A closed client answers new calls at once with why it closed.
- Reverse mode (`Rhp::endpoint::listen`): the client listens and serves one host at a time; when that host's session ends the client keeps listening and the next call waits (`connect_timeout`) for a host to dial in. A connection that never authenticates fails nothing.
- TLS: dialing a non-loopback address (or with `require_tls`) uses TLS; `client_options::tls.ca_pem` + `server_name` check the host's certificate. `info().tls` says whether the connection is encrypted.
- Resume: a dialing client whose link drops redials (backoff) and resumes the same session within `limits.resume_ms`; calls in flight are resent and run exactly once (`info().resumes` counts). A listening client waits for its host to dial back.
- Blobs go in chunks (`client_options::blob_chunk`, `blob_window` in flight); the last chunk's answer is the sink's verdict.
- `on(name, fn)`: the first callback for a name sends `kSubscribe` (blocking), the last `off` sends `kUnsubscribe`. `kEvent` deliveries call every matching callback (its name, or `*`) on the network thread, outside the client's lock. A reverse-mode client subscribes again whenever a new host session becomes ready.
- `RHP_ENABLE=0`: every call reports `kDisabled`.
- `info().closed` distinguishes terminal failure from a resumable detach. Fleet replaces terminal members and retains live sessions between broadcasts.
- Fleet: a thin template over one engine compiled in `fleet.cpp`. Its members are client engines on one shared `net::io_context` (`setup::shared_io`) run by one I/O thread for the whole fleet (none with `io<zero_threads>`). An engine on a shared reactor never runs or owns it, drops work queued for it once destroyed (a liveness token checked by its posts and dial completions), and is destroyed on the reactor's thread (or after it stopped). The public `client<Cfg>` never uses `shared_io`.
