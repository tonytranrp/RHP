# client — layer 5

`Rhp::client<Cfg>`: talks to a host. A thin template over an engine compiled once (`client.cpp`); never links Lua.

| Header | What |
|---|---|
| `client.hpp` | `Rhp::client<Cfg>`: blocking calls for every op, `async()`, `exec_async` / `exec_future`, `blob`, `pin` / `unpin`, `cancel`, `port` (reverse mode), `poll` |
| `pending.hpp` | `Rhp::pending<T, Errors>`: one async result — `then`, `get`, `future`, `co_await`, `request()` |
| `detail/engine.hpp` | `client_options`, the type-erased `setup`, the engine's free functions |

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
- Blobs go in chunks (`client_options::blob_chunk`, `blob_window` in flight); the last chunk's answer is the sink's verdict.
- `RHP_ENABLE=0`: every call reports `kDisabled`.
