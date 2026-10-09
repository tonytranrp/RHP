# net — layer 3

Transports: ordered, reliable byte streams between a host and a client. Namespace `Rhp::net` (`Rhp::endpoint` is an alias of `Rhp::net::endpoint`).

| Header | What |
|---|---|
| `endpoint.hpp` | `endpoint::listen` / `endpoint::dial` (host, port, `insecure_lan`); the `transport` concept; `transport_ops` (a transport as function pointers) |
| `io_context.hpp` | the reactor (Asio behind a wall): `post`, `poll`, `run_one_for`, `run(stop_token)`, one-shot `timer` |
| `link.hpp` | `link` (a connected stream: `start`, `send`, `close`, `peer`), `link_handler` (`on_bytes`, `on_closed`), `listener` (`port`) |
| `loopback/loopback.hpp` | in-process transport: named channels, no sockets, ends may live on different threads |
| `tcp/tcp.hpp` | TCP on Asio; loopback addresses only unless `Rhp::net::insecure_lan` (TLS is Stage 5) |

## Writing a transport

```cpp
struct my_transport {
    static constexpr std::string_view name = "my";
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};
using cfg = Rhp::config<>::transport<my_transport>;   // checked by Rhp::net::transport here
```

Links you hand out implement `Rhp::net::link`; use `io_context::post` to get back onto the context's thread.

## Rules

- `asio.hpp` only in `io_context.cpp` and `tcp/tcp.cpp`; `io_context::native_handle()` is how an Asio-based transport reaches the `asio::io_context`.
- Everything about a link, listener or timer happens on its io_context's thread; other threads only `post`.
- `on_closed` is reported from a posted handler, never re-entrantly from `close()`, and never after the link is destroyed.
- No default port: every endpoint names one (0 = any free port for TCP listeners).
- No OS `#ifdef`s: platform differences go through `Rhp::platform` (e.g. `SO_REUSEADDR` only off Windows).
