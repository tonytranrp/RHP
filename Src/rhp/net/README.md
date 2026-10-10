# net — layer 3

Transports: ordered, reliable byte streams between a host and a client. Namespace `Rhp::net` (`Rhp::endpoint` is an alias of `Rhp::net::endpoint`).

| Header | What |
|---|---|
| `endpoint.hpp` | `endpoint::listen` / `endpoint::dial` (host, port, `insecure_lan`, `require_tls`), `tls_mode`, `is_loopback_host`; the `transport` concept (`network` marks transports the TLS address rules apply to); `transport_ops` |
| `io_context.hpp` | the reactor (Asio behind a wall): `post`, `poll`, `run_one_for`, `run(stop_token)`, one-shot `timer` |
| `link.hpp` | `link` (a connected stream: `start`, `send`, `close`, `peer`, and `loopback`, `encrypted`, `channel_binding` with defaults), `link_handler` (`on_bytes`, `on_closed`), `listener` (`port`) |
| `loopback/loopback.hpp` | in-process transport: named channels, no sockets, ends may live on different threads |
| `tcp/tcp.hpp` | TCP on Asio (`network = true`); a non-loopback address only with `insecure_lan` or when TLS is layered on top (hosts and clients do that) |
| `websocket/websocket.hpp` | RFC 6455 binary tunnel over TCP (`websocket/README.md`); codec in `websocket/detail/protocol.hpp` |
| `udp_reliable/udp_reliable.hpp` | ordered stream over UDP (`udp_reliable/README.md`); packet format in `udp_reliable/detail/packet.hpp` |
| `local/local.hpp` | local IPC: named pipes, AF_UNIX (`local/README.md`) |
| `discovery.hpp` | the `discovery` concept, `service_record`, `advertise_options`, `browse_options`, `no_discovery` |
| `mdns/mdns.hpp` | `mdns` (platform DNS-SD) and `mdns_wire` (own multicast responder): `mdns/README.md` |
| `detail/http.hpp`, `detail/http_connection.hpp` | HTTP/1.1 heads and one-request connections for the host's HTTP listener and the WebSocket upgrade |

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

- Asio stays in backend `.cpp` files and native test backends; `io_context::native_handle()` reaches the reactor. Public headers contain no Asio types.
- Everything about a link, listener or timer happens on its io_context's thread; other threads only `post`.
- `on_closed` is reported from a posted handler, never re-entrantly from `close()`, and never after the link is destroyed.
- No default port: every endpoint names one (0 = any free port for TCP listeners).
- A protocol's byte format lives in a sans-IO `detail/` codec (no sockets, no Asio) so it is unit-tested and fuzzed (`Tests/fuzz/network_fuzz.cpp`) on its own.
- OS-specific APIs/macros stay in backend `.cpp` files (IPC and DNS-SD); general behavior uses `Rhp::platform` traits.
