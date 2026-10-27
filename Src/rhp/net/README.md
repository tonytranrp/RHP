# net — layer 3

Transports (ordered, reliable byte streams between a host and a client) and discovery. Namespace `Rhp::net` (`Rhp::endpoint` is an alias of `Rhp::net::endpoint`). Target `Rhp::net`; depends on `core` and `platform`, privately on Asio (build tree only) and the OS's DNS-SD / socket libraries. Usage: [networking guide](../../../Docs/guide/networking.md).

| Header | What |
|---|---|
| `address.hpp` | `ip_address`: an IPv4 or IPv6 address (IPv4 kept IPv4-mapped), `parse` (strict: host names such as `cafe1` are not addresses), `is_v4`, `is_loopback` / `is_private` / `is_link_local` / `is_local` (what `insecure_lan` may talk plaintext to; CGNAT is not local), `source` (an IPv4 address or IPv6 /64, for per-source limits); constexpr, no I/O |
| `endpoint.hpp` | `endpoint::listen` / `endpoint::dial` (host, port, and the tags `insecure_lan` (plaintext over a network transport, with local peers only: see the session module's TLS policy) / `require_tls`), `reversed()`, `with_port()`, `tls_mode`, `is_loopback_host`; the `transport` concept (a transport must declare `network`), `transport_ops` / `transport_ops_for<T>`, `accept_fn` / `connect_fn` |
| `io_context.hpp` | the reactor (Asio behind a wall): `post`, `shared_poster()` (posts from threads that may outlive it), `poll`, `run_one_for`, `run(stop_token)`, `running_in_this_thread`, `native_handle`, one-shot `timer` |
| `link.hpp` | `link` (a connected stream: `start`, `send`, `close`, `peer`; `loopback`, `encrypted`, `channel_binding`, `address` with defaults), `link_decorator` (forwards all of them), `link_handler` (`on_bytes`, `on_closed`), `listener` (`port`) |
| `loopback/loopback.hpp` | `loopback`: in-process transport, named channels (host + port name the channel), no sockets; ends may live on different threads (`network = false`) |
| `tcp/tcp.hpp` | `tcp` on Asio (`network = true`); a non-loopback address only with `insecure_lan` or when TLS is layered on top (hosts and clients do that) |
| `websocket/websocket.hpp` | `websocket`: RFC 6455 binary tunnel over TCP ([websocket/README.md](websocket/README.md)) |
| `udp_reliable/udp_reliable.hpp` | `udp_reliable`: an ordered stream over UDP ([udp_reliable/README.md](udp_reliable/README.md)) |
| `local/local.hpp` | `local_ipc`: named pipes, AF_UNIX sockets ([local/README.md](local/README.md)) |
| `discovery.hpp` | the `discovery` concept, `service_record`, `advertise_options`, `browse_options`, `advertisement`, `discovery_browser`, `discovery_ops`, `no_discovery`, `dns_sd_service` |
| `mdns/mdns.hpp` | `mdns` (platform DNS-SD) and `mdns_wire` (own multicast responder and querier): [mdns/README.md](mdns/README.md) |
| `detail/http.hpp`, `detail/http_connection.hpp` | HTTP/1.1 heads and one-request connections for the host's HTTP listener and the WebSocket upgrade |

```cpp
using cfg = Rhp::config<>::transport<Rhp::net::udp_reliable>;          // or tcp (default), websocket, local_ipc, loopback
Rhp::host<cfg> host{Rhp::endpoint::listen("0.0.0.0", 7777), keys, signers};   // non-loopback: TLS
Rhp::client<cfg> lan{Rhp::endpoint::dial("192.168.1.20", 7777, Rhp::net::insecure_lan), id, key}; // plaintext, trusted LAN only
```

## Writing a transport

```cpp
struct my_transport {
    static constexpr std::string_view name = "my";
    static constexpr bool network = true; // reaches other machines: TLS rules apply (false: in-process, IPC, cable)
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};
using cfg = Rhp::config<>::transport<my_transport>;   // checked by Rhp::net::transport here
```

`network` is required and must be a constant: a transport without it doesn't compile, so none is silently treated as local. Links you hand out implement `Rhp::net::link`; a link that wraps another derives from `link_decorator`, which forwards `loopback()`, `encrypted()`, `channel_binding()` and `address()` (the session's security depends on them). A transport that reaches other machines reports its peer's IP address in `address()`: hosts and listening clients cap unauthenticated connections per source by it (without one, its connections only count toward the total). Use `io_context::post` to get back onto the context's thread. A complete one: [Examples/custom_transport](../../../Examples/custom_transport).

## Rules

- Asio stays in backend `.cpp` files, `detail/asio_support.hpp` (private: not in the installed header set, included only by those `.cpp` files; the shared stream link, `context_of`, `is_loopback`, the address text and the plaintext address rule) and native test backends; `io_context::native_handle()` reaches the reactor. Public headers contain no Asio types. With `RHP_ENABLE=OFF` the headers stay (configs still name transports) but nothing is compiled and Asio is not fetched.
- Everything about a link, listener or timer happens on its io_context's thread; other threads only `post`. Code that may outlive the context (native callbacks, cross-thread transports) posts through `shared_poster()`, which refuses once the context shuts down.
- `on_closed` is reported from a posted handler, never re-entrantly from `close()`, and never after the link is destroyed.
- No default port: every endpoint names one (0 = any free port for TCP and UDP listeners; `local_ipc` requires 0).
- TCP and IPC links send the frames queued behind a write in flight in one gathered write (up to 16 buffers). Keep `send()` cheap: it only queues.
- A protocol's byte format lives in a sans-IO `detail/` codec (no sockets, no I/O; the DNS codec's implementation uses Asio's IP address type to format and parse addresses) so it is unit-tested and fuzzed (`Tests/fuzz/network_fuzz.cpp`) on its own.
- OS-specific APIs and macros stay in backend `.cpp` files (IPC and DNS-SD); general behavior uses `Rhp::platform`.
- Discovery records are untrusted hints: they never carry keys, grant nothing and never enable plaintext.
