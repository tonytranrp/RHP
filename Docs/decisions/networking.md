# Networking backend and transports

**Decision:** standalone Asio 1.38.x behind the `Rhp::net::transport` concept. Transports: TCP, local IPC (AF_UNIX), in-memory loopback, TLS, WebSocket (own RFC 6455 framing, proxy traversal only), UDP-reliable, HTTP/1.1 gateway (own minimal parser). Both directions: the host can listen or dial out (reverse mode). Discovery: platform DNS-SD APIs behind `Rhp::net::discovery`. No default port.

**Why**
- Asio is the most portable mature reactor (IOCP/epoll/kqueue) with C++20 coroutines.
- `std::execution` has no networking until C++29.

**Alternatives:** libuv (C callbacks), raw sockets (we'd write the reactor), Beast (needs Boost), websocketpp (unmaintained since 2022), IXWebSocket (own threads).

**Consequences**
- Asio isn't in its own upstream iOS/Android test matrix — our mobile presets are the guarantee.
- iOS can't listen while suspended → reverse mode, plus `NSLocalNetworkUsageDescription` / `NSBonjourServices`.

**Stage 3 (as built)**
- Asio 1.38.2 (standalone, `ASIO_NO_DEPRECATED`), only in `net/io_context.cpp` and `net/tcp/tcp.cpp`; `net::io_context` wraps `asio::io_context` (post, poll, run_one_for, run(stop_token), one-shot timers).
- `Rhp::net::transport` concept: `name`, `listen(io, endpoint, accept_fn) → result<unique_ptr<listener>>` (binds at once), `dial(io, endpoint, connect_fn)` (asynchronous). Transports hand out `net::link`s (start / send / close / peer) that report to a `link_handler` on the context's thread; `on_closed` is posted, once, never after destruction.
- Shipped: `net::loopback` (in-process channels named by host + port, ends may sit on different threads/contexts) and `net::tcp` (IPv4 + IPv6, `TCP_NODELAY`, `SO_REUSEADDR` only off Windows, port 0 → a free port).
- Until TLS (Stage 5) TCP allows loopback addresses only (127.0.0.0/8, ::1, v4-mapped, `localhost`); anything else is `kForbidden` unless the endpoint carries `Rhp::net::insecure_lan`.
- Stage 3 hosts listen and clients dial; reverse mode is Stage 4. Local IPC, WebSocket, UDP-reliable, the HTTP gateway and mDNS are Stage 5–6.
