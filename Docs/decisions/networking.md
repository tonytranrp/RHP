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
- Until TLS (Stage 5, now built) TCP allowed loopback addresses only (127.0.0.0/8, ::1, v4-mapped, `localhost`); anything else is `kForbidden` unless the endpoint carries `Rhp::net::insecure_lan`.
- Stage 3 hosts listen and clients dial; reverse mode is Stage 4. Local IPC, WebSocket, UDP-reliable, the HTTP gateway and mDNS are Stage 5–6.

**Stage 4 (as built):** reverse mode. A host with `Rhp::endpoint::dial(...)` dials and redials (capped exponential backoff with full jitter between `limits.backoff_min_ms` and `backoff_max_ms`); a client with `Rhp::endpoint::listen(...)` listens, serves one host at a time, reports its port with `client::port()`, and survives its host (calls in flight fail; the next call waits for a host to dial in). Each connection is a fresh session; resume is Stage 5.

**Stage 5 (as built):** TLS 1.3 over any transport through a link decorator (`session::tls_client` / `tls_server`), engines from `config<>::tls<B>` (the system's OpenSSL or Mbed TLS 4.2). Endpoints carry `tls_mode` (`kAuto`, `kRequire` via `Rhp::net::require_tls`): dialing a non-loopback address over a network transport (`T::network`) uses TLS unless `insecure_lan`; a listener sniffs the first byte and takes plaintext only from loopback peers (`link::loopback()`), local transports or `insecure_lan`. TCP binds or dials non-loopback addresses when the endpoint says TLS will be layered on top (or `insecure_lan`). A lost link is redialed and the session resumed (`limits.resume_ms`), in both directions.
