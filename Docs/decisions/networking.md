# Networking backend and transports

**Decision:** standalone Asio 1.38.x behind the `Rhp::net::transport` concept. Transports: TCP, local IPC (AF_UNIX), in-memory loopback, TLS, WebSocket (own RFC 6455 framing, proxy traversal only), UDP-reliable, HTTP/1.1 gateway (own minimal parser). Both directions: the host can listen or dial out (reverse mode). Discovery: platform DNS-SD APIs behind `Rhp::net::discovery`. No default port.

**Why**
- Asio is the most portable mature reactor (IOCP/epoll/kqueue) with C++20 coroutines.
- `std::execution` has no networking until C++29.

**Alternatives:** libuv (C callbacks), raw sockets (we'd write the reactor), Beast (needs Boost), websocketpp (unmaintained since 2022), IXWebSocket (own threads).

**Consequences**
- Asio isn't in its own upstream iOS/Android test matrix — our mobile presets are the guarantee.
- iOS can't listen while suspended → reverse mode, plus `NSLocalNetworkUsageDescription` / `NSBonjourServices`.
