# custom_transport

Your own `Rhp::net::transport`: a `name`, `listen()` and `dial()` handing out `Rhp::net::link`s. This one wraps the in-process loopback transport and counts the bytes it sends; a Steam P2P socket, a serial link or a company relay has the same shape.

```cpp
using metered_cfg = Rhp::config<>::transport<metered::transport>;   // concept-checked on this line
```

RHP layers the session on top of any ordered byte stream: framing, CRC32C, the PSK handshake, the per-frame MAC, seq/ack/nack and heartbeats. A transport only moves bytes.

Rules for a link: call the handler only on the `io_context`'s thread (use `io_context::post` from elsewhere), report `on_closed` once and never after the link is destroyed, and write queued bytes before closing.

Run: `custom_transport` prints the sum a script computed and how many bytes crossed the metered links.
