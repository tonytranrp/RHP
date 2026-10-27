# WebSocket

`Rhp::config<>::transport<Rhp::net::websocket>` on both peers (`network = true`: the TLS address rules apply; DNS-SD publishes it under `_rhp._tcp` with transport `websocket`).

```cpp
using cfg = Rhp::config<>::transport<Rhp::net::websocket>;
Rhp::host<cfg> host{Rhp::endpoint::listen("127.0.0.1", 8080), keys, signers};   // ws://127.0.0.1:8080/rhp
```

- RFC 6455 at `/rhp`: binary frames, client masking, continuations, ping/pong, a 5-second close handshake. A text frame is a protocol error (close 1002). Extensions and subprotocols are never offered: a server answer that adds one fails the upgrade (the TCP connection closes, no Close frame).
- Session TLS travels *inside* the frames, so the channel-bound PSK handshake is kept. This is a tunnel for proxies that only pass HTTP, not a browser `wss` endpoint (that would put TLS before the upgrade).
- `detail/protocol.hpp` is the sans-IO part: `decode_header`, `encode_frame` / `encode_header`, `apply_mask`, close payloads and the upgrade. The link state in `websocket.cpp` is a template on `ws::role`, so masking and the upgrade direction are compile-time.
- Data payloads are handed to the session as they arrive; only a frame header or one control frame is buffered. Each send is one message of at most 16 MiB (larger sends are split); the pre-upgrade queue too. A send over 16 KiB keeps its buffer: the header goes ahead of it and a client masks it in place, so the payload isn't copied (smaller ones are copied behind their header, one buffer for TCP).
- `close()` before the upgrade finishes waits for it, then sends the queued bytes and Close. Destroying a closing link still flushes it; destroying an open one aborts it.
