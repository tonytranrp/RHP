# Wire format and reliability

**Decision:** fixed 28-byte little-endian binary header (magic `RHP` + NUL, `protocol_rev`, flags, op, seq, ack, length) + MessagePack payload (msgpack-c ≥ 9.0.0, Boost-free) + CRC32C trailer (omitted under TLS) + keyed-BLAKE2b MAC on loopback/IPC. 4 MiB max frame; blobs fragment. Reliability: seq/ack resend window, resume token, idempotency-key response cache, ping 2 s / dead after 3 misses, backoff 250 ms → 30 s with full jitter. No compression.

**Why**
- The header routes without decoding the payload.
- MessagePack maps 1:1 onto Lua values with no codegen.
- TCP's checksum misses roughly 1 in 10^8–10^9 packets, so a CRC is justified when TLS isn't there.
- FEC only applies to the UDP transport.

**Alternatives:** CBOR, FlatBuffers / Protobuf / Cap'n Proto (codegen, heavy), glaze (heavy compile, unlisted mobile support).

**Consequences:** `protocol_rev` is a plain integer agreed in `hello`; there is no "v" naming anywhere.
