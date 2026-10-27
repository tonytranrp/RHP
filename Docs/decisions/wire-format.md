# Wire format and reliability

**Decision** (as originally taken; the as-built notes below supersede the codec, MAC and blob parts)**:** fixed 28-byte little-endian binary header (magic `RHP` + NUL, `protocol_rev`, flags, op, seq, ack, length) + MessagePack payload (msgpack-c ≥ 9.0.0, Boost-free) + CRC32C trailer (omitted under TLS) + keyed-BLAKE2b MAC on loopback/IPC. 4 MiB max frame; blobs fragment. Reliability: seq/ack resend window, resume token, idempotency-key response cache, ping 2 s / dead after 3 misses, backoff 250 ms → 30 s with full jitter. No compression.

**Why**
- The header routes without decoding the payload.
- MessagePack maps 1:1 onto Lua values with no codegen.
- TCP's checksum misses roughly 1 in 10^8–10^9 packets, so a CRC is justified when TLS isn't there.
- FEC only applies to the UDP transport.

**Alternatives:** CBOR, FlatBuffers / Protobuf / Cap'n Proto (codegen, heavy), glaze (heavy compile, unlisted mobile support).

**Consequences:** `protocol_rev` is a plain integer agreed in `hello`; there is no "v" naming anywhere.

**Stage 3 (as built)**
- **Codec changed:** MessagePack is RHP's own codec for `Rhp::value` (`Rhp::wire::msgpack`, `Src/rhp/wire/codec/`), not msgpack-c. Why: `Rhp::value` has eight kinds, so the codec is ~400 lines with no dependency; msgpack-c's Boost-free mode is still marked experimental; every count is checked against the bytes left and nesting against `decode_limits::max_depth` (100) before anything is allocated, which is what a fuzzer will hammer. `config<>::codec<>` still takes any codec.
- The header is the 28 bytes above with a 16-bit op. Ops 1–15 are the handshake (`hello`, `challenge`, `response`, `welcome`, reserved `resume`), 16–47 requests, 48–63 replies — both sequenced — and 64+ control frames (`ping`, `pong`, `ack`, `nack`), which are unsequenced (seq 0). A session-ending error is an unsequenced `kError`.
- Every request and reply payload is an `envelope {req, idem, body}` (`wire/messages.hpp`, one `Rhp::convert` per message). Decoders ignore unknown keys; a changed meaning bumps `kProtocolRevision` (1).
- CRC32C covers header + payload on every frame. After the handshake every frame carries a keyed-BLAKE2b MAC over header + payload under its direction's key; the host's `welcome` is the first sealed frame.
- Reliability: cumulative ack in every header; explicit `ack` frames when nothing else carries it; a nack's ack field is the last good seq and the peer resends everything after it; a heartbeat interval with no ack progress resends the window; duplicates are dropped by seq.
- Idempotency: per session, keyed by the client's 63-bit `idem`; 256 finished responses kept; a retry in flight waits for the original's result.
- Not yet: resume tokens, reconnect/backoff (Stage 5), fragmentation (`kMore`, blobs, Stage 4), `CRC_OMITTED` (TLS, Stage 5).

**Stage 3 review fixes:** frames before the handshake are capped at 16 KiB; the MessagePack decoder has a total value budget (`max_elements`, 2^20) and reserves at most 256 slots per container up front; control frames (ping, pong, ack, nack) carry a per-direction counter in `seq` so replays are dropped.

**Stage 4 (as built):** `kProtocolRevision` 2. `exec` / `load` / `reload` requests carry `signature` (nil = unsigned); `pin` / `unpin` take `{module}`; `module_status` gains `pinned`. Blobs are chunked per message, not per frame: `kBlob` carries `{transfer, sink, name, total, offset, data}`, each chunk is a request answered nil, the last one's answer is the sink's verdict; `kMore` stays reserved. `wire::required_role(kBlob)` is observe — each sink checks its own role.

**Stage 5 (as built):** `kProtocolRevision` 3. `kResume {session, proof}` (handshake op 5, sealed, the sender's next control counter in `seq`, its cumulative ack in `ack`; `proof` = the sender's frame MAC over `"rhp/resume"` ‖ the new connection's channel binding) opens a new connection for a detached session; the answer is a sealed `kWelcome {session, proof}` (`"rhp/resumed"`); both sides then resend everything after the other's ack. Frames on encrypted links set `kCrcOmitted` and carry no CRC; such a frame on a plaintext link ends the session. A host that dials (reverse mode) opens with an unsealed ping (seq 0), which handshakes ignore.

**Stage 7 (as built):** `kProtocolRevision` 4. `kSubscribe` (33) / `kUnsubscribe` (34) carry `subscribe_request {name}` (observe; answered nil); `kEvent` (52) is a sequenced reply with envelope `req` 0 and `event_message {name, module, args, dropped}`. Because the revision check is strict, revision-3 peers are refused at hello instead of meeting an unknown op mid-session.

**Stage 10:** `kProtocolRevision` 5 (releases and revocation lists): see [stage10-releases.md](stage10-releases.md).

**Stage 11:** `kProtocolRevision` 6 (tunables, the profiler and the debugger): see [stage11-tools.md](stage11-tools.md).
