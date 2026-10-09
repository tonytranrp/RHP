# session — layer 4

One authenticated, reliable conversation over a link. Namespace `Rhp::session`.

| Header | What |
|---|---|
| `session.hpp` | `session` (host or client side), `handler` (`on_ready`, `on_message`, `on_closed`), `options`, `state` |

## What a session does

```text
handshake   hello → challenge → response → welcome (first MAC'd frame); handshake_timeout_ms
frames      CRC32C on every frame; keyed MAC on every frame after the handshake (wrong MAC → kAuth, close)
sequenced   requests and replies: seq 1, 2, 3 …, cumulative ack in every header, delivered once and in order
nack        a corrupt frame (bad CRC) or a gap → nack(last good seq) → the peer resends everything after it
resend      unacked frames are resent on nack, and when a whole heartbeat passes with no ack progress
heartbeat   ping every heartbeat_ms; heartbeat_misses quiet intervals → kTimeout, close
errors      a fatal problem goes to the peer as an unsequenced kError (sealed once keys exist), then close
```

## Rules

- No templates over policies: transports, codecs and authenticators arrive as `net::link`, `wire::codec_ops` and `security::*_handshake`.
- Every call happens on the session's `net::io_context` thread. `on_closed` is posted; destroy a session only from `on_closed` or outside its callbacks.
- Resume tokens and reconnect/backoff are Stage 5; today a dead link ends the session.
