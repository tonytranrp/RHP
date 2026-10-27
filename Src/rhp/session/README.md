# session — layer 4

One authenticated, reliable conversation over a link, and TLS over any link. Namespace `Rhp::session`. Target `Rhp::session`; depends on `net`, `security`, `tls` and `wire` (nothing is compiled with `RHP_ENABLE=OFF`). Hosts and clients use it; applications don't need to.

| Header | What |
|---|---|
| `session.hpp` | `session` (host or client side: `start`, `send`, `close`, `resume`; `id`, `current`, `ready`, `usable`, `identity`, `granted`, `peer`, `peer_platform`, `encrypted`, `handed_over`, `stats`), `handler` (`on_ready`, `on_message`, `on_closed`; `on_detached`, `on_resumed`, `resume_target` for resume), `options`, `state` (`kHandshaking`, `kReady`, `kDetached`, `kClosed`) |
| `secure_link.hpp` | `tls_client` / `tls_server` (TLS over any `net::link`; the server sniffs the first byte: `0x16` is TLS), `channel_policy` (which connections of an endpoint get TLS: `make`, `transport_endpoint`, `wrap`, `tls`) |

## What a session does

```text
handshake   hello → challenge → response → welcome (first MAC'd frame); limits.handshake_timeout_ms
binding     under TLS the authenticator mixes the link's channel binding (tls-exporter) into its proofs
frames      CRC32C on every frame except on TLS links; keyed MAC on every frame after the handshake
sequenced   requests and replies: seq 1, 2, 3 …, cumulative ack in every header, delivered once and in order
acks        an outgoing frame carries the ack; a standalone kAck waits options.ack_delay_ms (5 ms) for one,
            and goes at once for the 8th unacknowledged frame, a frame with kAckRequested, and a duplicate
nack        a corrupt frame (bad CRC) or a gap → nack(last good seq) → the peer resends everything after it
resend      unacked frames are resent on nack, when a whole heartbeat passes with no ack progress, and on resume
heartbeat   ping every limits.heartbeat_ms; heartbeat_misses quiet intervals → the link is dead
resume      (options.resumable) a dead link detaches the session for limits.resume_ms; the dialing side
            calls resume(new_link) → sealed kResume with a proof over the new link's channel binding;
            the other side's new connection hands its link to the session (resume_target) → sealed
            kWelcome, bound the same way; both resend what wasn't acked. A failed attempt (no answer
            within min(handshake_timeout_ms, 2 s), 2 s when that is 0; garbage; a refusal) only loses that link: the dialing side tries another
errors      a fatal problem goes to the peer as an unsequenced kError (sealed once keys exist), then close
```

With delayed acks a call and its reply are two frames instead of four; the protocol is unchanged (`ack_delay_ms = 0` acks every read at once).

## TLS policy (`channel_policy`)

- Dialing: TLS when the endpoint requires it (`require_tls`), or when the transport is a network one, the address isn't loopback and the endpoint doesn't say `insecure_lan`.
- Listening: TLS is accepted from anyone who starts it (when a backend exists); plaintext only from loopback peers, over local transports, or with `insecure_lan`, never with `require_tls`.
- `make` fails with `kForbidden` when the endpoint needs TLS and the backend (`tls::none`) can't provide it.

## Rules

- No templates over policies: transports, codecs, authenticators and TLS arrive as `net::link`, `wire::codec_ops`, `security::*_handshake` and `security::tls::context`.
- Every call happens on the session's `net::io_context` thread. `on_closed` is posted; destroy a session only from `on_closed` or outside its callbacks.
- A session's link can change (resume): the old one is not destroyed inside its own callbacks (`retired_`).
- The side that dials speaks first: a TLS dialer sends its ClientHello, a plaintext host that dials opens with an unsealed ping (`options::speaks_first`); handshaking sessions ignore pings.
- A peer that stops acknowledging past `options::max_unacked_bytes` (64 MiB) is dropped.
