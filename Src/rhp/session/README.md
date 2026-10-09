# session — layer 4

One authenticated, reliable conversation over a link, and TLS over any link. Namespace `Rhp::session`.

| Header | What |
|---|---|
| `session.hpp` | `session` (host or client side), `handler` (`on_ready`, `on_message`, `on_closed`; `on_detached`, `on_resumed`, `resume_target` for resume), `options`, `state` |
| `secure_link.hpp` | `tls_client` / `tls_server` (TLS over any `net::link`; the server sniffs the first byte), `channel_policy` (which connections of an endpoint get TLS) |

## What a session does

```text
handshake   hello → challenge → response → welcome (first MAC'd frame); handshake_timeout_ms
binding     under TLS the authenticator mixes the link's channel binding (tls-exporter) into its proofs
frames      CRC32C on every frame except on TLS links; keyed MAC on every frame after the handshake
sequenced   requests and replies: seq 1, 2, 3 …, cumulative ack in every header, delivered once and in order
nack        a corrupt frame (bad CRC) or a gap → nack(last good seq) → the peer resends everything after it
resend      unacked frames are resent on nack, when a whole heartbeat passes with no ack progress, and on resume
heartbeat   ping every heartbeat_ms; heartbeat_misses quiet intervals → the link is dead
resume      (options.resumable) a dead link detaches the session for limits.resume_ms; the dialing side
            calls resume(new_link) → sealed kResume with a proof over the new link's channel binding;
            the other side's new connection hands its link to the session (resume_target) → sealed
            kWelcome, bound the same way; both resend what wasn't acked. A failed attempt (no answer
            within 2 s, garbage, a refusal) only loses that link: the dialing side tries another
errors      a fatal problem goes to the peer as an unsequenced kError (sealed once keys exist), then close
```

## Rules

- No templates over policies: transports, codecs, authenticators and TLS arrive as `net::link`, `wire::codec_ops`, `security::*_handshake` and `security::tls::context`.
- Every call happens on the session's `net::io_context` thread. `on_closed` is posted; destroy a session only from `on_closed` or outside its callbacks.
- A session's link can change (resume): it is not destroyed inside its own callbacks (`retired_`).
- The side that dials speaks first: a TLS dialer sends its ClientHello, a plaintext host that dials opens with a ping (`options::speaks_first`).
