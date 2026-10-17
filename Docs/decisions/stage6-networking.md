# Stage 6 networking decisions

Usage: [networking and fleet](../guide/networking.md). Stage 6 reuses the wire protocol, authentication, script signing and the host dispatcher; it adds transports, a discovery slot, a fleet and an HTTP frontend. Decision ids AC*/AD* are in [ARCHITECTURE.md](../ARCHITECTURE.md) §30–31.

## Shape

- **Transports are policies.** `websocket`, `udp_reliable` and `local_ipc` satisfy `Rhp::net::transport` like `tcp`. Each keeps its protocol in a sans-IO codec under `net/<transport>/detail/` (`ws::decode_header`/`encode_frame`, `rudp::decode_packet`/`encode_packet`) so it is unit-tested and fuzzed without sockets; the `.cpp` holds only the link state machine.
- **Discovery is a slot.** `config<>::discovery<D>` takes a `Rhp::net::discovery` policy (`mdns` default, `mdns_wire`, `no_discovery`), type-erased into `net::discovery_ops`. Publishing is a runtime opt-in (`host.advertise()`); library names are a second opt-in.
- **HTTP is a frontend, not a transport.** It feeds the existing dispatcher through a private `gateway_sink` interface the engine implements (as it implements `session::handler`), so no gateway type appears in `host.hpp`. Proof checking is the authenticator's job (`security::http_authenticator`).
- **Fleet is a thin template over one compiled engine.** `Rhp::fleet<Cfg>` (`fleet.cpp`) starts every `exec` / `load` / `call` before waiting and collects one outcome per host; `Rhp::discover<Cfg>()` is the shared browse. Its members are client engines on one shared `net::io_context`, so a fleet runs one I/O thread (none with `io<zero_threads>`) however many hosts it has. (The first cut held one full `client<Cfg>`, and so one I/O thread, per member.)

## WebSocket

RFC 6455 binary frames at `/rhp`, client masking, continuations, ping/pong and a five-second close handshake. Session TLS runs inside the frames, which keeps the RFC 9266 channel binding: a `ws` tunnel for proxies, not a browser `wss` endpoint. The client role is a template parameter of the link state (`websocket_state<ws::role>`), so masking and the upgrade direction are fixed at compile time. Data payloads stream straight to the session; only a frame header or a control frame (≤ 125 bytes) is ever buffered. Sends larger than 16 MiB become several messages.

## Reliable UDP

480-byte payloads (under the 576-byte IPv4 minimum reassembly size), random connection tokens, cumulative plus 64-bit selective ACKs and CRC-32C. Loss recovery: a hole with three later packets acknowledged is resent at once (fast retransmit, at most once per RTT, one window halving per recovery); otherwise the RFC 6298 timeout (25 ms – 2 s, Karn's rule) fires once per batch, doubling until progress. The timer is armed only for the next deadline, so an idle link costs no wakeups. A listening socket keeps at most 1024 live peers, so a Hello flood can't grow its state; the session's handshake budget limits the rest. FIN acknowledgements stay answerable for 12 s from a tombstone after the link is gone. ACKs are not authenticated: an on-path attacker can stall a link (as with TCP); the session MAC or TLS still rejects injected data.

## IPC

Windows: overlapped byte-mode pipes, the first instance created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and a DACL for the owner and SYSTEM, `PIPE_REJECT_REMOTE_CLIENTS`; dialers open with `SECURITY_IDENTIFICATION` so a pipe squatter can't impersonate them. POSIX: mode-0600 sockets, only the listener's own device/inode is unlinked. Linux/Android check `SO_PEERCRED` against the effective UID for abstract (`@name`) and pathname sockets. Authentication stays mandatory.

## Discovery

- Windows: the DNS-SD API for browsing and for wildcard listeners; a listener bound to one address uses the wire responder, because native registration can't publish that address. Apple: `dns_sd` with owned address and service records (not built or run on this host: see [TODO](../TODO.md)). Linux and native Android executables: `mdns_wire`; an APK can supply an `NsdManager` policy.
- The wire responder follows RFC 6762: probe 3 × 250 ms after a random 0–250 ms delay, announce twice a second apart, then answer queries only; goodbye with TTL 0; a renamed record releases the old names first, an updated one is re-announced without probing; `update()` clears a previous conflict. The querier sends continuous queries from 1 s doubling to a minute and follows up missing SRV/TXT/A/AAAA records. Host-name listen addresses are resolved asynchronously; the I/O thread never blocks on DNS.
- Bounds: 9000-byte packets, 128 records per packet, 1024 cached records, 255-byte TXT items, 1200 bytes of TXT.

## HTTP

- One logical session per key, kept across connections. It ends after `gateway_idle_ms` only with nothing in flight; a client that hangs up cancels its own request. (The first cut expired identities with requests still running and reverted their work.)
- Proofs: keyed BLAKE2b over the request, ±30 s, one use. Unknown key names are checked against a per-process decoy key, so timing doesn't reveal valid names. The replay cache gives each key its own quota (4096 per window) so one key can't fill it for everyone, and prunes in expiry order.
- `X-RHP-Signature` carries the signer policy's signature value as base64 MessagePack, so custom `signer<S>` policies work over HTTP (the first cut rebuilt Ed25519's internal format by hand).
- Cancellation is per request (`X-RHP-Request` token, `POST /cancel/{token}`) or explicitly for every request of the key (`POST /cancel`).
- Channel binding is opt-in per request (`X-RHP-Channel: tls-exporter`): the MAC then also covers the connection's RFC 9266 exporter value, so a TLS-terminating relay can't get a request accepted. Opt-in keeps plain HTTP clients and TLS-offloading front ends (which can't see the exporter) working; such clients must check the host certificate instead.
- Every answer to an authenticated request carries `X-RHP-Proof`, a MAC over status, content type and body under a per-request key derived from the request's MAC, so the answer is tied to its request without the host keeping per-client state. The PSK itself never signs answers.
- Idle expiry follows the host's `config<>::clock` through an offset from `steady_clock` that `pump()` samples into an atomic: the network thread never calls the user's clock, which may be advanced by the game thread. With a custom clock the idle timer re-checks every 25 ms instead of sleeping to a deadline it can't predict. Proof freshness and the replay window stay on the system clock: shifting them with a game clock would reject real clients, and a clock that jumps and returns would reopen the window for replays.
- `host_options::http_require_binding` refuses unbound requests (signed 401), for hosts that want the native handshake's guarantee over HTTP.
- `script_executed` carries a `peer` for every request; over HTTP it is that request's caller, since one logical session has many.

## Sources

[RFC 6455](https://www.rfc-editor.org/rfc/rfc6455) · [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085) · [RFC 6298](https://www.rfc-editor.org/rfc/rfc6298) · [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762) · [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) · [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) · [Windows DNS-SD](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsservicebrowsecancel) · [Apple DNS-SD](https://developer.apple.com/documentation/dnssd) · [Android NSD](https://developer.android.com/develop/connectivity/wifi/use-nsd) · [Named pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
