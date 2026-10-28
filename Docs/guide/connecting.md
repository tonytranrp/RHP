# Connecting

Everything about *how* a client and a host find and talk to each other.

## Endpoints

An `Rhp::endpoint` says where the peer is and which side waits. There is no default port.

```cpp
Rhp::endpoint::listen("127.0.0.1", 7777)                       // wait here
Rhp::endpoint::dial("10.0.0.5", 7777)                          // connect there
Rhp::endpoint::listen("0.0.0.0", 7777, Rhp::net::require_tls)  // TLS even on loopback
Rhp::endpoint::listen("0.0.0.0", 7777, Rhp::net::insecure_lan) // plaintext with local peers only (hardening dev only)
```

For a TCP listener, port 0 binds a free port; check and read `host.port()` (or `client.port()` in reverse mode). Dial endpoints need the actual listening port. Loopback uses an in-process channel name and number, and its listener reports port 0 rather than an OS socket port.

## Common setups

| Setup | Host | Client |
|---|---|---|
| Same machine (dev) | `listen("127.0.0.1", 7777)` | `dial("127.0.0.1", 7777)` |
| LAN or internet | `listen("0.0.0.0", 7777)` — TLS is applied to every non-loopback peer | `dial("10.0.0.5", 7777)` — TLS automatically |
| Phone or NAT (reverse) | `dial("devpc", 7777)` | `listen("0.0.0.0", 7777)` |
| Same process (tests) | config `transport<Rhp::net::loopback>`, `listen("game", 1)` | `dial("game", 1)` |

## TLS

TLS 1.3 comes from `config<>::tls<B>`: the system's **OpenSSL ≥ 3.0** on desktop, **Mbed TLS 4.2** on mobile and as the fallback; the default `auto_backend` picks for you.

| Situation | Behavior |
|---|---|
| dial a non-loopback address over a network transport | the dialer starts TLS under `tls_mode::kAuto` |
| listen on a non-loopback address | TLS from remote peers; plaintext only when the accepted peer is loopback or the endpoint explicitly permits it |
| loopback peer or a local transport | plaintext is fine; frames still carry a keyed MAC |
| `Rhp::net::require_tls` | TLS always, plaintext refused |
| `Rhp::net::insecure_lan` | plaintext allowed with local peers only: loopback, private (RFC 1918, RFC 4193 `fc00::/7`) and link-local addresses. Anyone else must start TLS (or is refused when there is no TLS to offer); a dial to a literal address that isn't local fails at once, one whose name resolved to such an address before a byte is sent (`kForbidden`). CGNAT (`100.64/10`) isn't local. Refused outright above hardening `dev`, by hosts, gateways and clients |
| no TLS backend built (`tls<Rhp::security::tls::none>` or `RHP_WITH_TLS=OFF`) | non-loopback endpoints are refused (`kForbidden`) unless `insecure_lan` |

**Supplying a certificate is optional; TLS still uses one.** By default the host makes an ephemeral self-signed certificate and the key handshake is bound to the TLS channel (RFC 9266), so a relay that terminates TLS cannot authenticate; the default PSK policy rejects a TLS-terminating relay with a different channel binding. Add certificate checks if you want them:

```cpp
Rhp::host_options ho;
ho.tls.cert_pem = certificate_pem;
ho.tls.key_pem = private_key_pem;

Rhp::client_options co;
co.tls.ca_pem = authority_pem;
co.tls.server_name = "game.lan";
```

The three input variables above contain PEM **text loaded by the application**, not file paths. CLI `--cert`, `--key` and `--ca` instead accept paths and read those files. With a CA and an empty `server_name`, the certificate is checked against what was dialed: a DNS name against its DNS names, an IP endpoint against its IP subject alternative names. So dialing by IP needs a certificate that carries that IP address, or a `server_name` set to a DNS name the certificate carries. A dialed name counts as an IP address only if it parses as one (`cafe1` and `db1.de` are names). With an IP address, Mbed TLS also sends it as SNI; OpenSSL sends none. CA-chain checks and PSK channel authentication are separate checks. The Python client's `ca_file` checks the name too: a DNS name or IP address in the certificate's subject alternative names (`*.` covers one label; the common name doesn't count).

Pick a backend explicitly: `Rhp::config<>::tls<Rhp::security::tls::mbedtls>`.

## Reverse mode

Use it when the host can make an outbound connection but cannot accept an inbound one, such as a device behind NAT. Both the host pump and networking must still run; reverse mode does not keep a suspended application executing.

```cpp
Rhp::host<> host{Rhp::endpoint::dial("10.0.0.5", 7777), keys, signers};                       // on the phone
Rhp::client<> dev{Rhp::endpoint::listen("0.0.0.0", 7777), id.credential(), *id.signer_key()}; // on the PC
auto port = dev.port();                                                                       // starts listening; check the result
auto ready = dev.connect();                                                                   // waits up to connect_timeout; check before making calls
```

- The dialing host redials whenever the dial fails or the session ends, with capped exponential backoff and full jitter (`limits.backoff_min_ms` 250 ms to `backoff_max_ms` 30 s).
- A listening client serves one host at a time. When that host's session ends, calls in flight fail and the next call waits for a host to dial in. Every connection is a candidate until it authenticates, and candidates handshake side by side under the client's own admission limits (`pending_handshakes`, `handshakes_per_source`, `first_byte_ms`): the first to authenticate becomes the session, so a stalled or silent connection can't keep the real host out.
- Tooling: `rhp-cli connect 0.0.0.0:7777 -i dev.rhpid --listen` and `headless_server --reverse HOST:PORT`.
- iOS needs `NSLocalNetworkUsageDescription` (and `NSBonjourServices` containing `_rhp._tcp` or `_rhp._udp` for discovery) in Info.plist.

## Reliability and reconnect

You do not code any of this; it is how the session layer behaves.

- Frames carry CRC32C (omitted under TLS), sequencing, acks, nacks and resends; authenticated traffic carries the per-session MAC. Three quiet 2 s heartbeat intervals detect a dead link. With resume enabled, that starts the detached/resume period rather than immediately ending the session.
- **Resume:** when a link drops, both sides keep the session for `limits.resume_ms` (6 s). The dialing side redials and sends a sealed resume request bound to the new connection; both sides resend unacked frames. The sandbox, modules and in-flight requests are untouched, and resent frames are delivered once in that surviving session. The host also keeps a bounded response cache for duplicate idempotency-key requests. Neither mechanism is durable across a host restart; evicted cache entries do not retain arbitrary old retry results.
- Only when the session truly ends (closed, refused, or not resumed in time) does the "last session gone, revert the identity" rule fire. Set `resume_ms = 0` to end sessions at once.
- `limits.max_frame` caps each payload at 4 MiB by default, excluding header/trailers. Use `client.blob()` for larger binary data and register a sink explicitly; blobs do not automatically fragment an oversized exec source or result.
- A dialing client resumes a temporarily detached session. Once that session finally ends, or its initial dial/authentication fails, create a new client to reconnect. A dialing host retries fresh sessions; a listening client keeps serving future hosts.
- A timed-out call may already have performed application effects. A new call gets a new request/idempotency key; do not assume repeating it is the same protocol retry.
- Graceful client close and host goodbye end sessions without waiting for the resume grace period; application cleanup still needs host pumps.
- A standalone ack waits up to 5 ms for an outgoing frame (usually the reply) to carry it, so a call and its reply are two frames. TCP and IPC links send frames queued behind a write in flight in one gathered write. Neither changes the protocol; see [performance](performance.md#network).

## `rhp-cli`

The REPL and scripting client. Full command list: [`Tools/rhp-cli/README.md`](../../Tools/rhp-cli/README.md).

```bash
rhp-cli keygen dev                                            # dev.rhpid (role patch); rhp-cli pubkey -i dev.rhpid prints the host's lines
rhp-cli connect HOST:PORT -i dev.rhpid                        # REPL, every script signed
rhp-cli connect --dev my_game                                 # a dev session on this machine: no key files
rhp-cli run scripts/low_grav.lua -c HOST:PORT -i dev.rhpid --pin --name low_grav
rhp-cli exec "return game.gravity" -c HOST:PORT -i dev.rhpid
rhp-cli stubs -c HOST:PORT -i dev.rhpid -o rhp_api.lua
rhp-cli blob configs settings.json -c HOST:PORT -i dev.rhpid
rhp-cli watch scripts -c HOST:PORT -i dev.rhpid                # save a .lua, it reloads
rhp-cli events game.round_over -c HOST:PORT -i dev.rhpid       # print host events until Ctrl+C
rhp-cli sign file.lua -i dev.rhpid                             # signature for other tools
```

Other commands have their own guides: `discover` and `fleet` ([networking](networking.md#fleets)), `release`, `revoke` and `rollout` ([releases](releases.md#rhp-cli)), `tune`, `profile` and `dap` ([tools](tools.md)), `test` ([testing scripts](testing-scripts.md#rhp-cli-test)).

| Option | What |
|---|---|
| `-i`, `--identity` (or `RHP_IDENTITY`) | identity file |
| `--listen` | reverse mode: listen and wait for the host to dial in |
| `--timeout ms` | connect timeout; CLI default 10 s when dialing and 10 min with `--listen`; not a script execution timeout |
| `--tls` | TLS even on loopback (non-loopback always uses it) |
| `--ca pem` + `--server-name` | verify the host's certificate |
| `--cert` / `--key` | this side's certificate (with `--listen`) |
| `--insecure-lan` | plaintext to a local (private or link-local) address; refused by an `rhp-cli` built above hardening `dev` |
| `--dev [app]` (`connect` only) | a [dev session](security.md#dev-sessions) of a program on this machine: no address or identity file; with no app, the only one open |

Ctrl+C cancels an executing Lua chunk. In the REPL, Ctrl+C at a continuation prompt drops unfinished input; EOF with unfinished Lua is an error. Temporary link loss is resumed within the session window; permanent session failure requires a new CLI connection. One-shot commands disconnect on exit, so use `run --pin` with an admin key when a loaded module must survive the command. `watch` watches saves after it starts; it does not initially load every existing file. `events` (and `subscribe` / `unsubscribe` in the REPL) print the host's C++ events and your identity's script events ([scheduling and events](scheduling-and-events.md#5-watch-events-from-a-tool)). Exit status is 0 on success, 1 on failure and 2 for usage errors.

## `headless_server`

A ready-made host for `rhp-cli`, and a good template for your own. Options are in [`Examples/headless_server/README.md`](../../Examples/headless_server/README.md): `--host`, `--port`, `--keys`, `--signers`, `--audit`, `--blobs`, `--reverse`, `--tls`, `--cert` / `--key`, `--ca`, `--insecure-lan`.

## Your own transport

RHP layers framing, handshake, MAC, acks and heartbeats on top of **any ordered byte stream**. To add Steam P2P, a serial link or a company relay, write a type that satisfies `Rhp::net::transport`:

```cpp
struct my_transport {
    static constexpr std::string_view name = "my";
    static constexpr bool network = true; // required for automatic network TLS policy
    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::accept_fn);
    static void dial(Rhp::net::io_context&, const Rhp::endpoint&, Rhp::net::connect_fn);
};

using cfg = Rhp::config<>::transport<my_transport>; // concept-checked on this line
```

`listen` binds at once (errors return immediately), keeps calling `on_accept` with each new `Rhp::net::link` until the returned `Rhp::net::listener` is destroyed, and reports its port through `listener::port()` (0 for transports without ports). `dial` connects asynchronously and calls `on_connect` exactly once with a link or an error.

A link is a connected byte stream:

| `Rhp::net::link` member | Does |
|---|---|
| `start(link_handler&)` | begin delivering received bytes (`on_bytes`) and the end of the stream (`on_closed`) |
| `send(byte_buffer)` / `close()` | queue bytes / close after writing what is queued |
| `peer()` | a readable address for logs and audit |
| `loopback()` / `encrypted()` / `channel_binding()` | security facts the session uses; the defaults say remote, plaintext, unbound |
| `address()` | the peer's IP address (`std::optional<Rhp::net::ip_address>`); the default says none |

Every transport must declare `network` (Stage 8): `true` for anything another machine can reach (the TLS address rules then apply), `false` for in-process, IPC or a cable. A transport without it doesn't compile, so none is silently treated as local. A network transport should report its peer's IP address in `address()`: hosts and listening clients cap unauthenticated connections per source by it, and `insecure_lan` speaks plaintext only with peers it knows to be local; without one, connections count only toward the total cap and get no plaintext. When wrapping a link, derive from `Rhp::net::link_decorator`: it forwards `loopback()`, `encrypted()`, `channel_binding()` and `address()`, which the session's security depends on.

Link rules: call the handler only on the `io_context`'s thread (use `io_context::post` from elsewhere), report `on_closed` exactly once and never after the link is destroyed, and write queued bytes before closing. See [`Examples/custom_transport`](../../Examples/custom_transport).

## Other transports and discovery

[Networking and fleet](networking.md) documents WebSocket binary tunneling, reliable UDP, local IPC, the HTTP REST listener, explicit DNS-SD advertisement and fleet execution. They use the existing authentication, signatures and lifecycle. Advertisement is opt-in; discovery does not authenticate an endpoint.
