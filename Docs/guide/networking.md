# Networking and fleet

More transports, finding hosts on the LAN, running one script on many hosts, and the HTTP listener. Everything here uses the ordinary `Rhp::host<Cfg>` / `Rhp::client<Cfg>`: authentication, roles, script signing, cancellation and rollback work exactly as over TCP.

## Transports

```cpp
using ws_cfg  = Rhp::config<>::transport<Rhp::net::websocket>;
using udp_cfg = Rhp::config<>::transport<Rhp::net::udp_reliable>;
using ipc_cfg = Rhp::config<>::transport<Rhp::net::local_ipc>;
```

Both peers use the same transport. The session layer adds TLS on top of any of them under the [usual rules](connecting.md#tls).

| Transport | Endpoint | Notes |
|---|---|---|
| `websocket` | host + port (0 = any) | RFC 6455 binary tunnel at `/rhp`, for proxies that only pass HTTP. RHP's TLS runs *inside* the frames, so the channel-bound handshake is kept. Not a browser-facing `wss` server: text frames and extensions are refused. |
| `udp_reliable` | host + port (0 = any) | An ordered stream over UDP: 480-byte fragments, CRC-32C, selective ACKs, fast retransmit, an RTT-based timeout and window backoff. Ten seconds without progress closes the link, and session resume takes over. TLS runs over the stream (not DTLS). |
| `local_ipc` | name, port 0 | Windows: a named pipe `\\.\pipe\rhp.<name>` for the owner and SYSTEM only, remote clients refused. POSIX: an absolute socket path created mode 0600 (only its own inode is ever removed). Linux/Android: `@name` is an abstract socket; both ends check the peer's UID. PSK authentication is still required. |

```cpp
Rhp::host<ipc_cfg> host{Rhp::endpoint::listen("my_game", 0), keys, signers};  // Windows pipe name
Rhp::client<ipc_cfg> client{Rhp::endpoint::dial("my_game", 0), identity, signing};
```

## Advertising a host

Nothing is published until you ask. After installing your libraries, on the pump thread:

```cpp
auto advertised = host.advertise({.name = "qa-worker", .app = "my_game", .build = "development"});
if (!advertised) {
    std::println(stderr, "{}", advertised.error());
}
```

Calling `advertise()` again updates the record (leave `name` empty to keep the current one). Registration finishes on the network thread, so later problems such as a name conflict (`kAlreadyLoaded`) show up in `host.discovery_status()`. Library names are published only with `.include_libs = true`; installing another library then refreshes the record.

The provider is the `discovery<D>` slot:

| `D` | What it does |
|---|---|
| `Rhp::net::mdns` (default) | Windows DNS-SD API; Apple `dns_sd`; elsewhere, and for Windows listeners bound to one address, the multicast responder below |
| `Rhp::net::mdns_wire` | RHP's own multicast DNS-SD (RFC 6762/6763): probes the name, announces twice, then answers queries; sends goodbyes; queries with backoff; caches with TTLs. No system daemon needed (Linux, native Android executables). |
| `Rhp::net::no_discovery` | `advertise()` and browsing report `kDisabled` |

Stream transports publish `_rhp._tcp`, reliable UDP publishes `_rhp._udp`. A record carries the address, port, wire revision, platform, app, build and transport name (TXT). Keys never go into a record. An Android app that needs `NsdManager` can supply its own policy with the same `Rhp::net::discovery` shape.

A record is a hint, not a credential. Anyone on the LAN can publish one; clients still authenticate every host they dial, and nothing in a record can turn on plaintext.

## Fleets

```cpp
#include <print>
#include <rhp/rhp.hpp>

int broadcast(const Rhp::security::identity_file& id) {
    auto signing = id.signer_key();
    if (!signing) {
        std::println(stderr, "identity needs a signing key");
        return 1;
    }
    Rhp::fleet<> group{id.credential(), *signing};
    Rhp::net::browse_options options;
    options.app = "my_game";
    options.duration = std::chrono::seconds{2};
    auto discovered = group.discover(options);
    if (!discovered) {
        std::println(stderr, "{}", discovered.error());
        return 1;
    }
    if (group.size() == 0) {
        std::println(stderr, "no compatible hosts found");
        return 1;
    }
    bool ok = true;
    for (const auto& entry : group.exec<int>("return game.tick")) {
        if (entry.outcome) {
            std::println("{}: {}", entry.host.name, *entry.outcome);
        } else {
            std::println(stderr, "{}: {}", entry.host.name, entry.outcome.error());
            ok = false;
        }
    }
    return ok ? 0 : 1;
}
```

`load` and `call` broadcast the same way. A module is called by name, because its id differs from host to host:

```cpp
for (const auto& entry : group.load("low_grav", source)) {   // host_result<Rhp::module_id>
    if (!entry.outcome) {
        std::println(stderr, "{}: {}", entry.host.name, entry.outcome.error());
    }
}
for (const auto& entry : group.call<double>("low_grav", "set", 1.6)) { /* host_result<double> */ }
```

- `exec`, `load` and `call` start the request on every member, then collect one outcome per host, in member order. A slow or failed host never hides the others: it gets its own error, or `kTimeout` after the shared deadline (`fleet_options::timeout`, ten seconds by default, zero waits forever); its request is then cancelled. `exec<T>` / `call<T>` convert the first returned value; without `T` they return every value (`value_list`). `load` returns each host's module id.
- Scripts (`exec`, `load`) are signed once with the fleet's signing key; without one, hosts refuse them (`kBadSignature`) except for observe identities. Calling already-loaded code needs no signature.
- `discover` adds every host a `client<Cfg>` can talk to (this transport, this wire revision) and skips malformed or foreign records. `add(record)` adds one by hand.
- Members keep their sessions, and so their effects, between broadcasts; `clear()` or destroying the fleet ends them. A member whose client closed for good is replaced on the next broadcast or discovery.
- TLS and `insecure_lan` come from `fleet_options`, never from a record.
- Every member runs on the fleet's one network reactor: a single I/O thread for the whole fleet with the default `io<owned_io_thread>`, however many hosts it has. Under `io<zero_threads>` there is none: the fleet drives every member while it waits and browses; call `poll()` while idle.
- `fleet_options::client` applies to every member. Its `on_output` / `on_emit` run on the fleet's network thread (inside the waits and `poll()` with `io<zero_threads>`); never call the fleet from them.
- One thread uses a fleet at a time.
- `Rhp::discover<Cfg>(options)` is the same browse without a fleet.

The tools run the whole flow:

```text
headless_server --port 7777 --keys keys.txt --signers signers.pub --advertise --name worker-a --app my_game
rhp-cli discover --app my_game --wait 2000
rhp-cli fleet patch.lua -i dev.rhpid --app my_game --wait 2000
```

## HTTP listener

```cpp
Rhp::host_options options;
options.gateway = Rhp::endpoint::listen("127.0.0.1", 8080); // port 0 works too: host.gateway_port()
Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 7777), keys, signers, options};
```

(`headless_server --http-port 8080` does the same.) The HTTP listener feeds the same host: the same identities, sandboxes, roles, signing checks, module lifecycle and audit events. It needs an authenticator that models `Rhp::security::http_authenticator` (`psk_keyring` does); otherwise `gateway_port()` reports `kDisabled`. Off loopback, HTTPS is required under the normal endpoint rules, with the host's TLS certificate settings.

| Route | Body | Result |
|---|---|---|
| `POST /exec` | Lua source | the return values |
| `POST /modules/{name}` | Lua source | load, or a transactional reload |
| `POST /modules/{name}/call/{function}` | MessagePack array of arguments (`application/msgpack`) | the return values |
| `POST /modules/{name}/revert` | | revert summary |
| `DELETE /modules/{name}` | | unload summary |
| `GET /modules`, `GET /modules/{name}` | | module status |
| `GET /describe` | | LuaLS annotations |
| `POST /cancel/{token}` | | cancels the request sent with `X-RHP-Request: {token}` |
| `POST /cancel` | | cancels every request this key has in flight |

Answers are MessagePack: the result, or an RHP error. Status codes: 200, 400 (bad request or arguments), 401 (proof refused or replayed), 403 (role or signature), 404, 408 (headers too slow), 409 (cancelled), 413 (too large), 422 (the script or module failed), 429 (too many requests), 500, 503 (host disabled), 504 (timed out). A suspended script answers when it finishes. Requests need `Content-Length` (no chunked bodies, no pipelining); `Expect: 100-continue` is answered. Heads are limited to 16 KiB and 64 fields, bodies to `limits.max_frame`.

Each key has one logical session, kept across connections. It ends after `limits.gateway_idle_ms` (five minutes) with nothing in flight, which reverts its effects like any last session (pinned modules and other live sessions of the identity are kept). A request in flight is never expired while its client is connected; a client that hangs up cancels its request. Idle time is measured on the host's clock (`config<>::clock<>`), and the replay window below follows that clock's offset from `steady_clock`: a test clock that jumps ahead expires identities without real waiting. A custom clock is read on the network thread too. Audit records (`script_executed`) name the caller of each request in `peer`, not the first caller of the key.

### Authenticating requests

```text
Authorization:   RHP <key-name>,<unix-seconds>,<base64 16-byte nonce>,<base64 MAC>
X-RHP-Signature: <base64 MessagePack of the signer's signature value>    (patch/admin source)
X-RHP-Request:   <your token, for /cancel/{token}>                       (optional)
X-RHP-Channel:   tls-exporter                                            (optional, TLS only)
```

```cpp
// identity: Rhp::security::psk_identity; signing: the signer policy's key (Rhp::security::signing_key)
auto signature = signing.sign(source).and_then(Rhp::security::http_signature_header);
if (!signature) {
    return std::unexpected{signature.error()};
}
const Rhp::security::http_proof request{.method = "POST", .target = "/exec", .signature = *signature,
                                        .content_type = "text/plain", .body = Rhp::utils::as_bytes(source)};
auto authorization = Rhp::security::http_authorization(identity, request); // the Authorization header value
```

The MAC is keyed BLAKE2b-256 under the key's PSK over `rhp/http\0`, the timestamp (8 bytes little-endian), then key name, nonce, method, target, `X-RHP-Signature` and `Content-Type`, each as an 8-byte little-endian length and the bytes, then the body the same way. The PSK never leaves either end. The host accepts a proof once, within 30 seconds of its clock; each key may have up to 4096 proofs in that window, so a busy key can't lock out others. Unknown key names cost the host the same work as known ones, so timing doesn't reveal which names exist.

**Channel binding.** Over HTTPS a client can bind its proof to its TLS connection: it sends `X-RHP-Channel: tls-exporter` and fills `http_proof::channel` and `http_proof::binding` (its connection's RFC 9266 exporter value, what `link::channel_binding()` returns); the MAC then also covers both, each length-prefixed after the body. The host mixes in its own connection's value. A relay that terminates TLS with its own certificate has two connections and two values, so a bound request through it is refused with 401, as the native handshake is. Binding on a connection without TLS is refused.

**Answer proofs.** Every answer to a request whose proof checked out (results and errors alike) carries `X-RHP-Proof`: keyed BLAKE2b-256 over `rhp/http-answer\0`, the status (8 bytes little-endian), then `Content-Type` and the body, each length-prefixed, under a key derived from the request's own MAC (keyed BLAKE2b-256 of the PSK over `rhp/http-answer-key\0` and the 32 MAC bytes). Answers to refused proofs (401, 503 before authentication) carry none.

```cpp
// After the answer arrived: its status, Content-Type, body and X-RHP-Proof header.
auto genuine = Rhp::security::verify_http_answer(identity, *authorization, {status, content_type, body}, proof_header);
if (!genuine) {
    return std::unexpected{genuine.error()}; // kIntegrity: changed, or not from a holder of the key
}
```

So an HTTP client knows an answer is unmodified and answers its own request even without checking the host's certificate. Without binding (or a checked certificate), a relay can still read requests and answers and pass them along; with binding it can't get a request accepted at all.
