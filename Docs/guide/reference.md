# Reference

## Error codes

Result-bearing operations report `Rhp::error { code, message, where, traceback }` in expected mode. `message`, `where` and `traceback` are owning strings; `Rhp::exception::err()` exposes the same data in throwing mode. Over the wire the code travels by name; an unknown name arrives as `runtime`.

| Code | Meaning |
|---|---|
| `transport` | connection failed, closed, or a TLS alert |
| `protocol` | malformed frame or message |
| `protocol_revision_mismatch` | host and client speak different protocol revisions (currently 4) |
| `auth` | authentication/MAC/resume-proof failure, or a certificate verification failure when certificate checks are enabled |
| `forbidden` | role too low, pinned module, or a non-loopback address without TLS or `insecure_lan` |
| `bad_signature` | script unsigned (and not observe), unknown signer, or signature does not verify |
| `integrity` | checksum failure during handshake; a ready session normally nacks a bad CRC; bad MACs are `auth` |
| `timeout` | connect, request or `wall_ms` exceeded |
| `compile` | Lua syntax error |
| `runtime` | Lua runtime error |
| `budget_exceeded` | `instructions` limit hit |
| `memory_exceeded` | `memory` limit hit |
| `stale_handle` | a handle whose `is_alive` check failed |
| `not_found` | no such module or blob sink (also unknown checkpoint tag) |
| `already_loaded` | name taken (lib, sink) |
| `has_dependents` | other modules `require` it; unload with `force` |
| `revert_partial` | some effects could not be undone |
| `irreversible` | reported effect that cannot be undone |
| `cancelled` | stopped by `cancel` |
| `limit_exceeded` | a limit was hit: too many pending handshakes, too many requests in flight, a blob over `max_blob`, a reply too large to cache |
| `disabled` | `RHP_ENABLE=OFF` or `set_enabled(false)` |
| `invalid_argument` | bad call arguments, or writing a read-only member |
| `type_mismatch` | value cannot convert to the requested type |
| `out_of_range` | a number does not fit the target integer type, or is not an integer |
| `unloaded` | touched a force-unloaded module |

## Host events

All carry `time`. `peer` is the transport address of the client.

| Event | When | Notable fields |
|---|---|---|
| `session_opened` | a client authenticated | `session`, `identity`, `granted` role, `peer`, `platform`, `tls` |
| `session_resumed` | a session continued on a new link | `session`, `identity`, `peer`, `tls` |
| `session_closed` | an authenticated session ended | `session`, `identity`, `peer`, `reason` |
| `auth_failed` | a connection never authenticated | `peer`, `reason` |
| `script_executed` | any request that runs code or changes state, refused ones included | `session`, `identity`, `granted`, `op`, `module`, `hash` (BLAKE2b-256 hex), `signer`, `outcome` |
| `blob_received` | a blob finished or was refused | `sink`, `file`, `size`, `hash`, `outcome` |
| `identity_reverted` | an identity's last session ended and the host reverted it | `undone`, `irreversible`, `failures`, `pinned` |
| `handler_failed` | a script's timer, frame callback, event handler or task failed | `identity`, `module`, `kind`, `source`, `handler` (the script's id), `action` (`report` / `remove` / `fault`), `outcome` |

`Rhp::event::to_json(event)` returns JSON text; sinks append a newline when writing it. A suspended request's `script_executed` reports its final outcome; see [audit semantics](host-and-client.md#events-and-audit). Session and blob events' `peer`/identity describe the connected peer, which may be a dialing host in reverse mode. `event::script_event` (`host.on_script_event`) is application traffic and not part of `event::any`.

## Operations

`exec`, `load`, `call`, `reload`, `rollback`, `checkpoint`, `revert_to`, `revert`, `unload`, `pin`, `unpin`, `revert_all`, `list`, `status`, `describe`, `blob`, `subscribe` / `unsubscribe` (`client.on` / `off`), and `cancel` (client side). Minimum roles are in [Host and client](host-and-client.md#rhpclientcfg).

## Wire protocol (for custom clients)

- 28-byte little-endian header: magic `RHP\0`, 8-bit `protocol_revision`, 8-bit flags, 16-bit op, 64-bit seq, 64-bit ack, 32-bit payload length. Then MessagePack, a 4-byte CRC32C trailer (omitted on TLS links), and a 32-byte keyed MAC once authenticated.
- Ops 1–15 handshake (`hello`, `challenge`, `response`, `welcome`, `resume`), 16–47 requests, 48–63 replies, 64+ control frames (`ping`, `pong`, `ack`, `nack`). Controls do not join data sequencing; their seq field carries a replay-protection counter, not always zero.
- Requests and replies are envelopes `{req, idem?, body}`; req correlates output/results and idem identifies a retry within the retained session cache. Handshake messages are direct payloads; session-ending errors are unsequenced direct error maps.
- `subscribe` (33) / `unsubscribe` (34) carry `{name}` and are answered nil; each delivery is an `event` reply (52) with `req` 0 and `{name, module, args, dropped}`.
- Max frame 4 MiB; blobs are sent as chunked requests.

Details: [`../decisions/wire-format.md`](../decisions/wire-format.md) and `Docs/ARCHITECTURE.md` §8. The protocol revision is a plain integer; there is no "v" naming anywhere in RHP.

## What the Lua sandbox contains

| | observe / patch | admin |
|---|---|---|
| Libraries | `string`, `table`, `math`, `utf8`, `coroutine`, `os.time`, `os.clock` | full standard library: `io`, `os` (incl. `execute`, `getenv`, `remove`, `rename`), `package.loadlib`, `debug` |
| `load` | text only | text only |
| RHP `exec` / `load` / `reload` source | text only | text only |
| `string.dump` | removed | available (admin's full standard library) |
| Other capabilities | no `dofile`, `loadfile`, `collectgarbage`, `io`, `package`, `debug` | available; admin file/native-library operations are outside RHP's text-source loader and undo model |
| `require` | host loader: only loaded modules of the same identity | same |

## Threading summary

| Thread | Does |
|---|---|
| application/sandbox thread | Lua execution, owned patch layers, blob sinks and host events; same-thread `lua_event` fire may deliver synchronously outside pump |
| RHP network thread | sockets, TLS, framing, acks, resume, cancel relays |
| any thread | `cancel()`, `set_enabled()`, `sessions()`, `identities()`, hitting a patch point (runs the C++ default if its layer belongs to another thread), subscribing to events |

Request/reply traffic crosses two SPSC rings and cancel relays; queued Lua events and pending client results use mutex-protected state. Async callbacks normally complete on the client I/O thread, or immediately on the registration thread if already ready. Owned-I/O and zero-thread operation have different progress rules; see [host/client threading](host-and-client.md#thread-rules). Details: [`../decisions/threading-model.md`](../decisions/threading-model.md).
