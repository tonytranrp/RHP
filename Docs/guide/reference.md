# Reference

## Error codes

Result-bearing operations report `Rhp::error { code, message, where, traceback }` in expected mode. `message`, `where` and `traceback` are owning strings; `Rhp::exception::err()` exposes the same data in throwing mode. Over the wire the code travels by name; an unknown name arrives as `runtime`.

| Code | Meaning |
|---|---|
| `transport` | connection failed, closed, or a TLS alert |
| `protocol` | malformed frame or message |
| `protocol_revision_mismatch` | host and client speak different protocol revisions (currently 6) |
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
| `limit_exceeded` | a size, count or rate limit was hit: a frame or reply over `max_frame`, a peer leaving 64 MiB unacknowledged, MessagePack depth / element limits, too many pending handshakes, requests in flight or backlog, a blob over `max_blob`, a reply too large to cache, HTTP header / replay limits, too many arguments for a coroutine or `rhp.spawn` |
| `disabled` | `RHP_ENABLE=OFF` or `set_enabled(false)` |
| `invalid_argument` | bad call arguments, or writing a read-only member |
| `type_mismatch` | value cannot convert to the requested type |
| `out_of_range` | a number does not fit the target integer type, or is not an integer |
| `unloaded` | touched a force-unloaded module |
| `expired` | a release outside its validity window (`not_before` / `not_after`, with the manager's clock skew) |
| `revoked` | a release (or the key that signed it) a revocation list withdrew, or one quarantined on this host |
| `superseded` | a release whose seq isn't above its channel's floor, or a revocation list not newer than the last |
| `out_of_scope` | a release meant for another app, build or platform |

A write outside a variable's `Rhp::range<>` (a script's, or `tune`) is `out_of_range`. The debugger answers `not_found` for a request that isn't paused, `out_of_range` for a frame it doesn't have.

## Host events

All carry `time`. `peer` is the transport address of the client. In JSON the `granted` field is written as `"role"`.

| Event | When | Notable fields |
|---|---|---|
| `session_opened` | a client authenticated | `session`, `identity`, `granted` role, `peer`, `platform`, `tls` |
| `session_resumed` | a session continued on a new link | `session`, `identity`, `peer`, `tls` |
| `session_closed` | an authenticated session ended | `session`, `identity`, `peer`, `reason` |
| `auth_failed` | a connection never authenticated | `peer`, `reason` |
| `script_executed` | any request that runs code or changes state, refused ones included | `session`, `identity`, `granted`, `peer` (per request; the HTTP caller over the gateway), `op`, `module`, `hash` (BLAKE2b-256 hex), `signer`, `outcome` |
| `blob_received` | a blob finished or was refused | `session`, `identity`, `sink`, `file`, `size`, `hash`, `outcome` |
| `identity_reverted` | an identity's last session ended and the host reverted it | `identity`, `undone`, `irreversible`, `failures`, `pinned` |
| `handler_failed` | a script's timer, frame callback, event handler or task failed | `identity`, `module`, `kind`, `source`, `handler` (the script's id), `action` (`report` / `remove` / `fault`), `outcome` |
| `release_changed` | a served release manager (`host.serve`) applied, confirmed, rolled back or refused a release, or applied a revocation list | `kind` (`applied` / `confirmed` / `rolled_back` / `refused` / `revocations`), `channel`, `release` and `fallback` (hex ids), `seq`, `reason`, `outcome` |

`Rhp::event::to_json(event)` returns JSON text; sinks append a newline when writing it. A suspended request's `script_executed` reports its final outcome; see [audit semantics](host-and-client.md#events-and-audit). Session events' `peer` and every event's `identity` describe the connected peer, which may be a dialing host in reverse mode. `event::script_event` (`host.on_script_event`) is application traffic and not part of `event::any`.

## Operations

`exec`, `load`, `call`, `reload`, `rollback`, `checkpoint`, `revert_to`, `revert`, `unload`, `pin`, `unpin`, `revert_all`, `list`, `status`, `describe`, `blob`, `subscribe` / `unsubscribe` (`client.on` / `off`), `release_apply` / `release_confirm` / `release_deactivate` (admin), `release_status` / `revoke` ([releases](releases.md)), `tunables` / `profile` (observe), `tune` / `debug` (patch) ([tools](tools.md)), and `cancel` (client side). Minimum roles are in [Host and client](host-and-client.md#rhpclientcfg).

## Wire protocol

- 28-byte little-endian header: magic `RHP\0`, 8-bit `protocol_revision`, 8-bit flags (`kMac` 1, `kAckRequested` 2, `kMore` 4 reserved, `kCrcOmitted` 8), 16-bit op, 64-bit seq, 64-bit ack, 32-bit payload length. Then MessagePack, a 4-byte CRC32C trailer (omitted on TLS links), and a 32-byte keyed MAC once authenticated. Before the handshake completes a payload may be at most 16 KiB.
- Ops: handshake `hello` 1, `challenge` 2, `response` 3, `welcome` 4, `resume` 5; requests `exec` 16, `load` 17, `call` 18, `reload` 19, `rollback` 20, `unload` 21, `revert` 22, `revert_to` 23, `checkpoint` 24, `revert_all` 25, `cancel` 26, `list` 27, `status` 28, `describe` 29, `pin` 30, `unpin` 31, `blob` 32, `subscribe` 33, `unsubscribe` 34, `release_apply` 35, `release_confirm` 36, `release_deactivate` 37, `release_status` 38, `revoke` 39, `tunables` 40, `tune` 41, `profile` 42, `debug` 43; replies `output` 48, `emit` 49, `result` 50, `error` 51, `event` 52; control `ping` 64, `pong` 65, `ack` 66, `nack` 67. Controls do not join data sequencing; their seq field carries a per-direction replay-protection counter.
- Handshake payloads: `hello {rev, platform, auth}`, `challenge {rev, platform, auth}`, `response {auth}`, `welcome {session, identity, role, heartbeat_ms, platform}`, `resume {session, proof}`.
- Requests and replies are envelopes `{req, idem?, body}`; req correlates output/results and idem identifies a retry within the retained session cache. Handshake messages are direct payloads; session-ending errors are unsequenced direct error maps.
- `subscribe` (33) / `unsubscribe` (34) carry `{name}` and are answered nil; each delivery is an `event` reply (52) with `req` 0 and `{name, module, args, dropped}`.
- `release_apply` (35) carries `{envelope, confirm}` and answers `{channel, id, seq, running, already, replaced, signers}`; `release_confirm` / `release_deactivate` (36, 37) carry `{channel, hold, release}` (`release`: an expected 32-byte id, or empty) and answer the id of the release confirmed / stopped; `release_status` (38) answers `{app, build, platform, revocation_seq, channels}`; `revoke` (39) carries `{envelope}` and answers the number of channels that changed. Envelopes are opaque bytes here ([releases](releases.md)).
- `tunables` (40) carries `{prefix}` and answers an array of `{path, type, value, writable, min, max, step, unit, doc}`; `tune` (41) carries `{path, value}` and answers nil; `profile` (42) carries `{action, interval, max_depth, max_stacks}` (`start` / `read` / `stop`) and answers `{running, interval, samples, dropped, elapsed_us, stacks, truncated}` with each stack a `[folded, samples]` pair (stacks beyond a quarter of the host's max frame are left out and counted in `truncated`); `debug` (43) carries `{action, source, lines, request, frame, scope, path, expression}` and answers `{lines, paused, frames, variables}` ([tools](tools.md)).
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
| any thread | `cancel()`, `set_enabled()`, `sessions()`, `identities()`, `port()`, `gateway_port()`, hitting a patch point (runs the C++ default if its layer belongs to another thread), subscribing to events |

Request/reply traffic crosses two SPSC rings and cancel relays; queued Lua events and pending client results use mutex-protected state. Async callbacks normally complete on the client I/O thread, or immediately on the registration thread if already ready. Owned-I/O and zero-thread operation have different progress rules; see [host/client threading](host-and-client.md#thread-rules). Details: [`../decisions/threading-model.md`](../decisions/threading-model.md).
