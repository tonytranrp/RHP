# Reference

## Error codes

Result-bearing operations report `Rhp::error { code, message, where, traceback }` in expected mode. `message`, `where` and `traceback` are owning strings; `Rhp::exception::err()` exposes the same data in throwing mode. Over the wire the code travels by name; an unknown name arrives as `runtime`.

| Code | Meaning |
|---|---|
| `transport` | connection failed, closed, or a TLS alert |
| `protocol` | malformed frame or message |
| `protocol_revision_mismatch` | host and client speak different protocol revisions (currently 7) |
| `auth` | authentication/MAC/resume-proof failure (an unlisted, revoked or `env=dev` key at production included), a device-key handshake without TLS, a changed or unpinned host key, or a TLS certificate verification failure when certificate checks are enabled |
| `forbidden` | role too low, pinned module, a non-loopback address without TLS or `insecure_lan`, a plaintext peer `insecure_lan` doesn't count as local, a metatable with `__gc` outside admin's full standard library, a handler builtin (`rhp.timer`, `rhp.on`, `rhp.spawn`, ...) called by observe or by a narrowed exec; a [capability scope](security.md#keys-certificates-and-the-root-of-trust) refusal (an op, a patch point, an event, a binding's `Rhp::cap<>`: "needs capability <name>", a certificate that denies a lib the identity has); an operator certificate whose `max_role` is below the session's, with a critical option or unreadable scopes, or tagged dev at production; a [hardening](security.md#hardening-levels) refusal: `insecure_lan`, `unsigned_scripts` or a dev session the level doesn't allow (from `port()`), the debugger, `advertise()` or an unbound gateway at `production` |
| `bad_signature` | script unsigned (and not observe, or observe at hardening `production`), unknown signer (an `env=dev` signer at production included), signature does not verify, a certificate not issued by a trusted CA, malformed claims, or a claim nonce used before (a replay) |
| `integrity` | checksum failure during handshake; a ready session normally nacks a bad CRC; bad MACs are `auth` |
| `timeout` | connect, request or `wall_ms` exceeded |
| `expired` | a release outside its validity window (`not_before` / `not_after`, with the manager's clock skew), a root of trust update past its expiry, an operator certificate outside its validity, or script claims past their expiry |
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
| `limit_exceeded` | a size, count or rate limit was hit: a frame or reply over `max_frame`, a peer leaving 64 MiB unacknowledged, MessagePack depth / element limits, too many pending handshakes (in total or from one source), requests in flight or backlog, an identity over `request_rate` (HTTP 429) or with 4096 requests or 64 MiB waiting for `pump_requests`, a sandbox at its `handlers` cap, a blob over `max_blob`, a reply too large to cache, HTTP header / replay limits, too many arguments for a coroutine or `rhp.spawn` |
| `disabled` | `RHP_ENABLE=OFF`, or `set_enabled(false)` (the reason a closed session reports, and every call's answer while the host is off) |
| `invalid_argument` | bad call arguments, or writing a read-only member |
| `type_mismatch` | value cannot convert to the requested type |
| `out_of_range` | a number does not fit the target integer type, or is not an integer; a release or revocation seq that moves more than `max_seq_jump` at once |
| `unloaded` | touched a force-unloaded module |
| `revoked` | a release (or the key that signed it) a revocation list withdrew, one quarantined on this host, a script by a signer key or an operator certificate an identity revocation list names |
| `superseded` | a release whose seq isn't above its channel's floor, a revocation list not newer than the last, or a root of trust not newer than the one held |
| `out_of_scope` | a release meant for another app, build or platform; script claims or an operator certificate for another app, environment or host |

A write outside a variable's `Rhp::range<>` (a script's, or `tune`) is `out_of_range`. The debugger answers `not_found` for a request that isn't paused, `out_of_range` for a frame it doesn't have.

## Host events

All carry `time`. `peer` is the transport address of the client. In JSON the `granted` field is written as `"role"`.

| Event | When | Notable fields |
|---|---|---|
| `session_opened` | a client authenticated | `session`, `identity`, `granted` role, `peer`, `platform`, `tls` |
| `session_resumed` | a session continued on a new link | `session`, `identity`, `peer`, `tls` |
| `session_closed` | an authenticated session ended | `session`, `identity`, `peer`, `reason` |
| `auth_failed` | a connection never authenticated (refused by admission, the handshake or a disabled host) | `peer`, `reason`, `key` (the key name it tried, from its hello or HTTP proof; empty when none) |
| `script_executed` | any request that runs code or changes state, refused ones included | `session`, `identity`, `granted`, `peer` (per request; the HTTP caller over the gateway), `op`, `module`, `hash` (BLAKE2b-256 hex), `signer`, `outcome` |
| `blob_received` | a blob finished or was refused | `session`, `identity`, `sink`, `file`, `size`, `hash`, `outcome` |
| `identity_reverted` | an identity's last session ended and the host reverted it | `identity`, `undone`, `irreversible`, `failures`, `pinned` |
| `handler_failed` | a script's timer, frame callback, event handler or task failed | `identity`, `module`, `kind`, `source`, `handler` (the script's id), `action` (`report` / `remove` / `fault`), `outcome` |
| `release_changed` | a served release manager (`host.serve`) applied, confirmed, rolled back or refused a release, applied a revocation list, or accepted a newer root of trust or identity revocation list | `kind` (`applied` / `confirmed` / `rolled_back` / `refused` / `revocations` / `trust`), `channel`, `release` and `fallback` (hex ids), `seq` (for `trust`: the root version or the identity list's seq, `reason` says which), `reason`, `outcome` |

`Rhp::event::to_json(event)` returns JSON text; sinks append a newline when writing it. A suspended request's `script_executed` reports its final outcome; see [audit semantics](host-and-client.md#events-and-audit). Session events' `peer` and every event's `identity` describe the connected peer, which may be a dialing host in reverse mode. `event::script_event` (`host.on_script_event`) is application traffic and not part of `event::any`.

## Operations

`exec`, `load`, `call`, `reload`, `rollback`, `checkpoint`, `revert_to`, `revert`, `unload`, `pin`, `unpin`, `revert_all`, `list`, `status`, `describe`, `blob`, `subscribe` / `unsubscribe` (`client.on` / `off`), `release_apply` / `release_confirm` / `release_deactivate` (admin), `release_status` / `revoke` / `trust` ([releases](releases.md)), `tunables` / `profile` (observe), `tune` / `debug` (patch; `debug` is refused at hardening `production`) ([tools](tools.md)), and `cancel` (client side). Minimum roles are in [Host and client](host-and-client.md#rhpclientcfg).

## Wire protocol

- 28-byte little-endian header: magic `RHP\0`, 8-bit `protocol_revision`, 8-bit flags (`kMac` 1, `kAckRequested` 2, `kMore` 4 reserved, `kCrcOmitted` 8), 16-bit op, 64-bit seq, 64-bit ack, 32-bit payload length. Then MessagePack, a 4-byte CRC32C trailer (omitted on TLS links), and a 32-byte keyed MAC once authenticated. Before the handshake completes a payload may be at most 16 KiB.
- Ops: handshake `hello` 1, `challenge` 2, `response` 3, `welcome` 4, `resume` 5; requests `exec` 16, `load` 17, `call` 18, `reload` 19, `rollback` 20, `unload` 21, `revert` 22, `revert_to` 23, `checkpoint` 24, `revert_all` 25, `cancel` 26, `list` 27, `status` 28, `describe` 29, `pin` 30, `unpin` 31, `blob` 32, `subscribe` 33, `unsubscribe` 34, `release_apply` 35, `release_confirm` 36, `release_deactivate` 37, `release_status` 38, `revoke` 39, `tunables` 40, `tune` 41, `profile` 42, `debug` 43, `trust` 44; replies `output` 48, `emit` 49, `result` 50, `error` 51, `event` 52; control `ping` 64, `pong` 65, `ack` 66, `nack` 67. Controls do not join data sequencing; their seq field carries a per-direction replay-protection counter.
- Handshake payloads: `hello {rev, platform, auth}`, `challenge {rev, platform, auth}`, `response {auth}`, `welcome {session, identity, role, heartbeat_ms, platform, host_key}` (`host_key`: the host device key's fingerprint, only with device keys), `resume {session, proof}`.
- Requests and replies are envelopes `{req, idem?, body}`; req correlates output/results and idem identifies a retry within the retained session cache. Handshake messages are direct payloads; session-ending errors are unsequenced direct error maps.
- `subscribe` (33) / `unsubscribe` (34) carry `{name}` and are answered nil; each delivery is an `event` reply (52) with `req` 0 and `{name, module, args, dropped}`.
- `release_apply` (35) carries `{envelope, confirm}` and answers `{channel, id, seq, running, already, replaced, signers}`; `release_confirm` / `release_deactivate` (36, 37) carry `{channel, hold, release}` (`release`: an expected 32-byte id, or empty) and answer the id of the release confirmed / stopped; `release_status` (38) answers `{app, build, platform, revocation_seq, channels, root_version, identity_seq}`; `revoke` (39) carries `{envelope}` and answers the number of channels that changed. Envelopes are opaque bytes here ([releases](releases.md)).
- `tunables` (40) carries `{prefix}` and answers an array of `{path, type, value, writable, min, max, step, unit, doc}`; `tune` (41) carries `{path, value}` and answers nil; `profile` (42) carries `{action, interval, max_depth, max_stacks}` (`start` / `read` / `stop`) and answers `{running, interval, samples, dropped, elapsed_us, stacks, truncated}` with each stack a `[folded, samples]` pair (stacks beyond a quarter of the host's max frame are left out and counted in `truncated`); `debug` (43) carries `{action, source, lines, request, frame, scope, path, expression}` and answers `{lines, paused, frames, variables}` ([tools](tools.md)).
- `trust` (44) carries `{documents}` (root of trust envelopes and identity revocation lists, applied in order) and answers `{root_version, identity_seq}`.
- Device-key handshake: `hello.auth` is `{scheme = "device", alg, pub, nonce}`, the challenge `{nonce, alg, pub, sig}` and the response `{sig}`; signatures cover the length-prefixed algorithms, public keys, nonces and TLS channel binding ([decisions](../decisions/stage13-security.md)). Certified script signatures are `{cert, claims, sig}` instead of `{signer, sig}`.
- Max frame 4 MiB; blobs are sent as chunked requests.

Details: [`../decisions/wire-format.md`](../decisions/wire-format.md) and `Docs/ARCHITECTURE.md` §8. The protocol revision is a plain integer; there is no "v" naming anywhere in RHP.

## What the Lua sandbox contains

The admin column applies in a `dev` build at hardening `dev` (`sandbox_options::admin_stdlib`); otherwise admin gets the observe / patch libraries and keeps its admin rights ([hardening levels](security.md#hardening-levels)).

| | observe / patch | admin |
|---|---|---|
| Libraries | `string`, `table`, `math`, `utf8`, `coroutine`, `os.time`, `os.clock` | full standard library: `io`, `os` (incl. `execute`, `getenv`, `remove`, `rename`), `package.loadlib`, `debug` |
| `load` | text only | text only |
| RHP `exec` / `load` / `reload` source | text only | text only |
| `string.dump` | removed | available (admin's full standard library) |
| Other capabilities | no `dofile`, `loadfile`, `collectgarbage`, `io`, `package`, `debug` | available; admin file/native-library operations are outside RHP's text-source loader and undo model |
| Finalizers | `setmetatable` refuses a metatable with `__gc` (`forbidden`); `<close>` variables work | available |
| `tostring`, `print`, `%p` of tables, functions, userdata | a SipHash-2-4 of the address under the sandbox's own key, not the address | same |
| Pattern matching, plain `find` | steps charged to `limits.instructions`; `wall_ms` and cancels stop them | same |
| `table.sort` without a comparator, `load` of a huge chunk, `<` between long strings | one C call each, not checked by limits or cancels until it returns | same |
| Libs, bindings, patch points, events | what the identity's [capability scopes](security.md#keys-certificates-and-the-root-of-trust) allow: a denied lib isn't installed, a denied `Rhp::cap<>` binding raises `forbidden`, `rhp.patch` and `rhp.on` / `once` / `wait_event` refuse denied ids and names (default: everything) | same |
| Changes to `string`, `table`, `math`, `utf8`, `coroutine`, `os`, `rhp` (and `rhp.buffer`) and the string metatable | undone by the identity's full revert (`revert_all`) and by its last session's end, pinned modules or not (a pinned module must not rely on them); unloading one module doesn't undo them | same |
| Handlers (`rhp.timer`, `after`, `every`, `every_frame(s)`, `on`, `once`, `on_error`, `spawn`) | observe: refused (`forbidden`); patch: allowed | allowed |
| `require` | host loader: only loaded modules of the same identity | same |
| `rhp.api()` | the installed libs, events and patch points as a value tree (the `rhp-cli test --api-from` source) | same |
| Test sandboxes (`Rhp::test`) | the scratch environment also holds the test framework (`describe`, `it`, `assert`, `expect`, `spy`, `stub`, `mock`, `match`, `test`, `gen`, `fake`) and the `__rhp_test` bridge; modules don't see them; `os.time` / `os.clock` follow the fake clock | same |

## Threading summary

| Thread | Does |
|---|---|
| application/sandbox thread | Lua execution, owned patch layers, blob sinks and host events; same-thread `lua_event` fire may deliver synchronously outside pump |
| RHP network thread | sockets, TLS, admission of unauthenticated connections, framing, acks, resume, cancel relays, the network side of `set_enabled` |
| any thread | `cancel()`, `set_enabled()`, `sessions()`, `identities()`, `port()`, `gateway_port()`, hitting a patch point (runs the C++ default if its layer belongs to another thread), subscribing to events |

Request/reply traffic crosses two SPSC rings and cancel relays; queued Lua events and pending client results use mutex-protected state. Async callbacks normally complete on the client I/O thread, or immediately on the registration thread if already ready. Owned-I/O and zero-thread operation have different progress rules; see [host/client threading](host-and-client.md#thread-rules). Details: [`../decisions/threading-model.md`](../decisions/threading-model.md).
