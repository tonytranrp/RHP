# wire — layer 2

What travels between a host and a client. Namespace `Rhp::wire`. Target `Rhp::wire`; depends on `core` only. Decisions: [wire format](../../../Docs/decisions/wire-format.md).

| Header | What |
|---|---|
| `ops.hpp` | `op` (16-bit frame op), `kProtocolRevision` (6), `frame_flag` (`kMac`, `kAckRequested`, `kCrcOmitted`; `kMore` reserved), op classes (`is_handshake`, `is_request`, `is_reply`, `is_sequenced`, `is_known`), `required_role(op)`, `to_string(op)` |
| `frame.hpp` | the 28-byte `frame_header`, `encode_frame`, the incremental `frame_decoder` (`decode_status`, `frame_view`), `frame_sealer` (the MAC interface the authenticator implements) |
| `codec.hpp` | the `codec` concept (`Rhp::value` ⇄ bytes), `decode_limits` (`max_depth` 100, `max_elements` 2^20), `codec_ops` / `codec_ops_for<C>` (the type-erased form the session uses) |
| `codec/msgpack.hpp` | `msgpack`: RHP's own MessagePack codec for `Rhp::value` (the default `config<>::codec`) |
| `messages.hpp` | payload schemas with `Rhp::convert` specializations: handshake (`hello`, `challenge`, `response`, `welcome`, `resume`), `envelope` with `envelope_value` / `take_envelope`, every request body, and the replies (`revert_summary`, `module_status`, `emit_message`, `event_message`, the release, tunable, profile and debug messages) |

## Frame

```text
 0         4     5       6    8       16      24       28
 | "RHP\0" | rev | flags | op | seq    | ack    | length | payload | [crc32c 4B unless kCrcOmitted] | [MAC 32B if kMac]
```

Little-endian header; the payload is MessagePack. The CRC and the MAC both cover header + payload, so a corrupted frame fails the CRC first (nack, resend) and only a forged one fails the MAC. `seq` 0 = unsequenced; `ack` is cumulative. Payloads are ≤ `limits.max_frame` (4 MiB), checked before anything is allocated. The CRC is left out only on encrypted links.

## Payloads

Every request and reply is an `envelope {req, idem, body}`: `req` ties replies, output and emits to the client's request (0 = none), `idem` is the client's idempotency key (0 = none). `envelope_value(req, idem, body)` and `take_envelope(value)` move the body in and out instead of copying it. Handshake frames carry their message directly; a session-ending `kError` (seq 0) carries an `Rhp::error`.

| Op | Least role | Request body | Result body |
|---|---|---|---|
| exec | observe | `{source, chunk, signature}` | array of values |
| load | patch | `{name, source, signature}` | module id |
| call | observe | `{module, function, args}` | array of values |
| reload / rollback | patch | `{module, source, signature}` / `{module, steps}` | revision (0 = deferred) |
| revert / unload | patch | `{module}` / `{module, force}` | `revert_summary` |
| checkpoint / revert_to | patch | `{tag}` | nil / `revert_summary` |
| revert_all | admin | nil | `revert_summary` |
| pin / unpin | admin | `{module}` | nil |
| cancel | observe | `{target}` (0 = all of this session's) | no reply |
| list / status / describe | observe | nil / `{module}` / nil | array of `module_status` / `module_status` / LuaLS stubs string |
| blob | observe (each sink checks its own role) | `{transfer, sink, name, total, offset, data}` (one chunk) | nil; the last chunk: the sink's verdict |
| subscribe / unsubscribe | observe | `{name}` | nil |
| release_apply | admin | `{envelope, confirm}` (`now` / `health` / `manual`) | `release_apply_reply` |
| release_confirm / release_deactivate | admin | `{channel, hold, release}` | the release id (bytes) |
| release_status | observe | nil | `release_status_reply` |
| revoke | observe (the list carries its own signatures) | `{envelope}` | channels changed |
| tunables / tune | observe / patch | `{prefix}` / `{path, value}` | array of `tunable_message` / nil |
| profile | observe | `{action, interval, max_depth, max_stacks}` | `profile_reply` |
| debug | patch | `{action, source, lines, request, frame, scope, path, expression}` | `debug_reply` |

`module` is an id (integer) or a name (string). Replies: `kResult`, `kError` (body = `Rhp::error`), `kOutput` (string), `kEmit` (`{module, value}`), `kEvent` (`req` 0, `{name, module, args, dropped}`). Control frames: `kPing`, `kPong`, `kAck`, `kNack` (header `ack` = last good seq).

```cpp
Rhp::utils::byte_buffer payload, out;
const Rhp::value body = Rhp::wire::envelope_value(7, 0, Rhp::value{"return 1"});
auto encoded = Rhp::wire::msgpack::encode(body, payload);        // or a config's codec_ops
Rhp::wire::frame_header h;
h.code = Rhp::wire::op::kExec;
h.seq = 1;
auto framed = Rhp::wire::encode_frame(h, payload.view(), out, /*sealer=*/nullptr, Rhp::limits{}.max_frame);
auto back = Rhp::wire::take_envelope(*Rhp::wire::msgpack::decode(payload.view()));
```

## Rules

- No sockets, no crypto, no Lua: the MAC is the `frame_sealer` interface; `Rhp::security` implements it.
- Decoders never trust a length or a count: every count is checked against the bytes left, nesting against `decode_limits::max_depth`.
- Message schemas only grow: decoders ignore unknown keys, and a changed meaning bumps `kProtocolRevision`.
- Op numbers are fixed: handshake < 16, requests 16..47, replies 48..63, control from 64. A new request goes at the end of its range and gets a `required_role`; bindings and sinks check their own roles on top.
