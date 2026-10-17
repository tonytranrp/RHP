# wire — layer 2

What travels between a host and a client. Namespace `Rhp::wire`. No dependencies beyond `utils` / `core`.

| Header | What |
|---|---|
| `ops.hpp` | `op` (16-bit frame op), `kProtocolRevision`, `frame_flag`, op classes (`is_request`, `is_sequenced`, …), `required_role(op)` |
| `frame.hpp` | the 28-byte header, `encode_frame`, the incremental `frame_decoder`, `frame_sealer` (the MAC interface the authenticator implements) |
| `codec.hpp` | the `codec` concept (`Rhp::value` ⇄ bytes), `decode_limits`, `codec_ops` |
| `codec/msgpack.hpp` | `msgpack`: RHP's own MessagePack codec for `Rhp::value` |
| `messages.hpp` | payload schemas (`hello` … `welcome`, `envelope`, every request, `module_status`, `revert_summary`, `emit_message`, `subscribe_request`, `event_message`) with `Rhp::convert` specializations |

## Frame

```text
 0         4     5       6    8       16      24       28
 | "RHP\0" | rev | flags | op | seq    | ack    | length | payload | crc32c 4B | [MAC 32B]
```

Little-endian header; the payload is MessagePack. The CRC and the MAC both cover header + payload. Payloads are ≤ `limits.max_frame` (4 MiB), checked before anything is allocated.

## Payloads

Every request and reply is an `envelope {req, idem?, body}`: `req` ties replies, output and emits to the client's request (0 = none), `idem` is the client's idempotency key. Handshake frames carry `hello` / `challenge` / `response` / `welcome` directly; a session-ending `kError` (seq 0) carries an `Rhp::error`.

| Op | Request body | Result body |
|---|---|---|
| exec | `{source, chunk, signature}` | array of values |
| load | `{name, source, signature}` | module id |
| call | `{module, function, args}` | array of values |
| reload / rollback | `{module, source, signature}` / `{module, steps}` | revision (0 = deferred) |
| pin / unpin | `{module}` | nil |
| blob | `{transfer, sink, name, total, offset, data}` (one chunk) | nil (the last chunk: the sink's verdict) |
| revert / status | `{module}` | revert summary / module status |
| unload | `{module, force}` | revert summary |
| checkpoint / revert_to | `{tag}` | nil / revert summary |
| revert_all | nil | revert summary |
| cancel | `{target}` (0 = all of this session's) | no reply |
| list / describe | nil | array of module status / LuaLS stubs string |

`module` is an id (integer) or a name (string). Replies: `kResult`, `kError` (body = `Rhp::error`), `kOutput` (string), `kEmit` (`{module, value}`).

## Rules

- No sockets, no crypto, no Lua: the MAC is the `frame_sealer` interface; `Rhp::security` implements it.
- Decoders never trust a length or a count: every count is checked against the bytes left, nesting against `decode_limits::max_depth`.
- Message schemas only grow: decoders ignore unknown keys, and a changed meaning bumps `kProtocolRevision`.
