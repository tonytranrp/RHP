# audit — layer 4

Sinks that write host events (see `../event`) as JSON lines. Namespace `Rhp::audit`.

| Header | What |
|---|---|
| `sinks.hpp` | `file_sink` (appends to a file, flushed per line; copies share the file), `ostream_sink` (a stream the caller owns) |

```cpp
auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
```

```text
{"event":"script_executed","time":"2026-10-09T08:45:11.817Z","session":1,"identity":"dev","role":"admin","op":"load","module":"low","hash":"ea78…","signer":"dev","outcome":{"code":"ok"}}
```

## Rules

- Sinks are thread-safe and copyable (`std::function` needs that); they take one event or `Rhp::event::any`.
- A sink that can't open its file drops events; `file_sink::ok()` says why — check it at startup.
- The hash in `script_executed` / `blob_received` is BLAKE2b-256 of the source / bytes, in hex.
