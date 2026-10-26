# audit — layer 4

Sinks that write host events (see [`../event`](../event)) as JSON lines, one per event (`Rhp::event::to_json`). Namespace `Rhp::audit`. Target `Rhp::audit`; depends on `event` only.

| Header | What |
|---|---|
| `sinks.hpp` | `file_sink` (appends to a file, flushed per line; copies share the file; `ok()`), `ostream_sink` (a stream the caller owns) |

```cpp
Rhp::audit::file_sink sink{"rhp_audit.log"};
if (auto ok = sink.ok(); !ok) { std::println(stderr, "audit: {}", ok.error()); }
auto audit = host.on_any(sink);
auto failures = host.on<Rhp::event::auth_failed>(Rhp::audit::ostream_sink{std::cerr});
```

```text
{"event":"script_executed","time":"2026-10-09T08:45:11.817Z","session":1,"identity":"dev","role":"admin","peer":"127.0.0.1:51234","op":"load","module":"low","hash":"ea78…","signer":"dev","outcome":{"code":"ok"}}
```

## Rules

- Sinks are thread-safe and copyable (`std::function` needs that); they take one event or `Rhp::event::any`.
- An `ostream_sink`'s stream must outlive every copy of the sink.
- A sink that can't open its file drops events; `file_sink::ok()` says why — check it at startup.
- The hash in `script_executed` / `blob_received` is BLAKE2b-256 of the source / bytes, in hex.
