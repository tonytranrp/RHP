# event — layer 3

What a host reports. Namespace `Rhp::event`. Depends on `core` only; built with `RHP_ENABLE=OFF` too.

| Header | What |
|---|---|
| `events.hpp` | the event types (`session_opened`, `session_closed`, `auth_failed`, `script_executed`, `blob_received`, `identity_reverted`), `any` (a variant of all of them), the `host_event` concept, `kind_of<E>`, `to_json` |
| `hub.hpp` | `hub` (a host's handlers, thread-safe), `subscription` (RAII, move-only), `subscribe<E>` / `subscribe_any` |

```cpp
auto scripts = host.on<Rhp::event::script_executed>([](const Rhp::event::script_executed& e) {
    std::println("{} ran {} ({}) signed by {}: {}", e.identity, e.op, e.hash, e.signer, e.outcome.code);
});
auto everything = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
```

## Rules

- Every event carries `time` (`system_clock`), so a log line is meaningful on its own.
- A host publishes on its pump thread; handlers run outside the hub's lock, so a handler may unsubscribe itself. A handler that throws is logged by the host and never breaks `pump()`.
- A `subscription` may outlive its host (it then does nothing); dropping it unsubscribes.
- `to_json` writes one line with no newline; strings are escaped (control characters as `\uXXXX`; bytes that aren't valid UTF-8 become U+FFFD, since names come from clients), errors as `{"code", "message", "where"}`.
- New event kinds go at the end of `any` (their index is `kind_of<E>`).
