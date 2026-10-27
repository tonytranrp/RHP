# event — layer 3

What a host reports. Namespace `Rhp::event`. Target `Rhp::event`; depends on `core` only, built with `RHP_ENABLE=OFF` too.

| Header | What |
|---|---|
| `events.hpp` | the host events `session_opened` (with `tls`), `session_closed`, `auth_failed` (with the `key` name that was tried), `script_executed`, `blob_received`, `identity_reverted`, `session_resumed`, `handler_failed`, `release_changed`; `any` (a variant of all of them), the `host_event` concept, `kind_of<E>`, `to_json`; `script_event` (an `rhp.publish`, not in `any`) |
| `hub.hpp` | `hub` (a host's handlers: `add`, `wants`, `publish`), `script_hub` (`host.on_script_event` handlers by name or `*`), `subscription` (= `Rhp::subscription`, RAII, move-only), `subscribe<E>` / `subscribe_any` / `subscribe_script` |

```cpp
auto scripts = host.on<Rhp::event::script_executed>([](const Rhp::event::script_executed& e) {
    std::println("{} ran {} ({}) signed by {}: {}", e.identity, e.op, e.hash, e.signer, e.outcome.code);
});
auto releases = host.on<Rhp::event::release_changed>([](const auto& e) { std::println("{} {} {}", e.kind, e.channel, e.release); });
auto everything = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
auto published = host.on_script_event("game.round_over", [](const Rhp::event::script_event& e) { /* e.identity, e.args */ });
```

## Rules

- Every event carries `time` (`system_clock`), so a log line is meaningful on its own.
- A host publishes on its pump thread. Both hubs are `core::listener_table`s: subscribe and unsubscribe from any thread; handlers run outside the lock, so a handler may unsubscribe itself; once an unsubscribe returns, that handler neither runs nor starts again. A handler that throws is logged by the host and never breaks `pump()`.
- `hub::wants(kind)` lets the host skip building events nobody listens to.
- A `subscription` may outlive its host (it then does nothing); dropping it unsubscribes.
- `to_json` writes one line with no newline; strings are escaped (control characters as `\uXXXX`; bytes that aren't valid UTF-8 become U+FFFD, since names come from clients), errors as `{"code", "message", "where"}`.
- New event kinds go at the end of `any` (their index is `kind_of<E>`).
- Script events stay out of `any`: they are application traffic, and audit sinks take `any`.
- The two `listener_table` instantiations are compiled once, in `hub.cpp` (`extern template` in `hub.hpp`); keep new instantiations there.
