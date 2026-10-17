# Limitations

What RHP does not do, or does only partly, as of Stage 7. Most of these are deliberate design limits; the rest are open work tracked in [Status and TODO](../TODO.md). Read this before putting RHP in front of anyone you don't fully trust.

## Safety and trust

- **RHP runs remote code on purpose.** Authentication, roles, script signing and TLS decide *who* may run code. They don't make the code harmless. An `admin` identity has Lua's full standard library (files, `os.execute`, native libraries) and is fully trusted.
- **No execution budgets by default.** Scripts run to completion unless the host sets `limits.instructions`, `wall_ms`, `memory` and optionally `slice_us`. Set them for any key that isn't fully trusted ([configuration](configuration.md#limits)).
- **Long C++ calls can't be interrupted.** The instruction count hook only runs between Lua instructions. A bound function that blocks blocks the pump.
- **Undo covers recorded effects only.** RHP undoes variable writes, patches, timers, subscriptions, tasks and functions you gave an inverse (`Rhp::undo<>`). Functions marked `Rhp::irreversible` are reported, untagged functions are assumed pure, and admin standard-library side effects (files written, processes started) are not undone.
- **`RHP_ENABLE=OFF` for builds that must not accept code.** Enabled builds need their own deployment and distribution review.
- **Probing.** Idle unauthenticated connections count against `pending_handshakes` and can delay a resume. A probe can tell a known session id from an unknown one.

## Scheduling and events

- **Runaway pump-time work can't be cancelled from the network.** A timer, frame callback, event handler or task run by `pump()` (not by a client request) that never returns can only be stopped by limits (`instructions`, `wall_ms`, `slice_us`). Ending the identity's last session doesn't stop it either.
- **Tasks without waits hold the pump.** A task is cooperative. Without `rhp.sleep` / `rhp.wait` / `rhp.next_frame` / `rhp.wait_event`, or `limits.slice_us`, it runs until its per-resume budget stops it.
- **Script events stay in one identity.** `rhp.publish` reaches only the same key's sandbox. To bridge identities, forward in C++ with `host.on_script_event`.
- **Script event values are data.** No functions, userdata or handles. Delivery is one pump later, never synchronous.
- **Mistyped C++ event names aren't errors.** `rhp.on` with a name no C++ `lua_event` registered subscribes to script events of that name.
- **Event queues drop when full.** `limits.event_queue` (65,536 by default) caps queued events per sandbox. Extras are dropped and counted (`rhp.stats().dropped_events`), including `rhp.handler_failed` reports to Lua (C++ still gets `on_handler_error` and `handler_failed`).
- **Remote events are rate-limited, not backlog-limited.** `host_options::remote_events_per_pump` bounds what one pump sends a session. A session that stays disconnected, or stops reading, while busy events keep flowing still ends at its unacknowledged-bytes limit (64 MiB).
- **Remote event arguments are values.** A C++ event argument whose type has no `Rhp::convert` (a handle-only type) arrives at clients as nil.
- **No event stream over HTTP.** The HTTP gateway serves requests only. Use a native session (`client.on`, `rhp-cli events`) to watch events.
- **Tasks take the sandbox's error policy.** `rhp.spawn` has no options table. There is no `task:join(timeout)` yet.
- **Patch handlers always fault their module on error.** The handler error policy covers timers, frame callbacks, event handlers and tasks only.

## Binding and scripting

- **Lua 5.5 only, one script engine.** There is no second engine and no `config<>::engine<>` slot yet.
- **No class binding.** `Rhp::lib` binds functions, variables and opaque handles. Handles must be trivially copyable, equality-comparable, non-arithmetic value types. There is no inheritance or method binding.
- **Text chunks only.** Binary Lua chunks are always refused, for every role. Non-admin roles have no `io`, `os` (except `time` / `clock`), `debug`, `package`, `dofile`, `loadfile` or `collectgarbage`.
- **`require` finds loaded modules only.** It looks in the same identity's loaded modules, never the file system.
- **Single-threaded sandboxes.** Lua runs only on the thread that calls `pump()` (or the operation). Patch points hit from another thread run the C++ default.

## Networking

- **Session state doesn't survive a host restart.** Resume covers a dropped connection within `limits.resume_ms` (6 s by default). A restarted host starts fresh, and identities without pins are reverted when their last session ends.
- **Protocol revisions must match exactly.** Stage 7 speaks revision 4. Older hosts, clients and `rhp-cli` builds are refused at connect time.
- **`io<zero_threads>` stops the network inside a stuck script.** A zero-thread host whose script is stuck in `pump()` also stops serving the network, so cancel can't reach it.
- **Mbed TLS is serialized.** Its calls go through one process-wide lock, because its PSA core isn't thread-safe in the default build.
- **WebSocket isn't a browser endpoint.** It's a binary tunnel with RHP's own session (and TLS) inside, meant for proxies, not `wss://` browser clients.

## Platforms and validation

- **macOS / iOS haven't run on real hardware.** Hosted CI builds and tests them (except the cases below). The Apple DNS-SD backend has only been built.
- **Hosted CI leaves some tests out.**
  - Real multicast cases are skipped on hosted Windows and Apple runners.
  - On hosted macOS, the three cross-process `rhp-cli` ↔ `headless_server` tests fail (the spawned host stops listening after its first connection) and are excluded until someone debugs them on a Mac.
- **Validation is Debug only.** Recorded results are Debug builds. Release builds and long libFuzzer runs aren't part of the routine checks.
- **No benchmarks yet.** `Tests/bench` is planned.
