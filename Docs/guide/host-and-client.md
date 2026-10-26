# Host and client API

Both are templates over a [`Rhp::config<>`](configuration.md) (default: `Rhp::config<>`), implemented by type-erased engines compiled once, so the runtime engines are not instantiated for each configuration. Neither can be copied or moved.

## `Rhp::host<Cfg>`

```cpp
Rhp::host<> host{endpoint, authenticator, trusted_signers, Rhp::host_options{}};
Rhp::host<> observe_only{endpoint, authenticator}; // no signers: only observe sessions can run code
```

| Member | What |
|---|---|
| `install<Lib>()` | make a lib visible to every identity (call from the pump thread). `kAlreadyLoaded` on a duplicate name |
| `on_blob(sink, fn, role = admin)` | register a blob sink: `fn(const blob_view&) -> result<void>` runs on the pump thread once a whole blob (≤ `limits.max_blob`) has arrived. The role is checked before a byte is buffered |
| `serve(manager)` | serve a [`release::manager`](releases.md): clients may apply, confirm, deactivate and inspect releases, and `pump()` pumps it. The manager must outlive the host; `kAlreadyLoaded` if one is served already |
| `on<Event>(fn)` / `on_any(fn)` | subscribe to host events; returns a `[[nodiscard]] event::subscription` that unsubscribes when destroyed. Handlers run on the pump thread |
| `on_script_event(name, fn)` | every `rhp.publish` of `name` (`"*"`: all, `rhp.handler_failed` included) in any identity's sandbox, as an `event::script_event` (`identity`, `module`, `event`, `args`), on the pump thread |
| `pump()` | **call every frame.** Runs requests that arrived, resumes suspended scripts, fires timers and queued events, hands replies to the network. With `io<zero_threads>` it also polls the network |
| `port()` | bound network port after port 0, or a setup failure; IPC, dialing hosts and loopback report 0 |
| `gateway_port()` | the optional HTTP listener's bound port or setup error |
| `advertise(options)` / `discovery_status()` | explicit DNS-SD registration/update and subsequent provider errors; pump thread |
| `sessions()` / `identities()` | authenticated sessions, including detached resumable ones and HTTP logical sessions / identities with a live sandbox, including sessionless pinned ones (any thread) |
| `set_enabled(bool)` / `enabled()` | runtime kill switch: while off, new connections are closed and every request answers `kDisabled` (what already ran stays; send `revert_all` first to undo it) |
| `logger()` / `clock()` | references to policy objects; callers must synchronize mutation with their use by RHP |

Destroy the host on its application/pump thread after concurrent calls have stopped. Its destructor sends a goodbye (waiting briefly for delivery), stops and joins the I/O runner, then tears down identity sandboxes and pinned modules. Application objects referenced by bindings and undo callbacks must still be alive during that cleanup. Install libs and sinks before normal pumping; call `pump()` from one application thread.

A host can listen (`Rhp::endpoint::listen`) or dial out (`Rhp::endpoint::dial`, [reverse mode](connecting.md#reverse-mode)).

```cpp
auto registered = host.on_blob("configs", [](const Rhp::blob_view& b) -> Rhp::result<void> {
    return game::load_config(b.bytes); // b.sink, b.name, b.identity, b.bytes
});                                    // admin only unless you pass another role
// Check registered before accepting clients.
```

`blob_view` contains borrowed names and bytes valid only during the sink call. Copy data before keeping it or handing it to another thread. Blobs are explicit sink effects, not automatically undoable ledger entries. A slow sink blocks the pump thread.

### `Rhp::host_options`

| Field | Default | What |
|---|---|---|
| `idempotency_cache` | 256 | finished responses retained per session for idempotency-key retries (old entries are evicted) |
| `idempotency_bytes` | 16 MiB | byte cap on that cache |
| `inbox_capacity` | 4096 | messages the network thread queues for `pump()` before holding more back |
| `tls` | empty | `cert_pem` / `key_pem` for the host's certificate (empty = ephemeral self-signed), `ca_pem` / `server_name` to check the peer when the host dials |
| `gateway` | none | separate listen endpoint for the authenticated HTTP gateway |
| `http_require_binding` | false | refuse HTTP requests whose proof isn't bound to their TLS connection (`X-RHP-Channel: tls-exporter`) |
| `handler_errors` | `report` | what a failing timer, frame callback, event handler or task does in every identity's sandbox when the script sets no `on_error` |
| `remote_events_per_pump` | 256 | subscribed events sent to one session per `pump()`; the rest are dropped and the next event says how many |
| `ack_delay_ms` | 5 | how long a received frame's ack waits for an outgoing frame to carry it; 0 acks every read at once |

## `Rhp::client<Cfg>`

```cpp
Rhp::client<> c{endpoint, credential, signing_key, client_options{}}; // signs every script
Rhp::client<> o{endpoint, credential};                                // unsigned: observe sessions only
```

Get them from a checked identity-file result: `id->credential()` and `id->signer_key()` (an optional). Validate both before construction; the [complete client example](getting-started.md#first-run-host-plus-rhp-cli) shows this. With the default signing policy, a client without a signing key can send code only to an observe session.

[Networking and fleet](networking.md) shows discovery and `Rhp::fleet<Cfg>` execution, including its per-host result and deadline contracts.

Result-bearing operations return `Rhp::result<T>` by default (see [errors](configuration.md#error-mode)). The client connects on first use, or call `connect()` yourself.

| Call | Returns | Role |
|---|---|---|
| `exec(src [, chunk])` / `exec<T>(src [, chunk])` | all returned values / the first one converted to `T` (`chunk` names the code in tracebacks, default `exec`) | any (signed unless observe) |
| `load(name, src)` | `module_id` | patch |
| `call(mod, "fn", args...)` | returned values | observe at the request level; called bindings still enforce their own roles |
| `reload(mod, src)` | new `revision_id` | patch |
| `rollback(mod, n = 1)` | `revision_id` | patch |
| `revert(mod)` / `unload(mod, force = false)` | `revert_summary` | patch |
| `checkpoint(tag)` / `revert_to(tag)` | void / `revert_summary` | patch |
| `revert_all()` | `revert_summary` (every identity) | admin |
| `pin(mod)` / `unpin(mod)` | void | admin |
| `blob(sink, bytes, name)` | the sink's verdict | per sink (admin by default) |
| `list()` / `status(mod)` | `module_status` data | any |
| `describe()` | LuaLS stubs filtered by your role | any |
| `cancel()` / `cancel(request)` | stops everything in flight / one request | any thread |
| `on(name, fn)` / `off(id)` | subscribe to host events: a C++ `lua_event` of that name, or an `rhp.publish` of this identity (`"*"`: every publish); `fn` gets a `remote_event` (`name`, `module`, `args`, `dropped`) on the network thread | observe |
| `info()` / `connected()` | `session_info {connected, closed, session, identity, granted, host_platform, tls, resumes}` / whether a session is up | |
| `connect()` / `port()` | connect and authenticate now (otherwise the first call does) / in reverse mode, start listening and return the port | |
| `poll()` | with `io<zero_threads>`: handle whatever the network has ready, without blocking (no-op with an I/O thread) | |
| `tunables(prefix)` / `tune(path, value)` | list the host's lib variables with their tags / write one as a script would ([tools](tools.md#tunables)) | observe / patch |
| `profile(action, interval)` | the sampling profiler: `"start"`, `"read"` or `"stop"` ([tools](tools.md#profiler)) | observe |
| `debug(request)` | the debugger: breakpoints, pause, steps, stacks, variables ([tools](tools.md#over-the-wire)) | patch |
| `release_apply(envelope, confirm)` / `release_confirm(channel)` / `release_deactivate(channel, hold)` | run a signed release on a host that [serves a manager](releases.md) | admin |
| `release_status()` / `revoke(envelope)` | what the host's channels run / send a signed revocation list | observe |

`mod` is a `module_id` or name (`"low_grav"`) within this identity. `exec<T>` converts the first returned value, or nil if none; untyped `exec` and `call` return a `value_list`. Remote load/reload/call replies wait for suspended Lua to finish. `revert_summary::clean()` checks undo failures, not the `irreversible` count; inspect both before asserting full restoration.

### Async

`c.async()` provides exec, load, call, reload, rollback, revert, unload, list, status and describe as `Rhp::pending<T>`; checkpoint, revert_to, revert_all, pin / unpin, blob, on / off and cancel are blocking-only client methods. `pending` also has `request()`, `ready()` and `wait_for(ms)`; `c.exec_async<T>(src, fn)` starts an exec and calls `fn` with its result. Choose one consumer for each result: `.get()`, `.then()`, `.future()` or `co_await`.

```cpp
auto p = c.async().exec<int>("return game.tick");
const auto request = p.request(); // save before moving the handle
// c.cancel(request);                        // ask the host to stop this call
auto result = std::move(p).get(); // waits; expected<int, error> by default
```

Independent calls can use a callback or future:

```cpp
c.async().exec<int>("return game.tick").then([](Rhp::result<int> result) {
    if (!result) {
        std::println(stderr, "{}", result.error());
    }
});
auto future = c.exec_future<int>("return game.tick");
auto result = future.get(); // expected<int, error>; int in throwing mode
```

These fragments need `<cstdio>`, `<print>` and the client headers. Callback arguments are always `result<T>`, including under `errors::throwing`; `.get()`, future consumption and `co_await` follow the chosen error mode.

Completion normally runs on the client's network thread. If a result is already ready when `.then()` is registered, the callback runs immediately on the registering thread. With `zero_threads`, progress happens inside `poll()`, client calls or `pending::get()` / `wait_for()`. A `std::future` does not pump zero-thread I/O by itself: poll elsewhere while waiting for it.

Do not block on the same client, destroy it, or directly mutate GUI/game state from a completion callback. Queue an owning result to the application's thread; captured objects must outlive completion. Handle exceptions inside the callback.

Inside an existing coroutine:

```cpp
auto result = co_await c.async().exec<int>("return game.tick");
```

RHP supplies an awaiter, not a coroutine task type. Destroying a suspended awaiting coroutine unregisters it (the result is then kept, not delivered); it must not race with that call's completion on the network thread. Cancellation is a request to stop work, not synchronous completion.

### `Rhp::client_options`

| Field | Default | What |
|---|---|---|
| `connect_timeout` | 10 s | handshake wait (in reverse mode: waiting for a host to dial in) |
| `request_timeout` | 0 | per-call reply wait; 0 = until reply or session end |
| `on_output` | none | every `print()` line, with its request id (network thread; keep it short, never call the client from it) |
| `on_emit` | none | every `rhp.emit(value)` with request and module |
| (events) | | `client.on(name, fn)` callbacks follow the same thread rules as `on_output` |
| `blob_chunk` / `blob_window` | 1 MiB / 4 | blob chunk size and chunks in flight |
| `ack_delay_ms` | 5 | how long a received frame's ack waits for an outgoing frame to carry it; 0 acks every read at once |
| `tls` | empty | `ca_pem` + `server_name` to check the host's certificate; `cert_pem` / `key_pem` when the client listens (reverse mode) |

### Thread rules

- Default `io<owned_io_thread>`: blocking calls can come from application threads; `cancel()` can run while another thread waits. Join those callers before destroying the client. Never make a blocking call from its network-thread callbacks.
- `io<zero_threads>`: single-threaded. Call `poll()` at least once per heartbeat (2 s) while idle or the host drops the session.
- A client destructor closes the session gracefully; the host performs final identity cleanup in its next pumps. A broken connection may first detach and resume, so link loss does not imply immediate revert.
- If host and client share an application thread, avoid blocking calls while that thread is responsible for `host.pump()`. Use `client.async()` and alternate `host.pump()` with client I/O progress:

```cpp
using local_cfg = Rhp::config<>::transport<Rhp::net::loopback>::io<Rhp::exec::zero_threads>;

Rhp::host<local_cfg> host{Rhp::endpoint::listen("game", 1), keys, signers};
Rhp::client<local_cfg> tool{Rhp::endpoint::dial("game", 1), id.credential(), *id.signer_key()};
auto tick = tool.async().exec<int>("return game.tick");
while (!tick.ready()) {   // one thread: the host and the client each make progress in turn
    host.pump();
    tool.poll();
}
auto result = std::move(tick).get();
```

The first call connects through the same turns. `Tests/bench/bench_e2e.cpp` drives a host and a client this way. Add a deadline in real code: a call that can't finish (a host that stopped pumping) otherwise loops forever.

## Events and audit

Events are published on the pump thread. Subscribe with `host.on<E>(fn)` or `host.on_any(fn)`:

`session_opened`, `session_resumed`, `session_closed`, `auth_failed`, `script_executed`, `blob_received`, `identity_reverted`, `handler_failed`, and `release_changed` from a served release manager (fields in the [reference](reference.md#host-events)). Script events are not host events: subscribe to them with `on_script_event`.

```cpp
auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"}); // JSON lines, flushed per line
auto execs = host.on<Rhp::event::script_executed>(Rhp::audit::file_sink{"scripts.log"});
auto stream = host.on_any(Rhp::audit::ostream_sink{std::clog});
auto mine = host.on<Rhp::event::session_opened>([](const auto& e) { /* ... */ });
```

`script_executed` is emitted for every request that runs code or changes state (exec, load, reload, rollback, call, revert, unload, checkpoint, revert_to, revert_all, pin, unpin), including refused ones, with the BLAKE2b-256 hash of the source and who signed it.

Keep each returned subscription alive for the desired observation period; an immediately destroyed subscription unsubscribes. `file_sink::ok()` reports open/write failure, so check it at startup and when audit availability matters. `ostream_sink` borrows its stream, which must outlive the subscription. A callback already executing when unsubscribed may finish. A thrown event-handler exception is caught and logged; remaining handlers in that publication are not guaranteed to run.

`script_executed` for a request that suspended is published when it finishes, with its final outcome (or `cancelled` when its identity is torn down first). Hash and signer fields are populated for new-source operations; `call`, rollback and cleanup operations do not carry new signed source. Subscribing and unsubscribing (`client.on` / `off`) are not audited.

### Watching events from a client

```cpp
auto id = client.on("game.round_over", [](const Rhp::remote_event& e) {
    // network thread: e.name, e.module (0 for a C++ event), e.args, e.dropped
});
// ... client.off(*id);
```

The first callback for a name subscribes on the host; the last `off` unsubscribes. Subscriptions belong to the session: they survive a resume and end with it (a reverse-mode client subscribes again for the next host). Past `host_options::remote_events_per_pump` per pump the host drops deliveries and the next one's `dropped` says how many. That bounds the rate, not the backlog: deliveries are sequenced frames, so a session that stays detached or stops reading while events keep flowing still ends at the session's unacknowledged-bytes limit. Subscribe to events of a modest rate. `rhp-cli` has `subscribe <event>` / `unsubscribe <event>` and `rhp-cli events <name>...`. The HTTP gateway has no event stream.
