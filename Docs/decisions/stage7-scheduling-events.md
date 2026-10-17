# Stage 7 scheduling and events decisions

Usage: [writing scripts](../guide/writing-scripts.md) and [host and client](../guide/host-and-client.md). Stage 7 lets a script keep working, and react, without a client request held open: frame callbacks and timer control, background tasks, events scripts define themselves, a way for C++ and remote clients to hear them, and handler failures that don't take a whole module down. Decision ids AF* are in [ARCHITECTURE.md](../ARCHITECTURE.md) §33.

The motivating use was a real embedding: a host inside a game process whose scripts kept a menu alive by holding a client session open for hours, polled every frame with `while true do rhp.wait(1) end`, and wrapped every handler in `pcall` because one error faulted the whole module.

## Schedule

- **What:** timers and frame callbacks are one schedule entry kind with two clocks (the script clock, the `pump()` count). `rhp.after`, `rhp.every`, `rhp.every_frame(s)`, the `times` option, `rhp.pause` / `rhp.resume` / `rhp.reschedule` and `rhp.timers()`. `rhp.timer` keeps its signature.
- **Why:** one code path for firing, overlap, retirement and introspection; frame callbacks are the common game case and were a coroutine loop before.
- **Alternatives:** separate frame and timer records (duplicate firing logic); a coroutine-based `rhp.every_frame` in Lua (no pause, no listing, a request per callback anyway).
- **Consequences:** a repeating entry never starts a call while its previous call is suspended. A callback that waits now skips the frames it waits through, where before calls piled up. Entries made during a pump fire at the next one at the earliest, so `rhp.after(0, again)` runs once per pump, never in a loop. Each call is still its own request with its own budget.

## Tasks

- **What:** `rhp.spawn(fn, ...)` is a request of its own, started at the next `pump()`, owned by the spawning module and the request that spawned it. The handle has `status`, `cancel`, `join` and `id`. Instruction and wall limits apply per resume.
- **Why:** a long-running loop no longer needs a client request held open, and it dies with its module through the ledger like every other effect.
- **Alternatives:** starting the task inside the spawner, which would charge the spawner's budget and run tasks while a module is still loading; lifetime budgets, which would kill every background loop eventually.
- **Consequences:** a task spawned by a failed exec, or by a handler that failed under `report`, is cancelled with that call's other effects. Tasks of pinned modules survive their session. `join` uses Lua continuations, so it works inside `pcall`. A suspended task is cancelled at once and its to-be-closed variables close. A task that cancels itself stops at the next hook tick. A runaway task with no waits still holds `pump()` unless `limits.slice_us` is set.

## Script events

- **What:** `rhp.publish(name, ...)` queues copies for the next `pump()` of the same sandbox (the same identity). `rhp.on`, `rhp.once` (with `priority`) and `rhp.wait_event` take script and C++ event names alike. `limits.event_queue` bounds both queues and drops are counted.
- **Why:** modules of one identity talk without `require` cycles or shared globals; queuing avoids re-entrant handler chains and keeps the publisher's budget its own.
- **Alternatives:** synchronous delivery (recursion, nested resumes, handlers charged to the publisher); cross-identity delivery (a security boundary change: the host can forward through C++ if an application wants it).
- **Consequences:** up to one pump of latency. A name a C++ `lua_event` uses always means that event, and scripts can't publish it or `rhp.` names. Subscribing to an unknown name is now a script subscription rather than a `kNotFound` error, so a mistyped C++ event name goes unnoticed. Values must convert to `Rhp::value` (no functions, userdata or handles).

## Waiting for an event

`rhp.wait_event(name [, timeout_ms])` returns `true, ...` or `false, "timeout"`. A shape like `args...` / `nil, "timeout"` can't tell an argument-less event or a leading nil from a timeout. A waiter attaches the sandbox to a C++ event as a subscription would, and detaches when it resumes, times out or is abandoned. Delivery comes before the resume pass in `pump()`, so an event and its timeout in the same pump resolve as the event.

## C++ and remote listeners

- **What:** `sandbox::on_script_event` and `host.on_script_event` (every identity) return a subscription. `client.on(name, fn)` subscribes through the protocol (`kSubscribe` / `kUnsubscribe` / `kEvent`, revision 4) to the host's C++ events or the client's identity's script events.
- **Why:** applications react to scripts, and tools watch a running game, without loading a script that forwards events over `rhp.emit`.
- **Alternatives:** putting script events in `event::any` (audit sinks would log every application event); a separate stream connection for events (a second authentication path).
- **Consequences:** `Rhp::subscription` moved from `event` to `core` (with `Rhp::subscribable`), and `event::subscription` is an alias. The host engine implements `event_listener` itself, attaching only while a session wants a C++ event and detaching when the session closes or the engine stops. Because subscriptions belong to the host session, they survive a resume. A reverse-mode client subscribes again for a new host session. `host_options::remote_events_per_pump` bounds what one pump sends a session: extra deliveries are dropped and the next one reports how many. Deliveries are sequenced frames, so this bounds the rate, not the backlog: a session that stays detached (or stops reading) while events keep flowing still reaches the session's unacknowledged-bytes limit and ends. Keep subscriptions to events of a modest rate. The HTTP gateway has no event stream. Revision-3 peers are refused at hello.

## Handler errors

- **What:** `handler_error_policy` is `report` (the default), `remove` or `fault`. It applies per handler (`{on_error = ...}`), per sandbox and per host. A failure is reported through `on_handler_error`, through `event::handler_failed` on a host, and through `rhp.handler_failed` / `rhp.on_error`.
- **Why:** one failing callback used to revert the whole module, so real scripts wrapped every handler in `pcall`.
- **Alternatives:** keeping `fault` as the default (no behaviour change, but every embedder would have to opt in); reporting without undoing (a half-applied handler's effects would stay live).
- **Consequences:**
  - `report` undoes exactly what the failed call did, as a failed exec undoes its own effects. The handler stays, so a handler that fails every time is reported every time; `remove` is the fix for that.
  - A memory stop always faults, because the state's memory is shared.
  - Patch handlers keep faulting their module: they replace C++ behaviour, which then falls back to the default.
  - Tests that relied on handler faults now pin `handler_error_policy::kFault`.
  - In the scratch module (exec) `fault` behaves like `report`: scratch failures only ever undo their own request.
  - A task stopped by `sandbox::cancel(request)` (not `task:cancel()`) is a failure with code `cancelled`, and is reported.
  - `rhp.handler_failed` events go through `limits.event_queue` like any script event and can be dropped with it; `on_handler_error` and the host event always fire.
  - Tasks take the sandbox's policy: `rhp.spawn`'s varargs leave no room for an options table.
