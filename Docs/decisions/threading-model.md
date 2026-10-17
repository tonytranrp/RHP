# Threading model

**Decision**
- Lua runs on the thread that calls `host.pump()` (`exec::pumped`).
- RHP owns one I/O thread (`exec::owned_io_thread`; alternatives are policies).
- Host request/reply traffic uses SPSC rings and cancel relays; queued Lua events and pending client results also use mutex-protected cross-thread state.
- Multiple hosts per process, no globals in hosts.
- Patch points and `lua_event`s use one process-wide registry.
- A patched point hit off the pump thread runs the C++ default and counts a miss.
- `lua_event` is synchronous on the pump thread, queued otherwise, fire-and-forget.
- The clock is injectable (`steady_clock` default).
- Current injection covers a standalone sandbox's Lua allocator and explicitly constructed `utils::byte_buffer`s. Other C++ containers/effects use their normal allocators; host-wide memory-resource injection is not implemented.

**Why:** game and GUI code must only be touched on its own thread; Lua states are single-threaded; mobile cores stay portable when threads live at the edges.

**Alternatives:** marshal patch-point calls to the pump thread (deadlock risk), RHP-owned script thread (bound functions would need to be thread-safe).

**Consequences:** `spsc_ring` is the one hand-rolled lock-free structure and is covered by a TSan preset.

**Stage 1 (as built):** patch layers are pushed, removed and invoked only on their owner thread. A call picks the highest layer owned by the calling thread under the point's mutex and invokes it unlocked; layers of other threads are skipped and counted in `off_thread_misses()`. While nothing is patched a call is one acquire load.

**Stage 2 (as built):** a sandbox's thread is the one that created it or last called `pump()`. `Rhp::lua_event::fire` on that thread delivers synchronously; from any other thread it copies the arguments into the sandbox's inbox (mutex) for the next `pump()`. `cancel(request)` goes through the same mutex; `cancel()` stays a single atomic flag.

**Stage 3 (as built)**
- `exec::owned_io_thread` (default) runs the host's or client's `net::io_context` on one `std::jthread`; `exec::zero_threads` runs no thread: `host.pump()` polls the network before and after its work, and a blocking client call runs it while it waits (so a zero_threads client is single-threaded, and a script stuck in a zero_threads host's `pump()` also stops its network).
- Host: the network thread owns sessions; `pump()` owns sandboxes. They exchange messages through two `utils::spsc_ring`s (network → pump requests, pump → network replies) with a small backlog on each side when a ring is full.
- The one other crossing is a per-identity cancel relay (a mutex and a sandbox pointer cleared before the sandbox dies): the network thread uses it to cancel the request running inside `pump()` — the escape hatch for a runaway loop — and suspended ones, and to stop an identity's scripts when its last session drops.
- Client: callers block on a condition variable (or poll, with zero_threads); the network thread fills reply slots and calls `on_output` / `on_emit`.
- Loggers are called from both threads under a mutex.

**Stage 3 review fixes:** `utils::spsc_ring::try_push` now moves its argument only when there is room (by-value pushes destroyed the item a full ring refused). Cancels are recorded in the relay and re-applied from a 20 ms network-thread timer, so none is lost to timing. Cross-thread posts (the loopback transport) go through `net::io_context::poster`, which refuses once the context shuts down. The loopback pump hands over at most 64 buffers per turn. A `zero_threads` client must `poll()` between calls.

**Stage 4 (as built):** host events are published on the pump thread through a thread-safe hub (handlers run outside its lock; subscribe / unsubscribe from any thread). Blob sinks run on the pump thread. Client async results (`Rhp::pending`: `then` callbacks, `co_await` resumptions, futures) normally complete on the client's network thread — or inside `poll()`, a blocking call or `pending::get()` with `io<zero_threads>`. Registering `then` after completion invokes it immediately on the registration thread; an already-ready await continues on its calling thread. `rhp-cli`'s `watch` uses one extra thread that makes blocking calls on the client.

**Stage 5 (as built):** TLS engines run on the network thread inside the links. Mbed TLS calls are serialized by one process-wide lock (its PSA core isn't thread-safe in the default configuration); OpenSSL needs none.

**Stage 6 (as built):** a fleet runs every member's client engine on one `net::io_context`: one I/O thread for the fleet with `exec::owned_io_thread`, none with `exec::zero_threads` (its broadcasts, `discover()` and `poll()` run the reactor on the caller's thread). Broadcast outcomes are collected under a mutex and condition variable. An engine on a shared reactor is destroyed on that reactor's thread (or once it stopped); its queued posts and dial completions check a liveness token, so none touches it afterwards.

**Stage 7 (as built):** script events (`rhp.publish`) never cross threads: they are queued and delivered on the sandbox's thread at its next pump. `sandbox::on_script_event` callbacks and `on_handler_error` run on the sandbox's thread at the end of the operation or pump (a failure in a game-code event delivery is reported at the end of that delivery). The host engine is itself a `lua_event` listener for remote subscriptions: fires on the pump thread go straight to the subscribed sessions, fires from other threads queue under the engine's `program_mutex_` (taken inside the event's own mutex; attach and detach never run under it) for the next pump. `client.on` callbacks run on the client's network thread, outside its lock.
