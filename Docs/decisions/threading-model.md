# Threading model

**Decision**
- Lua runs on the thread that calls `host.pump()` (`exec::pumped`).
- RHP owns one I/O thread (`exec::owned_io_thread`; alternatives are policies).
- Host request/reply traffic uses SPSC rings and cancel relays; queued Lua events and pending client results also use mutex-protected cross-thread state.
- Multiple hosts per process, no globals in hosts.
- Patch points and `lua_event`s use one process-wide registry.
- A patched point hit off the pump thread runs the C++ default and counts a miss.
- Stage 8: the host checks a script's Ed25519 signature on the network thread as the request arrives (about 0.1 ms each); `pump()` uses that verdict. `trusted_signers` is immutable once the host is built, so the check needs no lock. A custom `signer` policy's `trust::verify` runs there too and must be safe to call concurrently (`security/signer.hpp`). Requests that arrive through the HTTP gateway are the exception: their signatures are checked on the pump thread, in `pump()` (the gateway hands their bodies over unchecked).
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

**Stage 9:** an asynchronous binding's result may complete on any thread: the completing thread only stores it under the operation's lock and posts the call's `weak_ptr` to the sandbox's `async_inbox` (a mutex, never throws); `pump()` takes the inbox and wakes the request or settles the call. Calls are owned on the pump thread only, so `undo<G>` of an orphaned success runs there. A host's `async_leftovers` (calls of identities that closed) are pumped by `host.pump()`.

**Stage 8 review fixes:** a blocking client call (`get()`, `wait_for()`, `on` / `off`) made on the client's own network thread — inside a `then` callback, an `on` callback or a `co_await` continuation — reports `kInvalidArgument` (or `wait_for` returns false) instead of deadlocking on itself. A `zero_threads` client may be destroyed by a callback that its own `poll()` runs: the engine stays alive until `poll()` returns. A request resumed by `pump()` that reaches a patch handler, and event handlers fired synchronously by a checked request, are cancellable with that request (the cancel hook follows the checked run, not only operations).

**Stage 13a (as built):**
- `host.set_enabled(on)` (any thread) stores its flag at once (an atomic, release order), so `pump()` and the network thread see it on their next check: `pump()` runs no requests (answered `kDisabled`), handlers, tasks or release channels while it is off, and new connections are closed. The network's part (closing every session, native and HTTP, or dialing again in reverse mode) is posted to the network thread and runs there in the order the calls were made; the sessions' ends then reach `pump()` like any disconnect, which reverts the identities. If the post can't be made (out of memory) the flag still holds.
- Admission control for unauthenticated connections (`session::admission`) runs on the network thread only (its first-byte timer included); a host's native listener and its HTTP gateway share one, a listening client has its own.
- `limits.request_rate` and `pump_requests` are checked on the pump thread, when `pump()` takes a request from the inbox; the token bucket reads the host's clock there.

**Stage 13b (as built):**
- The device-key handshake runs on the network thread, the client's trust-on-first-use callback included (inside the handshake, before `limits.handshake_timeout_ms` ends it: it must not wait for a person). `known_hosts` is thread-safe and its copies share their entries.
- `release::manager::identities()` is a thread-safe set (it outlives the manager): the network thread asks it at every device-key handshake, the pump thread before running a script by a signer key.
- Operator CAs and revoked serials from a served manager's root are handed to the `certified` signer on the pump thread, after a `kTrust` request and at the next `pump()` after the app rotates the root itself.
