# Threading model

**Decision**
- Lua runs on the thread that calls `host.pump()` (`exec::pumped`).
- RHP owns one I/O thread (`exec::owned_io_thread`; alternatives are policies).
- Only SPSC rings and the cancel flag cross threads.
- Multiple hosts per process, no globals in hosts.
- Patch points and `lua_event`s use one process-wide registry.
- A patched point hit off the pump thread runs the C++ default and counts a miss.
- `lua_event` is synchronous on the pump thread, queued otherwise, fire-and-forget.
- The clock is injectable (`steady_clock` default).
- All engine allocations go through an injectable `std::pmr::memory_resource`.

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
