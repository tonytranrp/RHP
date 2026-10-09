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
