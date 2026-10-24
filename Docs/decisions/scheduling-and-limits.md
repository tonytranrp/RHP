# Scheduling and limits

**Decision:** scripts run as coroutines and **run to completion** by default. Totals (instructions, memory, wall time) are unlimited unless configured. A count hook checks an atomic cancel flag every `limits.cancel_check_instructions` (1000) instructions; the I/O thread sets it on `cancel`, `revert_all` or disconnect. Time slicing (`limits.slice_us`) is opt-in.

**Why:** the user decided against slicing by default; the cancel flag keeps a runaway loop stoppable even while `pump()` is inside it.

**Alternatives:** 2 ms slicing by default (safer for frame time, rejected); slicing only REPL `exec` (rejected).

**Consequences**
- An infinite loop holds the pumping thread until cancelled — documented as a known trade.
- Optional limits are sticky so a script's own `pcall` can't swallow them.
- A count hook can't interrupt a long C++ call, so bound functions must return.

**Stage 1 (as built)**
- Stops (cancel, instruction budget, memory) apply to runs: `exec`, `load`, `call` and the patch handlers they trigger. Handlers hit from game code outside a run aren't limited until the Stage 2 scheduler.
- Once a stop fires, the count hook switches to every instruction on the running thread and the main thread. A script that keeps re-entering `pcall` can otherwise swallow a stop that only fires every 1000 instructions.
- The memory limit covers the whole `lua_State` (allocator over `std::pmr`); growth is refused for the rest of the run once it's hit, and Lua's emergency GC reclaims afterwards.
- `cancel()` while nothing runs is a no-op: each run clears the flag when it starts.

**Stage 2 (as built)**
- Every exec / load / call, timer callback and event handler is a request coroutine with its own budget (instructions and wall time summed over its resumes). Scripts suspend with `rhp.wait(n)` (pump calls), `rhp.next_frame()`, `rhp.sleep(ms)` (injectable clock) or a plain `coroutine.yield()`; an operation whose request suspends returns early and reports through `on_result`.
- Time slicing stays opt-in (`slice_us`). Each operation, each `pump()` and each synchronous event delivery gets one slice; the count hook yields only the request's own thread when it is yieldable. `pump()` resumes ready requests round robin and stops when its slice is spent.
- `cancel()` stops the running request(s); `cancel(request)` stops one request, running or suspended. Either faults per the fault policy (a scratch request reverts only its own effects). Timers are ledger effects: revert / unload removes them.
- Patch handlers that game code triggers are small runs of their own: cancel, instructions and `wall_ms` (errc `kTimeout`) apply per call.

**Stage 7 (as built):** timers and frame callbacks are one schedule entry kind (`rhp.after`, `rhp.every`, `rhp.every_frame(s)`, `times`, pause / resume / reschedule, `rhp.timers()`); a repeating entry never starts a call while its previous one is suspended. A `pump()` delivers queued C++ events, then queued script events, fires frame callbacks and due timers, then resumes ready requests (waits that ended, woken waiters and joiners, tasks). `rhp.spawn` tasks are requests of their own that start at the next pump; their instruction and wall budgets reset on every resume (memory stays per state). `limits.event_queue` caps each sandbox's queued events. A failing handler follows `handler_error_policy` instead of the fault policy ([Stage 7 decisions](stage7-scheduling-events.md)).
