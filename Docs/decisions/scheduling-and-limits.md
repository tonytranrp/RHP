# Scheduling and limits

**Decision:** scripts run as coroutines and **run to completion** by default. Totals (instructions, memory, wall time) are unlimited unless configured. A count hook checks an atomic cancel flag every 1000 instructions; the I/O thread sets it on `cancel`, `revert_all` or disconnect. Time slicing (`limits.slice_us`) is opt-in.

**Why:** the user decided against slicing by default; the cancel flag keeps a runaway loop stoppable even while `pump()` is inside it.

**Alternatives:** 2 ms slicing by default (safer for frame time, rejected); slicing only REPL `exec` (rejected).

**Consequences**
- An infinite loop holds the pumping thread until cancelled — documented as a known trade.
- Optional limits are sticky so a script's own `pcall` can't swallow them.
- A count hook can't interrupt a long C++ call, so bound functions must return.
