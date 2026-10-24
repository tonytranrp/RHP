# script — layer 3

The script engine: PUC Lua 5.5 (built as C++), the `Rhp::lib<>` binding DSL, patch points, the undo ledger and the per-identity sandbox. Namespace `Rhp::script`; the DSL front (`Rhp::lib`, `Rhp::undo`, `Rhp::irreversible`, `Rhp::requires_role`, `Rhp::patch_point`, `Rhp::convertible`) is also reachable from `Rhp::`.

| Header | What |
|---|---|
| `lib.hpp` | `Rhp::lib<"name">::fn<>::var<>::ro<>::handle<>::sub<>` and the binding tags; names checked where written |
| `lua_event.hpp` | `Rhp::lua_event<"dotted.name", Args...>`: C++ fires, scripts `rhp.on` / `rhp.once` / `rhp.wait_event`; sync on the sandbox thread, queued otherwise; listeners outside Lua get the arguments as `Rhp::value`s |
| `patch_point.hpp` | `Rhp::patch_point<"dotted.id", &default_fn>`: overridable call site, a direct call when `RHP_ENABLE=0` |
| `sandbox.hpp` | `Rhp::script::sandbox`: one identity's `lua_State`, modules (`_ENV` per revision), requests (coroutines), exec / load / reload / rollback / call / revert / unload / checkpoint, pump; `handler_error_policy`, `on_script_event`, `stats` |
| `ledger.hpp` | `effect`, `ledger` (owner-keyed undo log), `revert_report` |
| `marshal.hpp` | `push` / `pull` between C++ and the Lua stack; `pushable`, `pullable`, `Rhp::convertible` |
| `stack.hpp` | `Rhp::script::stack`: the only wall between templates and the Lua C API (all out of line) |
| `stubs.hpp` | `stubs::generate<L>(role)` / `write<L>` / `rhp_api(role)`: LuaLS annotations from a lib type, filtered by role; no Lua needed |
| `detail/` | trampolines and lib builder, patch layers, variable layers, patch point and event registries, sandbox context |
| `puc_lua/` | the `.cpp` files that include `lua.h`, plus the private `sandbox_impl.hpp` / `builtins.hpp`: `sandbox.cpp` (requests, faults, the frame), `schedule.cpp` (timers, frame callbacks), `script_events.cpp` (subscriptions, `rhp.publish`, `rhp.wait_event`, C++ listeners), `tasks.cpp` (`rhp.spawn`), `lib_proxy.cpp` (locked lib proxies), `stack.cpp` (the Lua C API wall) |

## How a binding call flows

```text
Lua: game.spawn("crate", 1)
  → lib proxy __index → C closure call_fn<Handles, Entry> (upvalue: "game.spawn")
  → role check → pull args (handles first, then Rhp::convert) → invoke C++
  → C++ exceptions become Lua errors (raised after the try block)
  → ledger records undo<F>(result) for the current module → push results
```

## Rules

- `lua.h` / `lauxlib.h` / `lualib.h` only in `puc_lua/*.cpp`. Headers forward-declare `lua_State`.
- Lua is compiled as C++, so Lua errors unwind as C++ exceptions. Never put `catch (...)` around Lua API calls; catch `std::exception` only and raise after the `try` block.
- Every Lua call made from C++ outside a running script goes through `stack::run_protected` (or `stack::call`), so an out-of-memory under a memory limit becomes an error, never a panic.
- Effects that can be reverted out of order (variable writes, patch layers) live in process-wide per-target stacks (`detail/var_layers.hpp`, `detail/patch_layers.hpp`); the ledger only owns and orders them.
- A sandbox and its Lua state belong to one thread. Patch points may be hit from any thread; a layer owned by another thread is skipped (counted in `off_thread_misses()`).
- `RHP_ENABLE=OFF`: `puc_lua/` is not compiled, Lua is not fetched, `sandbox_disabled.cpp` reports `kDisabled`, patch points are direct calls. The DSL and the ledger still build.

## Requests and the frame

```text
exec / load / call ─▶ request (coroutine) ─▶ runs until done, error, rhp.wait/sleep, or slice end
                                              │ suspended: the operation returns early
pump() ─▶ queued C++ events ─▶ queued script events ─▶ frame callbacks ─▶ due timers
       ─▶ ready requests: woken waiters, tasks, waits that ended (round robin, within slice_us)
       ─▶ faults · handler failures · cancels · deferred lifecycle operations · collected task handles
       ─▶ handler failure reports · script-event listeners · on_result callbacks
```

- A failing load or call faults its module; a scratch (exec) request reverts only its own effects.
- A failing handler (timer, frame callback, event handler, task) follows its `handler_error_policy`: `report` undoes only that call's effects, `remove` also drops the handler, `fault` faults the module. A memory stop always faults. Patch handlers keep faulting.
- Every request's end goes through `request_ended` (from `complete` and `abandon_requests`): it releases waits, wakes joiners, finishes task records and clears the overlap guard of its schedule entry. Firing loops snapshot keys and look each one up again; a record is never written through a reference held across a Lua allocation (a collection can run finalizers that remove it). Finalizers that `lua_close` runs can't schedule, subscribe or spawn, and their effects are undone at once.
- A task never runs inside its spawner (it starts at the next pump) and its instruction and wall budgets reset on every resume. A suspended task is abandoned at once when cancelled; a running one is stopped through the cancel path.
- Lifecycle operations from inside a run are deferred to the end of the outermost operation.
- `sandbox_options::on_output` (print with its request and module) and `sandbox::pending(request)` exist for `Rhp::host`, which answers network requests that suspended once `on_result` reports them.
