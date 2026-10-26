# script — layer 3

The script engine: PUC Lua 5.5 (built as C++), the `Rhp::lib<>` binding DSL, patch points, events, the undo ledger and the per-identity sandbox with its scheduler, tools and test hooks. Namespace `Rhp::script`; the DSL front is in `Rhp::` (`Rhp::patch_point`, `Rhp::lua_event`, `Rhp::convertible`) or re-exported there (`Rhp::lib`, `Rhp::undo`, `Rhp::irreversible`, `Rhp::requires_role`, `Rhp::range`, `Rhp::step`, `Rhp::unit`, `Rhp::doc`). Target `Rhp::script`; depends on `core`, privately on Lua. Usage: [exposing C++](../../../Docs/guide/exposing-cpp.md), [writing scripts](../../../Docs/guide/writing-scripts.md), [scheduling and events](../../../Docs/guide/scheduling-and-events.md), [tools](../../../Docs/guide/tools.md).

| Header | What |
|---|---|
| `lib.hpp` | `Rhp::lib<"name">::fn<>::var<>::ro<>::handle<>::method<>::property<>::sub<>`; binding tags `undo<G>`, `irreversible`, `requires_role<R>`; variable tags `range<Min, Max>` (enforced), `step<S>`, `unit<"m/s">`, `doc<"...">`; a function may return `Rhp::async<T>` (an asynchronous binding). Names are checked where written |
| `lua_event.hpp` | `Rhp::lua_event<"dotted.name", Args...>`: C++ `fire`s, scripts `rhp.on` / `rhp.once` / `rhp.wait_event`; sync on the sandbox's thread, queued otherwise; listeners outside Lua get the arguments as `Rhp::value`s |
| `patch_point.hpp` | `Rhp::patch_point<"dotted.id", &default_fn>`: an overridable call site (`rhp.patch`), a direct call when `RHP_ENABLE=0`; `depth()`, `patched()`, `off_thread_misses()` |
| `sandbox.hpp` | `sandbox`: one identity's `lua_State`, modules (`_ENV` per revision), requests (coroutines); `install<L>`, `exec` / `exec_cached` / `load` / `reload` / `rollback` / `call` / `revert` / `unload` / `checkpoint` / `revert_to` / `revert_all`, `cancel`, `pump`, `on_script_event`, `release_async`, `stats`, `stubs`, `api`, tunables, debugger, profiler and test hooks; `sandbox_options`, `handler_error_policy`, `module_info`, `handler_failure`, `async_leftovers` |
| `tunables.hpp` | `tunable_info` (path, type, writability, value, min / max / step / unit / doc), `path_matches` |
| `debug.hpp` | debugger types (`debug_stop`, `debug_frame`, `debug_variable`, `step_mode`, `debug_scope`) and profiler types (`profile_options`, `profile_stack`, `profile_report`) |
| `testing.hpp` | test tools (Stage 12): `run_meter` (exact instructions, allocations, peak, objects by kind), `coverage_report`, `gc_mode`, `testing_options` for `sandbox::enable_testing` (the `__rhp_test` bridge, a host callback, fake `os.time`) |
| `ledger.hpp` | `effect`, `ledger` (owner-keyed undo log), `revert_report` |
| `marshal.hpp` | `push` / `pull` between C++ and the Lua stack; `pushable`, `pullable`, `Rhp::convertible` |
| `stack.hpp` | `stack`: the only wall between templates and the Lua C API (all out of line): `run_protected`, `call`, push / to / check helpers |
| `api.hpp` | `api::describe<L>(role)`: a lib as a value tree (functions, variables, handles, sub-libs; LuaLS type names) for `sandbox::api()`, `rhp.api()` and test fakes; no Lua needed |
| `stubs.hpp` | `stubs::generate<L>(role)` / `write<L>` / `rhp_api(role)`: LuaLS annotations from a lib type, filtered by role; no Lua needed |
| `detail/` | trampolines and lib builder (`installable`), patch layers, variable layers (`var_layers`, `lock_free_var`), patch point and event registries, sandbox context |
| `puc_lua/` | the `.cpp` files that include `lua.h`, plus the private `sandbox_impl.hpp`, `builtins.hpp`, `tools.hpp`, `lua_internals.hpp`: `sandbox.cpp` (requests, faults, the frame, the `rhp` table), `schedule.cpp` (timers, frame callbacks), `script_events.cpp` (subscriptions, `rhp.publish`, `rhp.wait_event`, C++ listeners), `tasks.cpp` (`rhp.spawn`), `async.cpp` (asynchronous bindings), `lib_proxy.cpp` (locked lib proxies), `stack.cpp` (the Lua C API wall), `tools.cpp` (tunables), `profile.cpp` (the sampling profiler), `debug.cpp` (the debugger), `testing.cpp` (meter, coverage, the test bridge, `api()`), `lua_internals.cpp` (the one file besides the sandbox that reads Lua's internals: per-thread hook countdown, line events, prototypes and their lines) |

```cpp
float gravity = -9.81f;
void spawn(std::string_view kind, int n);
void despawn_last(std::string_view kind, int n);
using game_lib = Rhp::lib<"game">
    ::var<"gravity", &gravity, Rhp::range<-50.0, 0.0>, Rhp::unit<"m/s2">>
    ::fn<"spawn", &spawn, Rhp::undo<&despawn_last>>;

Rhp::script::sandbox box;
(void)box.install<game_lib>();
auto g = box.exec<double>("return game.gravity");                     // -9.81
auto mod = box.load("low_grav", "game.gravity = -1.6 game.spawn('crate', 2)");  // journaled
(void)box.unload(*mod);                     // despawn_last("crate", 2), then gravity is -9.81 again
auto bad = box.exec("game.gravity = 10");   // fails: outside Rhp::range, nothing written
```

## How a binding call flows

```text
Lua: game.spawn("crate", 1)
  → lib proxy __index → C closure call_fn<Handles, Entry> (upvalue: "game.spawn")
  → role check → pull args (handles first, then Rhp::convert) → invoke C++
  → C++ exceptions become Lua errors (raised after the try block)
  → ledger records undo<F>(result) for the current module → push results
  (an Rhp::async<T> result: the request suspends until it arrives, then the same steps)
```

## Requests and the frame

```text
exec / load / call ─▶ request (coroutine) ─▶ runs until done, error, rhp.wait/sleep, an async binding, or slice end
                                              │ suspended: the operation returns early
pump() ─▶ queued C++ events ─▶ queued script events ─▶ frame callbacks and due timers ─▶ arrived async results
       ─▶ ready requests: woken waiters, tasks, waits that ended (round robin, within slice_us)
       ─▶ faults · handler failures · cancels · deferred lifecycle operations · collected task handles
       ─▶ handler failure reports · script-event listeners · on_result callbacks
```

- A failing load or call faults its module; a scratch (exec) request reverts only its own effects.
- A failing handler (timer, frame callback, event handler, task) follows its `handler_error_policy`: `report` (default) undoes only that call's effects, `remove` also drops the handler, `fault` faults the module. A memory stop always faults. Patch handlers keep faulting.
- Every request's end goes through `request_ended` (from `complete` and `abandon_requests`): it releases waits, wakes joiners, finishes task records and clears the overlap guard of its schedule entry. Firing loops snapshot keys and look each one up again; a record is never written through a reference held across a Lua allocation (a collection can run finalizers that remove it). Finalizers that `lua_close` runs can't schedule, subscribe or spawn, and their effects are undone at once.
- A task never runs inside its spawner (it starts at the next pump) and its instruction and wall budgets reset on every resume. A suspended task is abandoned at once when cancelled; a running one is stopped through the cancel path.
- Lifecycle operations from inside a run are deferred to the end of the outermost operation.
- `sandbox_options::on_output` (print with its request and module), `on_result` and `sandbox::pending(request)` exist for `Rhp::host`, which answers network requests that suspended once `on_result` reports them.

## Rules

- `lua.h` / `lauxlib.h` / `lualib.h` only in `puc_lua/*.cpp` (and `Tests/bench` raw-Lua twins). Headers forward-declare `lua_State`.
- Lua is compiled as C++: errors throw. Never put `catch (...)` around Lua API calls; catch `std::exception` only and raise after the `try` block.
- Yields jump, errors throw (`cmake/lua/lua_cxx.cpp`, `RHP_LUA_JUMP_YIELDS`): a yield `_longjmp`s back to its `lua_resume`. With the MSVC ABI only on x64, never under TSan; a process with a CET shadow stack (an executable linked `/CETCOMPAT` on a CPU that has one; `RDSSP` decides once per process) throws instead (`rhp_script_cet_tests`). So a C function that calls `lua_yield` / `lua_yieldk` (itself or through a helper, `detail::yield_async` included) holds no C++ object with a destructor at that point: use `string_view`s into the Lua stack. The count hook's slice yield is fine (Lua jumps after the hook returns).
- Every Lua call made from C++ outside a running script goes through `stack::run_protected` (or `stack::call`), so an out-of-memory under a memory limit becomes an error, never a panic.
- The cancel hook traps every Lua instruction while armed: arm it only through `arm_hook` / `operation_scope` / `start_request` and `limits.cancel_checks` (`cancel_scope`); the profiler and the debugger change its count and mask through `rearm_all`. A count that isn't due is counted down inline (`rhp_lua_traceexec` in `cmake/lua/lua_cxx.cpp`, used by `lvm.c` only); due counts, line events and hook yields go through upstream's `luaG_traceexec`, so hook calls and the exact instruction meter are unchanged. That file spells out onelua.c's include list: keep it in step when Lua is updated (an `#error` on the release number says so).
- Scheduler caches (`sandbox_impl.hpp`): anything that can make a timer / frame callback due sooner sets `schedule_dirty_`, anything that can wake a suspended request sooner sets `requests_dirty_`; otherwise `pump()` skips it.
- Request records, map nodes and coroutines are pooled: `request_record::reset()` must keep resetting every field (its strings keep their buffers, so a call's label is built in place without `std::format`).
- Asynchronous bindings (`Rhp::async<T>`, `puc_lua/async.cpp`): a completing thread only posts to `async_inbox`; waking and settling happen in `pump()` on the sandbox's thread. A request waiting for one has `wait_kind::kAsync` and holds the call; a call whose request is gone goes to `detached_async_` until its result arrives (`drop_async`), and an `async_call` destroyed with an untaken success settles it (`async<T>::abandon()`): never drop one another way. Before destroying a sandbox that may have pending calls, hand them on with `release_async()` (the host does) and pump the returned `async_leftovers`.
- Effects that can be reverted out of order (variable writes, patch layers) live in process-wide per-target stacks (`detail/var_layers.hpp`, `detail/patch_layers.hpp`); the ledger only owns and orders them. A reverted write finds its layer from the newest end.
- Lib variables: RHP's reads, writes and undos of one variable are serialized by one lock per variable; a small trivially copyable one (`lock_free_var<T>`: `std::atomic_ref<T>` always lock-free and aligned) is read with an atomic load and written with an atomic store instead of taking the lock for reads. The application's own accesses are its own business.
- A sandbox and its Lua state belong to one thread (the one that calls `pump()`). Patch points may be hit from any thread; a layer owned by another thread is skipped (counted in `off_thread_misses()`). Events fired off that thread are queued (`limits.event_queue`).
- The debugger with breakpoints only turns line events on per function (`scope_lines`, `internals::set_line_events`): only functions whose lines hold a breakpoint get them, switched on call and return events, with the last answer cached by source and line range. A chunk named without `@` / `=` keeps them on; a step, a pause or coverage watch every line. Inspection never runs Lua.
- Test tools never change what a script does: metering credits instructions to budgets too, swaps of lib members are ledger effects, the `__rhp_test` bridge exists only in the scratch environment of a sandbox with `enable_testing`. `exec_cached` is for trusted sources only (bytecode is never checked).
- `RHP_ENABLE=OFF`: `puc_lua/` is not compiled, Lua is not fetched, `sandbox_disabled.cpp` reports `kDisabled`, patch points are direct calls, `lua_event::fire` is a no-op. The DSL, the ledger and `api::describe` still build.
