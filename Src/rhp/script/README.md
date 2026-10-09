# script — layer 3

The script engine: PUC Lua 5.5 (built as C++), the `Rhp::lib<>` binding DSL, patch points, the undo ledger and the per-identity sandbox. Namespace `Rhp::script`; the DSL front (`Rhp::lib`, `Rhp::undo`, `Rhp::irreversible`, `Rhp::requires_role`, `Rhp::patch_point`, `Rhp::convertible`) is also reachable from `Rhp::`.

| Header | What |
|---|---|
| `lib.hpp` | `Rhp::lib<"name">::fn<>::var<>::ro<>::handle<>::sub<>` and the binding tags; names checked where written |
| `patch_point.hpp` | `Rhp::patch_point<"dotted.id", &default_fn>`: overridable call site, a direct call when `RHP_ENABLE=0` |
| `sandbox.hpp` | `Rhp::script::sandbox`: one identity's `lua_State`, modules (`_ENV` each), exec / load / call / revert / unload / checkpoint |
| `ledger.hpp` | `effect`, `ledger` (owner-keyed undo log), `revert_report` |
| `marshal.hpp` | `push` / `pull` between C++ and the Lua stack; `pushable`, `pullable`, `Rhp::convertible` |
| `stack.hpp` | `Rhp::script::stack`: the only wall between templates and the Lua C API (all out of line) |
| `stubs.hpp` | `stubs::generate<L>(role)` / `write<L>` / `rhp_api(role)`: LuaLS annotations from a lib type, filtered by role; no Lua needed |
| `detail/` | trampolines and lib builder, patch layers, variable layers, patch point registry, sandbox context |
| `puc_lua/` | the `.cpp` files that include `lua.h`, plus the private `sandbox_impl.hpp` |

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
