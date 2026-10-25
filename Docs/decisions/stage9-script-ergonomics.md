# Stage 9: asynchronous bindings and methods on handles

**Status:** implemented (branch `stage-9-async-methods`). ARCHITECTURE §35 (AH1–AH9).

Stage 9 makes the C++ side of a script API read like the Lua side: a binding may finish later without blocking the game, and a handle carries its own methods and properties.

## Asynchronous bindings (AH1–AH6)

**Decision.** A binding that returns `Rhp::async<T>` suspends the calling script until the result arrives:

```cpp
Rhp::async<texture> load_texture(std::string path) {
    auto [later, done] = Rhp::make_async<texture>();
    loader_pool.post([done, path] { done.complete(read_texture(path)); });
    return std::move(later); // a structured binding is not moved implicitly
}
using game_lib = Rhp::lib<"game">::fn<"load_texture", &load_texture, Rhp::undo<&unload_texture>>;
```

```lua
local tex = game.load_texture("ui/icons.png") -- the request waits; the game keeps running
```

- **AH1 — one core type pair.** `Rhp::async<T>` (the reading side: move-only, `ready()`, `take()`, `request_stop()`, `abandon()`, `async<T>::completed(result)`) and `Rhp::promise<T>` (copyable, any thread, the first `complete()` wins, `stop_requested()` / `stop_token()`), made by `Rhp::make_async<T>()`. They live in `core/async.hpp` (layer 1, no Lua) so producers don't depend on the script engine. When the last promise copy is dropped without completing, the reader gets `kRuntime` (or `kCancelled` once a stop was requested): a forgotten promise can't leave a script waiting forever.
- **AH2 — the request suspends, the pump resumes it.** The binding's trampoline calls the function, hands the `async` to the sandbox (`context::await_async`) and yields the request's coroutine with a continuation (`lua_yieldk`). The completing thread only posts the call to a mutex-guarded inbox; `pump()` wakes the request (between the schedule and the resume pass) and the continuation pushes the result or raises its error at the call site, so `pcall` works as for any binding. A result that is already there finishes without a yield.
- **AH3 — only a script's own thread can wait.** The same rule as `rhp.wait`: a patch handler, `on_save` / `on_restore` / `on_unload`, a coroutine the script created or a callback of a C function (`table.sort`) gets `kInvalidArgument` *before* the binding runs, so nothing starts that nobody can receive.
- **AH4 — effects are journaled when the result arrives.** `undo<G>` takes the result (or copies of the arguments, kept across the wait); `irreversible` is counted. A failed result records nothing.
- **AH5 — a result nobody receives is taken back.** When the request goes away first (cancel, unload, a handler's module going, `limits.async_ms`), the sandbox calls `request_stop()` and keeps the call; when its success arrives, `undo<G>` runs at the next `pump()` (`sandbox_stats::async_compensated`; a binding without an undo counts in `async_dropped`). Giving up is atomic (`async<T>::abandon()`): whoever drops a call either takes back the success that already arrived or makes every later `complete()` return `false`, so no path loses a success. A sandbox about to close hands its pending calls over (`sandbox::release_async()` -> `script::async_leftovers`): the host keeps an identity's after a disconnect and settles them in `pump()`. Only when nobody keeps them does `complete()` return `false` and the producer clean up. `G` may run after the module's other effects were undone, so it must tolerate stale state.
- **Review fixes:** borrowed views inside tuple / pair results don't compile; properties return one value (no tuple, async or void); the inbox's `post()` can't throw (an out-of-memory arrival sets an overflow flag and the next pump looks at every call); a moved-from promise is inert; the first handle name of a C++ type stays the one events push it as; async methods are `async fun(...)` in stubs; `async<T>::ready(result)` was renamed `completed(result)` (it read like the member `ready()`).
- **AH6 — limits.** Waiting costs no instructions and no wall time. `limits.async_ms` (script clock, 0 = none) bounds the wait; the script then gets `kTimeout`.

**Rejected at compile time:** `std::string_view` / `const char*` parameters (the view would outlive the Lua string once the binding returns), a borrowed result, `async<async<T>>`, `async<result<T>>` and `result<async<T>>` (an operation that fails at once is `async<T>::completed(error)`).

**Alternatives.** A callback-style binding (`fn(args..., done)`) was rejected: the arity and undo machinery would have to special-case the last parameter, and a promise type is reusable outside RHP. Running the binding on a worker thread owned by RHP was rejected: RHP doesn't own threads beyond the network one (threading-model), and the user knows where the work belongs.

**Consequences.** `wait_kind::kAsync` joins `kEvent` / `kTask`; `request_record` holds the call. Calls are owned on the pump thread only (completing threads hold `weak_ptr`s through the inbox), so `G` always runs there. The yield follows the jump-yield rule (`RHP_LUA_JUMP_YIELDS`): the trampoline holds no C++ object with a destructor when it yields. Stubs mark async bindings `---@async`.

## Methods and properties on handles (AH7–AH9)

**Decision.**

```cpp
using game_lib = Rhp::lib<"game">
    ::handle<"entity", entity_id, &is_alive>
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>
    ::method<"move", &move_entity, Rhp::undo<&move_back>>   // e:move(dx, dy)
    ::property<"hp", &health_of>;                            // e.hp
```

- **AH7 — the handle comes from the first parameter.** `::method<"move", &move>` belongs to the handle type of `move`'s first parameter; the lib tree must declare that handle (a lib that only adds members re-declares `::handle`, which needs the validity check anyway). Labels are `entity:move` and `entity.hp`; a missing or wrong self is reported as `(self)`, later arguments count from 1 as the script wrote them.
- **AH8 — members are read-only and live in the handle's metatable.** Methods sit in a methods table that is the metatable's `__index` (the VM's fastest lookup); once a property exists, `__index` becomes a small C function over both tables. `__newindex` raises `kInvalidArgument`. Properties take only `requires_role<>`: no undo, no waiting. Method and property names are unique per handle across the lib tree (compile time) and across libs in one sandbox (install time, all or nothing).
- **AH9 — everything else is a binding.** Methods go through the same trampoline as `fn`: roles, `undo<>`, `irreversible`, `Rhp::result` errors, asynchronous results. Handles delivered by events and returned by other libs share the metatable, so they carry the methods too.

**Alternatives.** Explicit `::handle<...>::methods<...>` nesting (more DSL for the same information); writable properties (would need a setter and a journal per handle field: left to bindings with `undo<>`).
