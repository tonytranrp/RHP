# Writing scripts

Lua 5.5, text only (no binary chunks). Each identity (key) has its own Lua state; each module revision inside it has its own `_ENV`. Sessions using the same identity share its modules and scratch environment. Module environments share that identity's libraries; they are not separate security boundaries.

## The `rhp` global

| Function | Role | What |
|---|---|---|
| `rhp.patch(id, fn)` | patch | override a C++ patch point; `fn(original, ...)`; undone with the module |
| `rhp.on(event, fn)` / `rhp.off(id)` | any | `on` returns a subscription id; `off` removes this module's timer/subscription by id |
| `rhp.timer(ms, fn, repeating)` | any | return a timer id; call `fn` after `ms` (repeat when the third argument is true); undone with its module |
| `rhp.wait(frames)` / `rhp.next_frame()` | any | suspend for N `pump()` calls |
| `rhp.sleep(ms)` | any | suspend for at least `ms` ms (clock is injectable) |
| `rhp.emit(value)` | any | stream a value to the client while the script keeps running |
| `rhp.frame()` | any | number of `pump()` calls so far |
| `rhp.role` | any | `"observe"`, `"patch"` or `"admin"` |
| `require(name)` | any | a loaded module of the same identity (read-only live proxy; cycles fail) |
| `print(...)` | any | streams back to the client as an output line |

Plus whatever libs the host installed (`game.spawn(...)`).

## Roles decide what a script can do

| Role | May |
|---|---|
| `observe` | run code, read variables, call pure bindings. May send *unsigned* code |
| `patch` | everything above plus write variables, call `undo` / `irreversible` bindings, patch points, load / reload / revert modules. Code must be signed |
| `admin` | plus `revert_all`, blobs, admin-tagged bindings, pin / unpin, and the **full Lua standard library** (`io`, `os`, `debug`, `package`). An admin key is fully trusted |

Non-admin states get `string`, `table`, `math`, `utf8`, `coroutine`, `os.time`, `os.clock`; no `io`, `package`, `debug`, `dofile`, `loadfile`, `collectgarbage`, `string.dump`; `load` is text-only.

## Running code: `exec` versus modules

- **exec**: runs in your identity's scratch module. Effects are kept until reverted or you disconnect. A failing exec reverts only its own effects.
- **load a module**: named (dotted lowercase), has hooks, can be reloaded, rolled back, reverted and unloaded individually. Loading an already loaded name performs a reload. The source returns an export table; if it does not return a table, its environment becomes the exports.

```lua
-- low_grav.lua
local M = { calls = 0 }

function M.on_load()
    game.gravity = -1.6
    rhp.patch("combat.damage", function(orig, b, t) return orig(b, t) * 2 end)
end

function M.on_unload() print("bye") end

function M.on_save()    return { calls = M.calls }  end       -- state handed to the next revision
function M.on_restore(s) M.calls = s and s.calls or 0 end

function M.set(g) M.calls = M.calls + 1; game.gravity = g end                      -- callable remotely: client.call(mod, "set", 1.6)

return M                                                    -- the export table (the _ENV if you return nothing)
```

The host must expose `game.gravity` and the `combat.damage` point for this example. `on_load` runs after the incoming top level; it may suspend. `on_save`, `on_restore`, `on_unload` and patch handlers run synchronously and cannot use the wait/sleep functions. Keep `on_save` free of application mutations: effects it records belong to the old revision and are not undone as incoming-revision effects if a reload fails. `on_unload` is called for an active module; its errors do not prevent cleanup, and it is not called again after a prior revert/fault.

A runtime error in a named module auto-reverts its recorded effects and leaves it `faulted`. Inspect the fault with `status`, then reload or unload it. A scratch exec failure reverts only that request's recorded effects; earlier scratch effects and ordinary Lua assignments are not a transactional snapshot.

## The undo model

Every mutation (variable write, `undo` binding, patch, timer, subscription) is recorded in an owner-keyed ledger. Reverting walks it newest first.

| Operation | Effect |
|---|---|
| `revert(mod)` | undo all effects; module stays loaded as `reverted` |
| `unload(mod [, force])` | `on_unload`, revert, forget. Refused with `kHasDependents` while other modules `require` it; `force` unloads anyway and dependents then get `kUnloaded` |
| `reload(mod, source)` | transactional: new revision runs next to the old, `new.on_restore(old.on_save())`, then the old revision's effects are removed. On any failure only the new revision is reverted |
| `rollback(mod, n)` | reload the source from `n` revisions back (default 8 revisions kept, `limits.revisions`) |
| `checkpoint(tag)` / `revert_to(tag)` | mark this identity's effect ledger and undo later effects; does not unload modules or restore a Lua-memory snapshot |
| `revert_all()` | panic button: unload every module. Over the network it reverts **every identity** (admin) |
| `pin(mod)` (admin) | keep the module and required dependencies after the last session ends; its own `revert` / `unload` are refused until unpinned; `revert_to` is refused while any module is pinned. Reload/rollback still work; `revert_all` removes it |
| disconnect | reverts the identity's modules (after the resume window), except pinned ones |

Variable writes and patches are stacked per target, so modules can be reverted in any order and the target ends up as if the undone write never happened. `irreversible` calls are listed in the revert result (`undone`, `irreversible`, `failures`, `deferred`).

Lifecycle operations are C++/client APIs, not functions in the `rhp` Lua table. If an application binding re-enters the sandbox to request cleanup, it is deferred until the outermost run has unwound (or a subsequent pump processes it). Inspect `deferred` in the revert report. A clean report means no undo callback failed; inspect `irreversible` separately because it can be nonzero in a clean report.

Module states in `status` are `loading` (first load suspended), `active`, `reverted`, and `faulted`. `reloading` identifies an incoming revision beside the live one. A reverted module remains inspectable but cannot be called through `sandbox::call`; reload it to reactivate it.

## Time, loops and limits

Scripts run to completion by default. They become coroutines when they call `rhp.wait`, `rhp.next_frame` or `rhp.sleep`: the call returns early and the rest continues inside later `pump()` calls, with the final result delivered asynchronously. A remote blocking client still waits for that final result, while `client.async()` returns a pending result immediately.

```lua
while true do
    rhp.emit(game.tick)
    rhp.wait(10)            -- every 10 frames, without blocking the frame
end
```

- **A runaway loop holds the pump thread** unless you opt in to slicing (`limits.slice_us`) or stop it through an instruction/time limit or cancellation. With the default owned I/O thread, `client.cancel()` reaches Lua's count hook even while the host is inside a script. A `zero_threads` host cannot receive that network cancel while blocked. Unexpected link loss does not cancel during the resume grace period; cancellation also cannot interrupt a bound C++ call.
- Instruction, memory and execution-time stops are sticky, so a script's `pcall` cannot make a stopped request succeed. `slice_us` yields a runnable request rather than failing it. These are separate from the client's end-to-end request timeout; see [configuration](configuration.md#limits).
- Observe keys can send unsigned code. Correct binding permissions protect application mutations, but default limits still allow code to hold the pump or grow memory until cancelled; set host budgets for less trusted callers.

For a local sandbox, use untyped `exec` / `call` when suspension is possible. An early `exec` / `call` result is an empty list; `load` returns an id whose state may be `loading`; a suspended `reload` returns a zero revision. The final outcome arrives in `sandbox_options::on_result` with the request id. The local typed `exec<T>` overload cannot convert an unfinished request's empty list into its eventual `T`.

```cpp
Rhp::script::sandbox_options options;
options.on_result = [](Rhp::request_id id, const Rhp::result<Rhp::value_list>& result) {
    if (!result) {
        std::println(stderr, "request {}: {}", id, result.error());
    }
};
Rhp::script::sandbox box{options};
auto started = box.exec("rhp.next_frame(); return 42");
if (started) {
    const auto request = box.last_request();
    while (box.pending(request)) {
        box.pump();
    }
}
```

This fragment needs `<cstdio>`, `<print>` and `<rhp/rhp.hpp>`. The callback runs on the sandbox's thread. In a game, perform one pump per frame rather than draining a long-running request in a tight loop. Timers that repeat fire at most once per pump; `rhp.off(timer_id)` removes a pending timer or subscription owned by the current module.

## Errors seen from Lua

Errors raised by bindings are strings of the form `[code] where: message`. The full list of codes is in the [reference](reference.md#error-codes).
