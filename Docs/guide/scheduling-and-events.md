# Scheduling and events

A task-oriented walkthrough of Stage 7: keeping work going inside the host without a client request held open, letting modules, C++ and tools talk through events, and what happens when a handler fails. The exact contracts are in [writing scripts](writing-scripts.md) (Lua) and [host and client](host-and-client.md) (C++); why it works this way is in the [Stage 7 decisions](../decisions/stage7-scheduling-events.md).

Everything here runs on the thread that calls `pump()`. Nothing runs between pumps.

## 1. Do something every frame

```lua
-- module: hud.overlay
local frames = 0

function on_load()
    rhp.every_frame(function()
        frames = frames + 1
        game.draw_text(10, 10, "frame " .. frames)
    end)
end
```

Load it once (`rhp-cli run hud.lua -c HOST:PORT -i dev.rhpid --pin --name hud.overlay`, or `load` in the REPL) and it keeps drawing until the module is reverted, unloaded or reloaded, or its identity's last session ends without a pin.

| You want | Write |
|---|---|
| every pump | `rhp.every_frame(fn)` |
| every `n` pumps | `rhp.every_frames(n, fn)` |
| once after `ms` | `rhp.after(ms, fn)` |
| every `ms` | `rhp.every(ms, fn)`; add `{times = n}` to stop after `n` calls |
| stop for a while | `rhp.pause(id)` … `rhp.resume(id)` (the time or frames left are kept) |
| change the period | `rhp.reschedule(id, interval)` (milliseconds for timers, frames for frame callbacks) |
| see what is scheduled | `rhp.timers()`: id, kind (`"timer"` / `"frames"`), interval, remaining, runs, times, repeating, paused, running |
| remove it | `rhp.off(id)` |

Every call is a request of its own, with its own instruction and time budget, so a slow call never stalls the next pump on its own unless it has no limits and never waits. A callback that waits (`rhp.wait`, `rhp.sleep`, `rhp.wait_event`) doesn't get a second, overlapping call: the entry skips until the first call ends.

## 2. Keep a loop running in the background

```lua
-- module: tools.watchdog
function on_load()
    worker = rhp.spawn(function()
        while true do
            local ok, err = check_server()
            if not ok then rhp.publish("tools.server_down", err) end
            rhp.sleep(1000)
        end
    end)
end

function status() return worker:status() end   -- "suspended", "running", "done", "failed", "cancelled"
function stop() return worker:cancel() end
```

`rhp.spawn` returns immediately: the request that called it (an exec from a client, say) is answered at once, and the task starts at the next pump. A task belongs to the module that spawned it and goes away with it. `worker:join()` (from another request) waits for its results, or raises its error. `rhp.tasks()` lists the module's unfinished tasks.

Give tasks waits (`rhp.sleep`, `rhp.wait`, `rhp.next_frame`, `rhp.wait_event`). A loop that never waits holds `pump()` for as long as its limits allow; set `limits.slice_us` on the host if scripts may do that.

## 3. Let modules talk: script events

```lua
-- module: game.rounds
function finish(winner) rhp.publish("game.round_over", winner, os.time()) end

-- module: ui.scoreboard
rhp.on("game.round_over", function(winner, at) show_banner(winner .. " wins") end)
rhp.once("game.round_over", function() print("first round finished") end)

-- anywhere a script can suspend
local fired, winner = rhp.wait_event("game.round_over", 30000)
if fired then print(winner) else print("no round ended in 30 s") end
```

- Events stay inside one identity: a module of key `dev` hears `dev`'s publishes, not another key's.
- Delivery happens at the next pump and the values are copies. Handlers may publish again; that arrives one pump later.
- `{priority = n}` orders handlers (higher first). `limits.event_queue` caps how many events wait for a pump; `rhp.stats()` shows how many were dropped.
- A name a C++ `Rhp::lua_event` uses always means that C++ event; scripts can't publish it.

## 4. Hear scripts from C++

```cpp
// In the application, next to host.install<...>():
auto rounds = host.on_script_event("game.round_over", [](const Rhp::event::script_event& e) {
    // pump thread: e.identity, e.module, e.event, e.args (Rhp::value)
    game::analytics_round_over(e.identity, e.args);
});
// The subscription unsubscribes when it is destroyed: keep it alive.
```

A standalone `Rhp::script::sandbox` has the same call, `box.on_script_event(name, fn)` (or `"*"` for every name), with a `Rhp::script::script_event` (`name`, `module` id, `module_name`, `args`). C++ events go the other way: declare `inline constexpr Rhp::lua_event<"game.player_died", int> player_died{};` and call `player_died.fire(id)`; scripts `rhp.on` it ([exposing C++](exposing-cpp.md)).

## 5. Watch events from a tool

```bash
rhp-cli events game.round_over game.player_died -c HOST:PORT -i dev.rhpid
```

```text
rhp> subscribe game.round_over
rhp> unsubscribe game.round_over
```

From C++:

```cpp
auto id = client.on("game.round_over", [](const Rhp::remote_event& e) {
    // network thread: e.name, e.module, e.args, e.dropped
});
// later: client.off(*id);
```

A client hears the host's C++ events (any identity may subscribe, observe included) and its own identity's script events (`"*"` for all of them). Subscriptions live as long as the session, through reconnects. A host sends at most `host_options::remote_events_per_pump` events per session per pump; the rest are dropped and the next delivery's `dropped` says how many.

## 6. When a handler fails

By default a failing timer, frame callback, event handler or task is **reported** and only what that one call did is undone. The handler stays and the module stays active, so there is no need for `pcall` around every handler.

```lua
rhp.every_frame(update, {on_error = "remove"})   -- drop it after its first failure
rhp.on("net.packet", parse, {on_error = "fault"}) -- the old behaviour: fault the whole module
rhp.on_error(function(f) print(f.module, f.kind, f.source, f.code, f.message) end)
```

The host also logs it, sends `[handler failed] ...` to the identity's sessions and publishes `Rhp::event::handler_failed` (audit sinks write it). Set the default for every sandbox with `host_options::handler_errors`. A memory-limit stop always faults the module.

## Recipes

| Problem | Pattern |
|---|---|
| a menu that must stay while you're disconnected | load it with an admin key and `--pin`; its frame callbacks and tasks keep running |
| poll something without blocking the frame | `rhp.every(250, poll)` or a task with `rhp.sleep(250)` |
| wait for C++ to say something happened | `rhp.wait_event("game.level_loaded", 10000)` in a task or exec |
| run a long computation | a task that does a slice of work, then `rhp.next_frame()` |
| tell your desktop tool what scripts are doing | `rhp.publish(...)` in the script, `rhp-cli events` or `client.on` on the tool |
| a handler that fails every frame | `{on_error = "remove"}`, or watch `rhp.on_error` |

Limits that apply here are listed in [limitations](limitations.md#scheduling-and-events).
