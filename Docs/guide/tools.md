# Tools: tunables, profiler, debugger

Three tools work on a running sandbox. They are available from C++, over the wire (rhp-cli and `Rhp::client`), and partly from Lua:

- **Tunables** list and change the variables your libs expose.
- **The profiler** samples where scripts spend their instructions.
- **The debugger** pauses a script at a breakpoint and inspects it.

The game keeps running throughout: a paused script waits in its own coroutine, `pump()` goes on, and other scripts run.

Over the wire, each tool acts on the **sandbox of the identity you connect as**: your own scripts. The tools never reach another identity's sandbox or a release channel.

## Tunables

Every `::var` and `::ro` of an installed lib is a tunable. Tags describe it for tools, and `Rhp::range` also guards it:

```cpp
inline double g_speed = 4.0;
inline int g_level = 3;

using game_lib = Rhp::lib<"game">
    ::var<"speed", &g_speed, Rhp::range<0.0, 10.0>, Rhp::step<0.5>, Rhp::unit<"m/s">, Rhp::doc<"player run speed">>
    ::var<"level", &g_level, Rhp::range<1, 5>>
    ::ro<"frame", &g_frame, Rhp::doc<"frames since start">>;
```

| Tag | On | Effect |
|---|---|---|
| `Rhp::range<Min, Max>` | `::var` of a number | Every write must lie in `[Min, Max]`: a script's `game.speed = 11`, a `tune` over the wire, anything. Otherwise the write raises `kOutOfRange` (NaN is never in range). Integer bounds must fit the type exactly; `Min <= Max` is checked at compile time. |
| `Rhp::step<S>` | `::var` of a number | A hint for sliders (writes aren't rounded). |
| `Rhp::unit<"m/s">`, `Rhp::doc<"...">` | `::var`, `::ro` | Shown by tools and in the LuaLS stubs (`---@field speed number [0, 10] m/s: player run speed`). |

From C++:

```cpp
auto list = box.tunables("game");                 // every variable under "game", with value and tags
box.tune("game.speed", Rhp::value{6.5});          // as a script would write it: role, range, journal
```

`tune` writes through the variable's setter, so it needs `kPatch`, checks the range, and is journaled in the scratch module like an `exec`. `revert_all`, or the identity's last session ending, puts the old value back. Scripts can read the same list with `rhp.tunables([prefix])`: a table of `{path, type, value, writable, min, max, step, unit, doc}`.

From rhp-cli:

```bash
rhp-cli tune -c 127.0.0.1:7777 -i dev.rhpid game
```

```bash
rhp-cli tune -c 127.0.0.1:7777 -i dev.rhpid game.speed 6.5
```

In the REPL, `tunables [prefix]` lists them and `tune <path> <value>` sets one. Over the wire, `client.tunables(prefix)` and `client.tune(path, value)` do the same (ops `tunables` and `tune`):

```cpp
if (auto list = client.tunables("game")) {
    for (const Rhp::tunable_message& t : *list) {
        std::println("{} = {} {}", t.path, Rhp::json::to_text(t.current), t.unit); // also type, writable, min, max, step, doc
    }
}
auto set = client.tune("game.speed", Rhp::value{6.5}); // kOutOfRange outside [0, 10]
```

## Profiler

The profiler samples the Lua stack every N VM instructions of the sandbox's scripts: requests, timers, frame callbacks, event handlers and tasks. It counts each distinct stack, which gives a flame graph of where the instructions went. Time spent inside C++ bindings costs no instructions, so it isn't sampled; use your native profiler for that.

```cpp
box.start_profile({.interval = 1000});   // a sample every 1000 instructions (at least 100)
// ... let the game run ...
Rhp::script::profile_report r = box.stop_profile();
for (const auto& s : r.stacks) {          // most samples first
    std::println("{} {}", s.stack, s.samples);   // "game.combat (main);boost (game.combat:40) 312"
}
```

- Frames are written `name (module:first line)`; a module's top level is `module (main)`; C functions are `name [C]`.
- The function C++ called (a `call`, a handler) is named after the request: the exported function's name, `(timer)`, `(frame callback)`, `(event x)` or `(task)`.
- `max_depth` (64, at most 256) cuts deep stacks.
- `max_stacks` (10 000, at most 100 000) bounds memory; samples beyond it are counted as `dropped`.
- While profiling, results, instruction limits and cancels behave exactly as without it. The hook just fires more often, which the [benchmarks](../benchmarks.md#stage-11-tools) measure.

From rhp-cli, sample for a while and print the functions with the most samples:

```bash
rhp-cli profile -c 127.0.0.1:7777 -i dev.rhpid --seconds 10 --interval 500 -o game.folded
```

`-o` writes the folded stacks (`stack count` lines) that `flamegraph.pl` and speedscope read. In the REPL use `profile start [interval]`, then `profile show` and `profile stop [file]`. Over the wire, call `client.profile("start" | "read" | "stop", interval)`. A profile stops by itself when the session that started it ends.

A reply carries the stacks with the most samples, up to a quarter of the host's `limits.max_frame`; `truncated` counts the stacks left out. Read the whole report in C++ (`box.profile()`) when you need every stack.

## Debugger

Breakpoints, pause and steps suspend a script's **request**: an `exec`, a `call`, a module's top level, a timer, frame callback, event handler or task. The request's coroutine waits at the line, the program goes on, and inspecting reads its stack and variables without running any Lua: no calls and no metamethods (only the C++ getters of lib variables), so looking can't change anything.

```cpp
Rhp::script::sandbox box;
auto sub = box.on_script_event("rhp.debug", [](const Rhp::script::script_event& e) {
    // e.args[0]: {kind = "paused" | "hit", request, reason, source, line, label}
});
box.set_breakpoints("game.combat", std::vector<std::uint32_t>{12, 40});
// ... a script reaches game.combat:40 and pauses; pump() keeps running everything else ...
for (const auto& stop : box.paused()) {
    auto frames = box.debug_stack(stop.request);                        // innermost first
    auto locals = box.debug_variables(stop.request, 0, Rhp::script::debug_scope::kLocals);
    auto hp = box.debug_evaluate(stop.request, 0, "target.stats.hp");   // a dotted path
    box.debug_resume(stop.request, Rhp::script::step_mode::kOver);      // or kContinue / kInto / kOut
}
```

| Call | Does |
|---|---|
| `set_breakpoints(source, lines)` | Replaces one source's breakpoints (a module name, or an `exec` chunk name such as `exec`). Returns the lines kept; an empty list clears it. |
| `debug_pause()` | The next line any request runs pauses (reason `pause`). |
| `paused()` | Every paused request: request id, label, reason (`breakpoint` / `step` / `pause`), source, line. |
| `debug_resume(request, mode)` | Runs on (`kContinue`) or steps: `kInto` stops at the next line, `kOver` at the next line of this function or a caller, `kOut` at the next line of a caller. The request continues at the next `pump()`. |
| `debug_stack(request)` | Frames: name, `Lua` / `main` / `C`, source, line, first line. |
| `debug_variables(request, frame, scope, path)` | `kLocals` (and varargs), `kUpvalues`, `kGlobals` (the module's own environment). `path` descends into tables: `{"t", "y"}`, `{"list", "[2]"}`. |
| `debug_evaluate(request, frame, expression)` | `a.b[2]["c d"]`, looked up in locals, upvalues, the module's globals, then libs and the standard library. Lib proxies (variables, sub-libs) are read through their C++ getters. Tables are read raw: a missing field is `nil` and `__index` isn't called. Other userdata (handles, `require` proxies) can be shown but not read into. Nothing else runs. |
| `debug_reset()` | Clears breakpoints, steps and pause, and resumes everything paused. |

Values are rendered without running Lua. Strings are quoted and shortened to 120 characters. Tables show their field count (`{...} (3 fields)`) and expand through `path`, at most 200 fields per listing. Functions show where they were defined. Handles and lib proxies show their type name.

`rhp.debug` events go to C++ listeners (`on_script_event`, `host.on_script_event`) and to clients that subscribed, at the end of the operation or `pump()` that paused. The sandbox's own scripts never hear them: an `rhp.on("rhp.debug", ...)` handler could pause and publish again.

**Where a script can't pause**, a breakpoint is reported instead: the event `rhp.debug` with `kind = "hit"`, once per place until the breakpoints change. That happens in:

- code a C++ caller ran synchronously (a patch point handler, a C++ `lua_event` fire),
- a coroutine the script created itself,
- code under a C function (a metamethod, a `table.sort` comparator),
- any request once 32 are already paused.

`pause` and steps wait for the next line that can pause.

A paused request keeps everything it holds: its effects, its module, any task joined on it. `cancel(request)` ends it like any request. Reverting or unloading its module abandons it, and the debugger forgets it. Its wall-time limit doesn't run while it waits, but a client waiting for its result may time out.

**What it costs.** With no breakpoint, step or pause set, the debugger costs nothing. With breakpoints only, line events run only in the functions whose lines hold a breakpoint (calls and returns switch them on and off), so code elsewhere runs at about its normal speed; call-heavy code still pays a call and a return event per call. A step or a pause watches every line until it ends. Clear breakpoints when you are done (`set_breakpoints(source, {})` or `debug_reset()`). Instruction limits, cancels and the profiler keep working while it watches. Numbers: [performance](performance.md#tools) and [benchmarks](../benchmarks.md#overall-optimization-pass).

### From rhp-cli

```text
rhp> load game.combat combat.lua
rhp> break game.combat 40
breakpoints in game.combat: 40
rhp> require('game.combat').hit(3)
paused at game.combat:40 (request 7, breakpoint): continue / step [into|over|out] / stack / locals / print <name>
rhp> stack
#0 hit (game.combat:40)
#1 ? (exec:1)
rhp> locals
damage = 12
target = {...} (4 fields) (table)
rhp> print target.stats.hp
target.stats.hp = 80 (number)
rhp> step over
paused at game.combat:41 (request 7, step): ...
rhp> continue
```

A script that pauses leaves the prompt free: an expression, `call`, `load` or `reload` whose own request pauses goes to the background, and its result prints when it finishes. Ctrl+C cancels a request that is still running. The other commands are `pause`, `paused`, `upvalues`, `globals` and `locals <frame> [path]`.

### From an editor (Debug Adapter Protocol)

`rhp-cli dap` is a [DAP](https://microsoft.github.io/debug-adapter-protocol/) server on stdin / stdout. Any DAP client can launch it; in VS Code, a minimal debug type that starts the executable is enough:

```bash
rhp-cli dap -c 127.0.0.1:7777 -i dev.rhpid --root ./scripts
```

Sources map to modules through `--root`: a breakpoint in `scripts/game/combat.lua` applies to module `game.combat`, and frames point back at that file when it exists. Paused requests are the debugger's threads; while nothing is paused there is one placeholder thread, `(no script paused)`, with no frames. Frame and variable references of one thread stay valid until that thread runs on. The adapter supports breakpoints (a line the host didn't keep is reported unverified), `threads`, stack traces, the Locals / Upvalues / Globals scopes with expandable tables, `continue`, `next`, `stepIn`, `stepOut`, `pause`, hover and watch evaluation, and `disconnect` (which resets the debugger). Hits where a script can't pause show up in the debug console. A message that isn't DAP (no `Content-Length`, a length that isn't a number, a header line over 1 KiB, a body over 64 MiB) ends the adapter, because the stream can't be read past it.

### Over the wire

`client.debug(request)` sends a `wire::debug_request`. Its `action` is one of `break` (source, lines), `pause`, `paused`, `continue` / `into` / `over` / `out` (request), `stack` (request), `variables` (request, frame, scope, path), `evaluate` (request, frame, expression) or `reset`. Subscribe to `rhp.debug` with `client.on` to hear when a script pauses:

```cpp
auto paused = client.on("rhp.debug", [](const Rhp::remote_event& e) { /* network thread: e.args[0] has kind, request, source, line */ });
Rhp::debug_request set;
set.action = "break";
set.source = "game.combat";
set.lines = {40};
auto kept = client.debug(set);                  // debug_reply: kept->lines
// ... later, with the request id an rhp.debug event (or the "paused" action) reported:
Rhp::debug_request look;
look.action = "variables";
look.request = request_id;
look.scope = "locals";
auto vars = client.debug(look);                 // vars->variables
```

Debugging needs `kPatch`, because pausing a script changes what it does. A host at hardening `production` has no remote debugger: `debug` answers `kForbidden`, and a `production` build leaves it out ([hardening levels](security.md#hardening-levels)). Tunables and the profiler stay available. Every session that sets breakpoints or pauses is a debugging session; when the last of them ends, the host resets the debugger and the paused scripts run on. `reset` from any session does it at once.

The actions that change what scripts do (`break`, `pause`, `continue`, the steps, `reset`) are audited like an `exec`: an `event::script_executed` with op `debug`. Reading (`paused`, `stack`, `variables`, `evaluate`), `tunables` and `profile` aren't.

## Limits

- One debugger per identity sandbox. Every session of the identity sees and drives the same breakpoints; they stay until the last debugging session ends.
- At most 32 requests paused at once, 10 000 breakpoint lines per source.
- No conditional breakpoints, no expression evaluation beyond paths, no setting variables from the debugger (use `tune` or `exec`).
- The profiler counts VM instructions, not time. A slow C++ binding is invisible to it, and so are the steps of pattern matching and plain `find` (they count toward `limits.instructions` only).
- Release channels (`Rhp::release::manager`) have no debugger or profiler over the wire. In C++, `manager.sandbox(channel)` gives the channel's sandbox.
