# frame_loop

A pretend game loop that pumps one `Rhp::script::sandbox` per frame for 120 frames: the scheduler at work, locally.

It shows:

- time slicing (`sandbox_options::limits.slice_us = 2000`): a runaway `while true do end` returns after one slice and then runs one slice per frame, so no frame blocks (the program checks the worst frame time), until `box.cancel(request)` stops it at frame 60;
- a module (`scripts/weather.lua`) that starts a forever loop with `rhp.timer(0, ...)`; the loop waits with `rhp.wait(10)` between gusts, writes the journaled variable `game.wind` and streams values with `rhp.emit` (received through `sandbox_options::on_emit`);
- a C++ event, `Rhp::lua_event<"game.goal", int>`, fired by the game and handled in Lua with `rhp.on`;
- `reload` of the module at frame 40 with the next revision, `scripts/weather_revised.lua`: the old revision hands its gust count over through `on_save` and the new one takes it in `on_restore`, then the old revision's timer loop, subscription and effects are removed;
- `sandbox_options::on_result` receiving the final result of requests that suspended;
- LuaLS editor stubs for the sandbox's role (`box.stubs()`), written to `rhp_api.lua` in the build folder;
- `revert_all` at the end, after which the game is exactly as before. The program exits with 1 if any check fails.

## Build and run

From the repository root:

```bash
cmake --build --preset windows-msvc --target frame_loop
ctest --preset windows-msvc -R example.frame_loop --output-on-failure
```

Or run `build/windows-msvc/Examples/frame_loop/Debug/frame_loop.exe` directly (Linux: `build/linux-clang/Examples/frame_loop/Debug/frame_loop`). The script folder is compiled in.

The guide's [writing scripts](../../Docs/guide/writing-scripts.md#time-loops-and-limits) and [scheduling and events](../../Docs/guide/scheduling-and-events.md) explain each piece.
