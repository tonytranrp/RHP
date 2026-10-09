# frame_loop

A pretend game loop that pumps one `Rhp::script::sandbox` per frame — the Stage 2 scheduler at work.

It shows:

- time slicing (`limits.slice_us = 2000`): a runaway `while true do end` returns after one slice and keeps running a slice per frame, so no frame blocks (the program checks the worst frame time), until `cancel(request)` stops it;
- a module (`scripts/weather.lua`) whose forever loop runs as a timer-started request that sleeps with `rhp.wait(10)` between gusts, streams values with `rhp.emit`, and subscribes to a C++ event (`Rhp::lua_event<"game.goal", int>`);
- `reload` to `scripts/weather_v2.lua` mid-game: the old revision hands its gust count over through `on_save` → `on_restore`, then its effects, timer loop and subscription are removed;
- LuaLS editor stubs for the sandbox's role written to `rhp_api.lua` in the build folder;
- `revert_all` at the end, after which the game is exactly as before (the program exits with 1 if any check fails).

## Run

```
ctest --preset windows-msvc -R example.frame_loop --output-on-failure
```

Or run `build/windows-msvc/Examples/frame_loop/Debug/frame_loop.exe` directly.
