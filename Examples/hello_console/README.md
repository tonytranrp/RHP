# hello_console

A tiny pretend game scripted locally through one `Rhp::script::sandbox`. No network, keys or signatures.

It shows:

- exposing C++ to Lua with `Rhp::lib`: a reversible function (`game.spawn`, undone by `despawn`), a pure function (`game.count`), a journaled variable (`game.gravity`) and an opaque handle type (`entity`);
- a patch point (`combat.damage`) that Lua overrides with `rhp.patch`;
- `exec<double>` in the scratch module, `load` of `scripts/low_grav.lua`, `call` of its exported `boost`, and `status`;
- `revert` of the module, after which gravity, the entity list and `combat.damage` are exactly as before (the program checks this and exits with 1 if anything was left behind).

```cpp
using game_lib = Rhp::lib<"game">
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>
    ::fn<"count", &entity_count>
    ::var<"gravity", &g_gravity>
    ::handle<"entity", entity_id, &is_alive>;
```

## Build and run

From the repository root:

```bash
cmake --build --preset windows-msvc --target hello_console
ctest --preset windows-msvc -R example.hello_console --output-on-failure
```

Or run the executable directly: `build/windows-msvc/Examples/hello_console/Debug/hello_console.exe` (on Linux, `build/linux-clang/Examples/hello_console/Debug/hello_console`). The script folder is compiled in (`RHP_HELLO_SCRIPTS_DIR`), so it works from any working directory.

Next: [`frame_loop`](../frame_loop) for per-frame scripts, [`remote_exec`](../remote_exec) for the same over a network, and the guide's [exposing C++](../../Docs/guide/exposing-cpp.md).
