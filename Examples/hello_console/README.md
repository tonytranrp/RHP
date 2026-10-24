# hello_console

A tiny pretend game scripted locally through one `Rhp::script::sandbox`.

It shows:

- exposing C++ to Lua with `Rhp::lib` — a reversible function (`spawn`, undone by `despawn`), a pure function, a journaled variable (`gravity`) and an opaque handle type (`entity`);
- a patch point (`combat.damage`) that Lua overrides with `rhp.patch`;
- `exec` in the scratch module, `load` of `scripts/low_grav.lua`, `call` of an exported function;
- `revert` of the module, after which gravity, the entity list and `combat.damage` are exactly as before (the program checks this and exits with 1 if anything was left behind).

## Run

As a test (from the repository root, after building):

```
ctest --preset windows-msvc -R example.hello_console --output-on-failure
```

Or run the executable directly, e.g. `build/windows-msvc/Examples/hello_console/Debug/hello_console.exe`. The script directory is compiled in (`RHP_HELLO_SCRIPTS_DIR`), so it works from any working directory.

Over a network: see `Examples/remote_exec` (and `Examples/headless_server` with `rhp-cli`).
