# Examples

Each example is a small, complete program you can copy. They link only `Rhp::rhp` and use only the public API (never `detail/`).

| Example | Target | Shows |
|---|---|---|
| [`hello_console/`](hello_console) | `hello_console` | local scripting with one `Rhp::script::sandbox`: `Rhp::lib` (reversible function, variable, handle), a patch point, `exec` / `load` / `call` / `revert` |
| [`frame_loop/`](frame_loop) | `frame_loop` | pumping scripts per frame: time slicing, `rhp.wait`, a timer-started loop, reload keeping state, a C++ event, cancel, LuaLS stubs |
| [`remote_exec/`](remote_exec) | `remote_exec` | `Rhp::host` and `Rhp::client` in one process over loopback and TCP: three keys and roles, signing, streamed output, cancel of a runaway loop, disconnect = revert |
| [`custom_transport/`](custom_transport) | `custom_transport` | your own `Rhp::net::transport` (a byte-metering wrapper around loopback) |
| [`headless_server/`](headless_server) | `headless_server` | a standalone host for `rhp-cli`: key files, audit log, blob folder, reverse mode, TLS, DNS-SD, HTTP gateway, releases |
| [`lua_tests/`](lua_tests) | `lua_tests_example` | testing a game's Lua scripts offline with `Rhp::test` and `rhp_add_lua_tests` |

## Build and run

Examples build with `RHP_BUILD_EXAMPLES=ON`, the default when RHP is the top-level project. From the repository root:

```bash
cmake --preset windows-msvc
cmake --build --preset windows-msvc --target hello_console frame_loop remote_exec custom_transport headless_server lua_tests_example
```

With tests built too (the default top-level build), the finite examples are ctest tests: `example.hello_console`, `example.frame_loop`, `example.remote_exec`, `example.custom_transport`, and one `example.lua_tests.<spec>` per spec file.

```bash
ctest --preset windows-msvc -R example --output-on-failure
```

Executables land in `build/<preset>/Examples/<name>/Debug/` (for example `build/windows-msvc/Examples/hello_console/Debug/hello_console.exe`). `hello_console`, `frame_loop` and `remote_exec` find their `scripts/` folder through a path compiled into the program, so they run from any working directory; `lua_tests_example` takes its folders on the command line. With `RHP_ENABLE=OFF` the examples still build, but they would only report `kDisabled`, so they aren't registered as tests.
