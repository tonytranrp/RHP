# Examples

Each example is a small, complete program a user can copy. They are added as the stages that power them land.

| Example | Shows | Arrives |
|---|---|---|
| `hello_console/` | exec, exposing C++ with `Rhp::lib`, patch points, load / call / revert — locally | Stage 1 |
| `frame_loop/` | pumping scripts per frame: slicing, `rhp.wait`, reload keeping state, events, LuaLS stubs | Stage 2 |
| `remote_exec/` | `Rhp::host` + `Rhp::client` over loopback and TCP: three keys and roles, streamed output, cancel of a runaway loop, disconnect = revert | Stage 3 |
| `custom_transport/` | writing your own `Rhp::net::transport` (a byte-metering wrapper around loopback) | Stage 3 |
| `headless_server/` | a standalone host for `rhp-cli`: key files, audit log, blob folder, reverse mode, TLS, DNS-SD advertisement, HTTP gateway | Stage 4, 6 |
| `lua_tests/` | testing a game's Lua scripts offline with `Rhp::test`: a test executable with the game's lib, specs, the fake clock, stubs, properties, budgets; `rhp_add_lua_tests` | Stage 12 |

## Rules

- One folder per example with its own `CMakeLists.txt`, linking only `Rhp::rhp`.
- Examples use only the public API — never `detail/`.
- Built when `RHP_BUILD_EXAMPLES=ON` (default when RHP is the top-level project).
