# Examples

Each example is a small, complete program a user can copy. They are added as the stages that power them land.

| Example | Shows | Arrives |
|---|---|---|
| `hello_console/` | exec, exposing C++ with `Rhp::lib`, patch points, load / revert / rollback — locally, then over TCP | Stage 1 (local), Stage 3 (TCP) |
| `custom_transport/` | writing your own `Rhp::net::transport` | Stage 3 |
| `headless_server/` | threaded host, roles, audit log, fleet + mDNS | Stage 6 |

## Rules

- One folder per example with its own `CMakeLists.txt`, linking only `Rhp::rhp`.
- Examples use only the public API — never `detail/`.
- Built when `RHP_BUILD_EXAMPLES=ON` (default when RHP is the top-level project).
