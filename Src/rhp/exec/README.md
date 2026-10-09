# exec — layer 3

Threading and time policies. Namespace `Rhp::exec`. Header-only.

| Header | What |
|---|---|
| `io_runner.hpp` | `io_runner` concept; `owned_io_thread` (default: one `std::jthread` runs the network), `zero_threads` (pump / blocking calls poll it) |
| `executor.hpp` | `executor` concept + `pumped` (scripts run in `host.pump()`); `clock_source` concept + `steady_clock` |

## Rules

- This layer knows nothing about sockets or Lua: an `io_runner` runs whatever body it is given (the host hands it the network loop).
- `owned_io_thread` is what makes `cancel` a real escape hatch: the network keeps reading while `pump()` is stuck in a script. With `zero_threads` a stuck script also stops the network.
