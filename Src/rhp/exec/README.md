# exec — layer 3

Threading and time policies for `Rhp::config<>`. Namespace `Rhp::exec`. Target `Rhp::exec`; header-only, depends on `core` and `Threads`. Decisions: [threading model](../../../Docs/decisions/threading-model.md).

| Header | What |
|---|---|
| `io_runner.hpp` | the `io_runner` concept (`kOwnsThread`, `start(body)`, `stop()`); `owned_io_thread` (default: one `std::jthread` runs the network), `zero_threads` (no thread: `pump()` and blocking calls poll the network) |
| `executor.hpp` | the `executor` concept (`kRunsInPump`) and `pumped` (scripts run in `host.pump()`, the only executor); the `clock_source` concept (`now()` → `steady_clock::time_point`) and `steady_clock` |

```cpp
struct game_clock {                                    // script time follows the game, e.g. paused in menus
    [[nodiscard]] std::chrono::steady_clock::time_point now() const { return game::script_time(); }
};
using cfg = Rhp::config<>::io<Rhp::exec::zero_threads>::clock<game_clock>;
```

## Rules

- This layer knows nothing about sockets or Lua: an `io_runner` runs whatever body it is given (the host hands it the network loop) until its `stop_token` is signalled.
- `owned_io_thread` is what makes `cancel` a real escape hatch: the network keeps reading while `pump()` is stuck in a script. With `zero_threads` a stuck script also stops the network, so a cancel can't reach it and heartbeats lapse.
- `owned_io_thread::stop()` called on the I/O thread itself detaches instead of joining; the body must then keep alive what it uses.
- A `zero_threads` client runs its network only inside calls, `client::poll()` and `pending::get()`: poll at least once per heartbeat (2 s) while idle, or the host drops the session.
- The clock is script time only (`rhp.sleep`, `rhp.timer`, the HTTP listener's idle expiry, sampled on the pump thread). Limits, heartbeats and HTTP proof freshness always use the steady / system clocks.
