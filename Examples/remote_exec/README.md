# remote_exec

A host and its clients in one process: the "game" thread pumps `Rhp::host`, the main thread plays three developers with three keys.

| Key | Role | Tries |
|---|---|---|
| `viewer` | observe | reads `game.gravity`; writing it and loading a module fail with `kForbidden` |
| `qa` | patch | loads `scripts/moon.lua` (gravity −1.6), calls a reversible binding, reads `status` and the LuaLS stubs over the wire, starts `while true do end` and cancels it from the network thread while the game thread is stuck in it, then disconnects — everything it did is reverted |
| `dev` | admin | prints (the line streams back), lists modules, presses `revert_all` |

The tour runs twice: over the in-process loopback transport, then over TCP on `127.0.0.1` with a free port. Finally a wrong key is refused (`kAuth`). Registered as `ctest -R example.remote_exec`.
