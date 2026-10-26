# Limitations

What RHP does not do, or does only partly, as of Stage 12. Most of these are deliberate design limits; the rest are open work tracked in [Status and TODO](../TODO.md). Read this before putting RHP in front of anyone you don't fully trust.

## Safety and trust

- **RHP runs remote code on purpose.** Authentication, roles, script signing and TLS decide *who* may run code. They don't make the code harmless. An `admin` identity has Lua's full standard library (files, `os.execute`, native libraries) and is fully trusted.
- **No execution budgets by default.** Scripts run to completion unless the host sets `limits.instructions`, `wall_ms`, `memory` and optionally `slice_us`. Set them on any host that accepts keys that aren't fully trusted; they apply to every identity of the host ([configuration](configuration.md#limits)).
- **Long C++ calls can't be interrupted.** The instruction count hook only runs between Lua instructions. A bound function that blocks blocks the pump.
- **Undo covers recorded effects only.** RHP undoes variable writes, patches, timers, subscriptions, tasks and functions you gave an inverse (`Rhp::undo<>`). Functions marked `Rhp::irreversible` are reported, untagged functions are assumed pure, and admin standard-library side effects (files written, processes started) are not undone.
- **`RHP_ENABLE=OFF` for builds that must not accept code.** Enabled builds need their own deployment and distribution review.
- **Probing.** Idle unauthenticated connections count against `pending_handshakes` and can delay a resume. A probe can tell a known session id from an unknown one.

## Scheduling and events

- **Runaway pump-time work can't be cancelled from the network.** A timer, frame callback, event handler or task run by `pump()` (not by a client request) that never returns can only be stopped by limits (`instructions`, `wall_ms`, `slice_us`). Ending the identity's last session doesn't stop it either.
- **Handlers don't check for `cancel()` by default.** With `limits.cancel_checks = kRequests` (the default) only requests and tasks check; a timer, frame callback, event handler or patch handler hit from game code runs unchecked, so `sandbox::cancel()` from a watchdog thread can't stop one stuck in a loop. Set `kEverything` for that (every handler then pays the per-instruction hook), or a limit. `kNone` turns checking off entirely: a cancel then stops a request only before it starts or resumes.
- **Tasks without waits hold the pump.** A task is cooperative. Without `rhp.sleep` / `rhp.wait` / `rhp.next_frame` / `rhp.wait_event`, or `limits.slice_us`, it runs until its per-resume budget stops it.
- **Script events stay in one identity.** `rhp.publish` reaches only the same key's sandbox. To bridge identities, forward in C++ with `host.on_script_event`.
- **Script event values are data.** No functions, userdata or handles. Delivery is one pump later, never synchronous.
- **Mistyped C++ event names aren't errors.** `rhp.on` with a name no C++ `lua_event` registered subscribes to script events of that name.
- **Event queues drop when full.** `limits.event_queue` (65,536 by default) caps queued events per sandbox. Extras are dropped and counted (`rhp.stats().dropped_events`), including `rhp.handler_failed` reports to Lua (C++ still gets `on_handler_error` and `handler_failed`).
- **Remote events are rate-limited, not backlog-limited.** `host_options::remote_events_per_pump` bounds what one pump sends a session. A session that stays disconnected, or stops reading, while busy events keep flowing still ends at its unacknowledged-bytes limit (64 MiB).
- **Remote event arguments are values.** A C++ event argument whose type has no `Rhp::convert` (a handle-only type) arrives at clients as nil.
- **No event stream over HTTP.** The HTTP gateway serves requests only. Use a native session (`client.on`, `rhp-cli events`) to watch events.
- **Tasks take the sandbox's error policy.** `rhp.spawn` has no options table. There is no `task:join(timeout)` yet.
- **Patch handlers always fault their module on error.** The handler error policy covers timers, frame callbacks, event handlers and tasks only.

## Binding and scripting

- **Lua 5.5 only, one script engine.** There is no second engine and no `config<>::engine<>` slot yet.
- **No class binding.** `Rhp::lib` binds functions, variables and opaque handles with methods and properties. Handles must be trivially copyable, equality-comparable, non-arithmetic value types. There is no inheritance.
- **Text chunks only.** Binary Lua chunks are always refused, for every role and every client operation. The one exception is C++: `sandbox::exec_cached` loads bytecode it compiled itself from a trusted source (the test framework). Non-admin roles have no `io`, `os` (except `time` / `clock`), `debug`, `package`, `dofile`, `loadfile` or `collectgarbage`.
- **`require` finds loaded modules only.** It looks in the same identity's loaded modules, never the file system.
- **Single-threaded sandboxes.** Lua runs only on the thread that calls `pump()` (or the operation). Patch points hit from another thread run the C++ default.

## Testing scripts

- **One runner, one thread.** Test files run one after another; the runner pumps its sandboxes itself. Code that needs other threads (a network round trip) belongs in C++ tests.
- **Process-wide points and events.** A test executable shares patch points and C++ events between files. Each test's patches are undone, but C++ code running in the background of the executable would see them while a test runs.
- **`test.call_point` needs value types.** Points whose parameters or result don't convert to `Rhp::value` can only be called from C++.
- **Costs of C++ aren't instructions.** Instruction counts are exact for Lua; time in C++ bindings shows in `time_ms` only, and C++ allocations aren't in the memory figures.
- **Coverage costs about 2-3x** on line-dense code (Lua's line hook), so it is opt-in.
- **Lua-level fuzzing.** `test.fuzz` generates and mutates Lua values; it finds logic errors in scripts, not memory errors in C++ (that is what `Tests/fuzz` and libFuzzer are for).
- **No watch mode in the runner.** The VS Code extension re-lists files on save; a terminal runner reruns on demand.

## Networking

- **Session state doesn't survive a host restart.** Resume covers a dropped connection within `limits.resume_ms` (6 s by default). A restarted host starts fresh, and identities without pins are reverted when their last session ends.
- **Protocol revisions must match exactly.** Stages 11 and 12 speak revision 6 (Stage 10 spoke 5, Stages 7 to 9 spoke 4). Older hosts, clients and `rhp-cli` builds are refused at connect time.
- **`io<zero_threads>` stops the network inside a stuck script.** A zero-thread host whose script is stuck in `pump()` also stops serving the network, so cancel can't reach it.
- **Mbed TLS is serialized.** Its calls go through one process-wide lock, because its PSA core isn't thread-safe in the default build.
- **Fleet broadcasts cover `exec`, `load` and `call`.** `rhp-cli fleet` runs `exec` only.
- **The HTTP gateway routes a subset of operations.** No rollback, checkpoint / revert_to, revert_all, pin / unpin, blob or subscriptions over HTTP.
- **No FEC on reliable UDP.** Loss is recovered by retransmission.
- **WebSocket isn't a browser endpoint.** It's a binary tunnel with RHP's own session (and TLS) inside, meant for proxies, not `wss://` browser clients.

## Platforms and validation

- **macOS / iOS haven't run on real hardware.** Hosted CI builds and tests them (except the cases below). The Apple DNS-SD backend has only been built.
- **Hosted CI leaves some tests out.**
  - Real multicast cases are skipped on hosted Windows and Apple runners.
  - On hosted macOS, the three cross-process `rhp-cli` ↔ `headless_server` tests fail (the spawned host stops listening after its first connection) and are excluded until someone debugs them on a Mac.
- **Validation is mostly Debug.** Recorded test results are Debug builds; benchmarks run Release. Long libFuzzer runs aren't part of the routine checks (CI runs one minute per target).
- **Coroutine yields throw in a few builds.** A yield is a jump (tens of nanoseconds) on Linux, Apple, Android and x64 Windows. It stays a C++ exception (microseconds) with the MSVC ABI outside x64, in a Windows process running with a CET shadow stack, and under ThreadSanitizer, so `rhp.next_frame` / `rhp.sleep` loops cost more there. See [performance](performance.md#coroutine-yields-rhp_lua_jump_yields).
