# Stage 8 packaging, hardening and performance decisions

Usage: [getting started](../guide/getting-started.md#installed-package), [configuration](../guide/configuration.md) and [benchmarks](../benchmarks.md). Stage 8 makes RHP something a stranger can install and depend on, fixes the threading and lifetime defects found by reviewing Stages 0-7, and measures the hot paths against raw Lua so the overhead RHP adds is a number rather than a guess. Decision ids AG* are in [ARCHITECTURE.md](../ARCHITECTURE.md) §34.

## Hardening

- **What:** every transport declares `static constexpr bool network` (a transport that doesn't fails to compile), so a custom network transport can't end up outside the TLS policy by omission; `net::link_decorator` forwards every query (`loopback`, `encrypted`, `channel_binding`) of the link it wraps. `stderr_logger`'s level is atomic and host logging formats only when the level passes. Setup calls (`install`, `on_blob`, `advertise`, ...) report `kInvalidArgument` off the pump thread once pumping started. `pending` is move-only and keeps its request id after `co_await`; a moved-from one reports "already taken". RHP's own reads and writes of a bound variable are serialized across sandboxes on different threads. Unsubscribing (host hub, script listeners, `lua_event` detach) waits for a call of that callback running on another thread. A blocking client call from the client's own network thread fails instead of deadlocking; a client destroyed from one of its callbacks hands its engine to the I/O thread; a callback that throws is dropped instead of ending the session. `Rhp::undo` fed with arguments accepts `string_view` parameters.
- **Why:** each was reproduced by a test first (they are regression tests now): races under TSan, deadlocks and use-after-free in callbacks, and one silent security hole (a custom transport without `network` skipped TLS).
- **Alternatives:** documenting the rules instead of enforcing them (the defects were all rule violations nobody would notice until production); a global lock around callbacks (would deadlock re-entrant callbacks).
- **Consequences:** a custom transport must add one line. Unsubscribing from inside the callback being unsubscribed still works (the barrier skips the calling thread); unsubscribing while holding a lock the callback takes, while another thread dispatches it, deadlocks, as documented on `listener_table`.

## Build configuration header

- **What:** CMake generates `<rhp/build_config.hpp>` (installed with `Rhp::core`) with `RHP_ENABLE`, `RHP_TLS_HAS_OPENSSL`, `RHP_TLS_HAS_MBEDTLS` and the target OS. Every public header that branches on them includes it. A translation unit that defines one of them differently fails to compile (`#error`); one that sees RHP's headers through an include path only still agrees with the library. The targets keep defining the macros too.
- **Why:** headers used to default `RHP_ENABLE` to 1 when it was missing, and a target that named only `Rhp::config` saw `tls::none` while the library used OpenSSL: the same type with two layouts, an ODR violation nothing reported.
- **Alternatives:** compile definitions only (the old state); the header only (breaks code that tests `#if RHP_ENABLE` before including an RHP header).
- **Consequences:** `Rhp::config` links `Rhp::tls`. `compile_fail` tests prove a mismatched `RHP_ENABLE` or platform doesn't compile.

## Package

- **What:** `RHP_INSTALL` (default: top level) installs headers, archives, the third-party archives RHP links (`lib/rhp/`), the `rhp` package (`lib/cmake/rhp`, targets `Rhp::<module>` and `Rhp::rhp`) and the licenses (`share/doc/rhp`). Third-party headers stay in the build tree. The package has no version: `find_package(rhp 1.0)` never matches, and it refuses another OS, pointer size, Android ABI or C++ ABI. It reports `rhp_STAGE`, `rhp_PROTOCOL_REVISION`, `rhp_ENABLE`, `rhp_TLS_HAS_*` and `rhp_PLATFORM`. On MSVC each configuration maps only to an installed configuration with the same runtime. `Tests/package` is a separate project built against the installed tree by ctest (`package.install`, `package.find_package`) and CI (Debug + Release in one prefix, `find_package` and `add_subdirectory`).
- **Why:** an SDK prefix is how most C++ shops consume a library; the subdirectory route alone forced every consumer to build Lua, Asio and Mbed TLS. No numbers because RHP counts stages, and a fake `1.0` would be a promise nobody is keeping.
- **Alternatives:** a version file with a made-up number; exporting third-party headers (would let consumers include `lua.h` and freeze RHP's dependency choices into their code); Conan / vcpkg recipes first (they can wrap this package later).
- **Consequences:** RHP's static libraries default to position-independent code and hidden visibility, Debug archives get a `d` postfix and MSVC debug info is embedded (`/Z7`), each only when the parent didn't set it. `RHP_WARNINGS_AS_ERRORS` defaults to top level only. Mbed TLS is configured inside `block()` with normal variables (no `FORCE`d cache entries leaking into a parent; the few its own scripts create are removed), its targets carry the prefix `rhp_mbedtls_` (a parent may build its own Mbed TLS next to RHP's) and it is built under RHP's own binary directory. A Debug MSVC consumer needs a Debug RHP installed.

## Dependency pins

- **What:** each git dependency is fetched by tag and its checkout checked against the commit the tag named when pinned (a warning when git isn't found); CPM.cmake is checked against its SHA-256 on download and on every configure; the Mbed TLS tarball keeps its SHA-256. `CPM_USE_LOCAL_PACKAGES` is off. `CPM_<name>_SOURCE` skips the check (a deliberate override). `NOTICE` and `THIRD_PARTY_LICENSES.md` list what a build contains and under which terms.
- **Why:** a tag can be moved upstream; a configure must never build code nobody reviewed.
- **Alternatives:** pinning `GIT_TAG` to the SHA (disables shallow clones and invalidates every existing cache directory); vendoring (a second copy to keep in sync).
- **Consequences:** a parent project that already added the same package with another commit fails the configure with a message naming `CPM_<name>_SOURCE`.

## Cancel scope

- **What:** `Rhp::limits::cancel_checks` (`Rhp::cancel_scope`) says which runs check for `cancel()`: `kRequests` (default: request coroutines of exec, load, call, reload and tasks, and the main thread while an operation runs), `kEverything` (handler calls too), `kNone`. The instruction, wall-time and slice limits still arm the hook everywhere.
- **Why:** the check is a count hook, and while any hook is set Lua traps every instruction: a tight loop ran 1.8x and recursive code 2.4x slower than raw Lua. The host's cancel relay only ever targets requests (a client cancels what it sent), so handlers paid for checks nobody could trigger.
- **Alternatives:** arming the hook from the cancelling thread (`lua_sethook` walks the call stack: unsafe from another thread); a larger check interval (the trap is per instruction regardless of the count).
- **Consequences:** `sandbox::cancel()` from a watchdog thread no longer stops a handler stuck in a loop unless `kEverything` is set; limits still do. Tests cover both scopes.

## Allocator

- **What:** `sandbox_options::memory == nullptr` allocates from the C heap with `realloc`, as Lua's own allocator does. A supplied `memory_resource` keeps the allocate-copy-free path.
- **Why:** growing a Lua string buffer or table through `allocate` + `memcpy` + `deallocate` cost up to 3x on string-heavy code; `realloc` grows blocks in place.
- **Alternatives:** keeping `std::pmr::get_default_resource()` as the default (it can't grow in place).
- **Consequences:** a program that replaced global `operator new` to count memory no longer sees Lua's allocations unless it passes a resource; `limits.memory` and `memory_used()` work either way.

## Coroutine yields

- **What:** with `RHP_LUA_JUMP_YIELDS` (default on; ignored for the MSVC ABI) Lua's `LUAI_THROW` / `LUAI_TRY` are overridden in `cmake/lua/lua_cxx.cpp`: a yield `_longjmp`s back to its `lua_resume`, errors still throw C++ exceptions.
- **Why:** compiled as C++, every yield was a thrown exception (about 2-3 us); `rhp.next_frame` loops and tasks yield every frame. Errors keep throwing so RAII in bindings stays correct.
- **Alternatives:** all jumps (C++ destructors in bindings would be skipped on errors); compiling Lua as C (Lua errors would then skip RHP's C++ frames); continuations everywhere (yields would still unwind).
- **Consequences:** a C function that yields must hold no C++ object with a destructor at the yield (`rhp.wait`, `rhp.next_frame`, `rhp.sleep`, `rhp.wait_event`, `task:join`; `rhp.wait_event` takes its name as a view for this). MSVC keeps the exception path because its `longjmp` unwinds like one. The rule is in `CLAUDE.md` and next to the macros.

## Request reuse and idle work

- **What:** finished requests' map nodes, records and coroutines are pooled (64 each) and reused; a handler's error location is formatted only when it fails; clocks are read per run only with `wall_ms`; `pump()` remembers the earliest due timer / frame callback and the earliest wake of a suspended request and skips both walks while nothing is due (anything that can make something due sooner marks them dirty).
- **Why:** a handler call cost about 1 us, most of it a fresh coroutine, a registry entry, a map node and a formatted label; 10k idle timers cost 80 us per pump just to find nothing due.
- **Alternatives:** a priority queue of due times (every reschedule, pause and resume would have to update it); one coroutine per handler kept for life (handlers may suspend).
- **Consequences:** a reused coroutine is reset (empty stack, status OK, hook set for its kind) and stays in the request-thread set, so scripts still can't resume it; a script that kept `coroutine.running()` from an old request may later see the same thread object run another request.

## Patch points, bindings, signatures, frames

- **What:** an unpatched point calls its default directly (inlinable); a Lua patch layer builds its `original` closure and token once and points the token at each call's frame (restoring it after, for re-entrant calls). Lib proxies use their members table as `__index` (no C call to find a function); variables fall through to the getters. The host checks script signatures on the network thread and `pump()` uses the verdict; an Ed25519 secret key derives its public half once. CRC32C uses the CPU instruction (SSE4.2 checked at run time, ARMv8 CRC when targeted); frames are encoded with one allocation; client idempotency keys come from a random seed and a counter.
- **Why:** measured costs (see [benchmarks](../benchmarks.md)): a patched call was 10x a raw `lua_pcall`, a signature check put 0.1 ms on the game's frame, CRC32C ran at 2 GB/s.
- **Alternatives:** caching signature verdicts by source hash (a second cache to bound and invalidate; the network thread has the time).
- **Consequences:** the members table of a lib is reachable only through the proxy's locked metatable, as before.

## Benchmarks

- **What:** `Tests/bench` (`RHP_BUILD_BENCH`), Catch2 benchmarks named `<group> <raw|rhp|local>: <work>`; raw twins do the same work on a plain `lua_State`. `Tools/bench/summarize.py` and `compare.py` turn the XML reports into tables. ctest runs a smoke pass.
- **Why:** the user asked to find and remove what RHP wastes around Lua code; a ratio to the raw twin shows that directly and stays meaningful across machines.
- **Consequences:** numbers in `Docs/benchmarks.md` are from one machine; compare ratios, and rerun before claiming a regression.
