# Lua runtime

**Decision:** PUC Lua 5.5, fetched with CPM and compiled **as C++** by our own CMake target. One `lua_State` per key identity, one `_ENV` per module.

**Why**
- Lua 5.4.9 (Aug 2026) is the final 5.4 release; 5.5 is the maintained line.
- Stage 8: coroutine yields jump (`_longjmp`) instead of throwing on every toolchain but the MSVC ABI (`RHP_LUA_JUMP_YIELDS`), errors still throw. ThreadSanitizer builds keep throwing yields (Stage 12): TSan's shadow call stack doesn't follow the jumps, and a request yielding some thousands of times crashed it. A yield cost 2-3 us as an exception; C functions that yield must hold no C++ object with a destructor at that point. See [Stage 8 decisions](stage8-packaging-performance.md#coroutine-yields). x64 MSVC and clang-cl jump too (the overall optimization pass): the CRT's longjmp skips unwinding when the buffer's frame is cleared after setjmp. A process with a CET shadow stack (an executable linked `/CETCOMPAT` on a CPU with CET) can't take that jump, so there yields still throw; `RDSSP` tells the two apart once per process, and `rhp_script_cet_tests` runs the yield tests linked `/CETCOMPAT`.
- Plain portable C: no JIT question on iOS, every hook we need (`load` mode `"t"`, count hooks that may `lua_yield`, `lua_Alloc`, `_ENV`).
- Compiled as C++, `lua_error` unwinds with exceptions, so RAII in binding trampolines stays correct.

**Alternatives**
- Luau — built-in sandbox and type checker, first-class CMake; rejected for weekly C-API churn, Lua 5.1 API and an on-device compiler.
- LuaJIT — interpreter-only on iOS, no CMake, `ffi` is a sandbox hazard.
- Luau as a second engine, for speed (re-examined in the Lua speed pass, 2026-10-25): not now. After the safe-point hook RHP runs pure Lua within about 0-15% of raw PUC 5.5, and typical hot-patch scripts spend their time in bindings, patch points, events and the scheduler, which a faster bytecode loop doesn't touch. Third-party numbers put Luau's interpreter about 1.6-1.8x ahead of Lua 5.4 on compute-bound code (no 5.5 comparison found); its native codegen needs executable memory (none on iOS) and annotated code. Costs: a different dialect (no integer subtype, bitwise operators, `goto`, `<close>`, `_ENV`, `math.type`, `load`; RHP's `property.lua`, several tests and the int64 wire value depend on them, so signed scripts would split by engine); `lua_*` / `lua_State` symbols that clash with PUC Lua's, so both can't link into one binary without a renaming layer (a build-time engine choice, not a `config<>::engine<>` type slot); yields built on continuations, which changes `detail::yield_async` in public detail headers; weekly upstream releases with C-API changes (0.738-0.744 alone renamed or reshaped embedder APIs). Estimate: 12-18 person-weeks for exec / call / load with bindings and limits, 19-29 for parity with the debugger, profiler and test engine. Revisit only for users who want the Luau dialect itself or a measured compute-bound workload, after a one-week gate: raw Luau against raw PUC 5.5 on the `lua raw:` benchmark twins, proceeding only at about 1.5x or more.

**Consequences**
- Binary chunks are never loaded (`load` forced to `"t"`, `string.dump` removed).
- `_ENV` isolation leaks through shared metatables, so separation between identities uses separate states.

**Stage 1 (as built)**
- Lua 5.5.1 is fetched from `github.com/lua/lua` (tag `v5.5.1`, download only) and compiled as one C++ translation unit through upstream's `onelua.c` (`cmake/lua/lua_cxx.cpp`, target `Rhp::lua`), with `LUA_USE_APICHECK` in Debug.
- Every role gets a text-only `load` that defaults to the caller's environment; a module's `_G` is its own `_ENV`. Non-admin roles get `os.time` / `os.clock` only and no `string.dump`, `dofile`, `loadfile`, `collectgarbage`, `require`, `io`, `package` or `debug`.
- `puc_lua` is the only engine. `Rhp::script::stack` is the engine boundary; a formal `engine` concept for `config<>::engine<>` arrives with a second engine.

**Stage 2 (as built):** `require` is the host loader for every role (admin included; `package` stays admin-only but never loads files through `require`). The `rhp` global gains `wait`, `next_frame`, `sleep`, `frame`, `timer`, `on`, `off` and `emit`. `coroutine.resume` / `coroutine.close` refuse the scheduler's request coroutines.

**Stage 7 (as built):** the `rhp` table gains `after`, `every`, `every_frame`, `every_frames`, `pause`, `resume`, `reschedule`, `timers`, `once`, `on_error`, `publish`, `wait_event`, `stats`, `spawn` and `tasks` ([Stage 7 decisions](stage7-scheduling-events.md)).
