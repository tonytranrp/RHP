# Lua runtime

**Decision:** PUC Lua 5.5, fetched with CPM and compiled **as C++** by our own CMake target. One `lua_State` per key identity, one `_ENV` per module.

**Why**
- Lua 5.4.9 (Aug 2026) is the final 5.4 release; 5.5 is the maintained line.
- Plain portable C: no JIT question on iOS, every hook we need (`load` mode `"t"`, count hooks that may `lua_yield`, `lua_Alloc`, `_ENV`).
- Compiled as C++, `lua_error` unwinds with exceptions, so RAII in binding trampolines stays correct.

**Alternatives**
- Luau — built-in sandbox and type checker, first-class CMake; rejected for weekly C-API churn, Lua 5.1 API and an on-device compiler.
- LuaJIT — interpreter-only on iOS, no CMake, `ffi` is a sandbox hazard.

**Consequences**
- Binary chunks are never loaded (`load` forced to `"t"`, `string.dump` removed).
- `_ENV` isolation leaks through shared metatables, so separation between identities uses separate states.
