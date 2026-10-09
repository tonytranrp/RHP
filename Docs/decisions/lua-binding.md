# Lua binding

**Decision:** our own concept-based binder behind the `Rhp::lib<"name">::fn<...>::var<...>::handle<...>` DSL. Binding depth: free functions, variables, opaque handles. No class/inheritance binding.

**Why**
- Every registration must go through the undo ledger so it can be reverted; off-the-shelf binders register straight into global tables.
- Predictable compile times (~1 kLOC, instantiated per binding, not per usertype graph).

**Alternatives**
- sol2 — no commits since Mar 2025; unreleased fixes for GCC 15; no Lua 5.5 support.
- LuaBridge3 — active and MIT; kept as the fallback if full class binding is ever needed.

**Consequences**
- `Rhp::convert<T>` is the single customization point for marshaling (no reflection-based automation).
- Stale handles raise a Lua error (`kStaleHandle`), never silently return nil.

**Stage 1 (as built)**
- Each lib is a locked userdata proxy (`__index` / `__newindex`, `__metatable = "locked"`): `rawset` can't bypass journaling, unknown reads are `nil`, writes to unknown, function or `ro` members raise `kInvalidArgument`.
- Names and tag combinations are checked on the `::fn<>` / `::var<>` line; whether every type crosses the Lua boundary is checked by `sandbox::install<L>()` (the `installable` concept), because handles may be declared after the functions that use them.
- Handles are trivially copyable, equality-comparable, non-arithmetic value types (strong ids), pushed as userdata with `__eq` / `__tostring`; handle names and types are unique across a lib tree.
- `Rhp::undo<G>` is fed the binding's result (with `Rhp::result<>` peeled off) or, failing that, its arguments (string views copied).
- Errors raised inside Lua are strings `[code] where: message`; C++ gets the original `Rhp::error` back.

**Stage 2 (as built)**
- `Rhp::lua_event<"name", Args...>`: arguments are `Rhp::convertible` or opaque handle types; a handle argument arrives as the handle userdata of whichever installed lib declares that C++ type (looked up by type tag), else through `Rhp::convert`, else `nil`.
- `Rhp::script::stubs::generate<L>(role)` emits LuaLS annotations at compile time, filtered by role; `sandbox::stubs()` joins the `rhp` API with every installed lib.
