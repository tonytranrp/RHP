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
