# Error handling

**Decision**
- One error type `Rhp::error { errc, message, where, traceback }`; `Rhp::result<T> = std::expected<T, Rhp::error>`.
- The error mode is a config policy: `Rhp::errors::expected` (default) or `Rhp::errors::throwing`; `Rhp::unwrap` converts one call.
- Exceptions are allowed internally, never across the API in expected mode. RTTI allowed.

**Why:** game engines often build without exceptions at their boundaries; tools prefer exceptions. One policy serves both without two APIs.

**Alternatives:** exceptions only, `std::error_code` (too little context for script errors).

**Consequences:** binding trampolines catch C++ exceptions and turn them into Lua errors; Lua compiled as C++ keeps unwinding RAII-safe.

**Stage 3 (as built):** `Rhp::error` crosses the wire as a map (`code` by name, `message`, `where`, `traceback`; unknown code names arrive as `kRuntime`). `Rhp::host` / `Rhp::client` honour `config<>::errors<>`: with `throwing` their calls return `T` and throw `Rhp::exception`.
