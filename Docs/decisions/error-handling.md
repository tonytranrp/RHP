# Error handling

**Decision**
- One error type `Rhp::error { errc, message, where, traceback }`; `Rhp::result<T> = std::expected<T, Rhp::error>`.
- The error mode is a config policy: `Rhp::errors::expected` (default) or `Rhp::errors::throwing`; `Rhp::unwrap` converts one call.
- Exceptions are allowed internally, never across the API in expected mode. RTTI allowed.

**Why:** game engines often build without exceptions at their boundaries; tools prefer exceptions. One policy serves both without two APIs.

**Alternatives:** exceptions only, `std::error_code` (too little context for script errors).

**Consequences:** binding trampolines catch C++ exceptions and turn them into Lua errors; Lua compiled as C++ keeps unwinding RAII-safe.
