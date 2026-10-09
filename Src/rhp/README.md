# Src/rhp — the library

One folder per module. Each module is its own CMake target (`Rhp::<module>`), declared with `rhp_add_module()` from `cmake/RhpModule.cmake`.

## Rules

1. **Layers only point down.** A module may depend only on modules in a lower layer, and only by `DEPS` in its `CMakeLists.txt`.

   | Layer | Modules |
   |---|---|
   | 0 | `utils` |
   | 1 | `core` |
   | 2 | `wire`, `platform` |
   | 3 | `net`, `security`, `tls` (`security/tls/`), `exec`, `script`, `event` |
   | 4 | `session`, `audit` |
   | 5 | `host`, `client` |

2. **Folder = namespace.** `rhp/script/` is `Rhp::script`; `rhp/script/detail/` is `Rhp::script::detail` and is never used outside its module.
3. **Lowercase paths.** Everything here is an include path and Linux/Android/iOS file systems are case-sensitive.
4. **Third-party headers stay in `.cpp` files.** Lua, Asio, crypto and TLS headers never appear in a `.hpp` here.
5. **No OS `#ifdef`s outside `platform/`.** Compiler-specific pragmas are allowed where unavoidable.
6. **Files are listed explicitly** in each `CMakeLists.txt` — no globbing.
7. **`.cpp` files exist for a reason:** a dependency wall, a heavy table, or code that shouldn't be in every includer.
8. `rhp.hpp` includes every public header; keep it in sync when adding one.
9. **Layer 4–5 code stays out of templates.** `Rhp::host<Cfg>` / `Rhp::client<Cfg>` type-erase their config into function pointers and run engines compiled once (`host.cpp`, `client.cpp`); the session layer only sees abstract interfaces.

| Module | Layer | Third-party (PRIVATE, `.cpp` only) |
|---|---|---|
| `utils`, `core` | 0, 1 | — |
| `platform` | 2 | OS headers (`bcrypt`, `sys/random.h`) |
| `wire` | 2 | — (own MessagePack codec) |
| `net` | 3 | Asio |
| `security` | 3 | Monocypher |
| `tls` (`security/tls/`) | 3 | OpenSSL (system) and/or Mbed TLS 4.2 |
| `exec` | 3 | — (header-only) |
| `script` | 3 | Lua |
| `event` | 3 | — |
| `session`, `audit` | 4 | — |
| `config`, `host`, `client` | 5 | — |
