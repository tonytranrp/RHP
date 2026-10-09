# Naming and code style

**Decision**

| Rule | Choice |
|---|---|
| Everything | `snake_case` (std-like) |
| Root namespace | `Rhp::`; sub-namespaces snake_case (`Rhp::script`); include root `<rhp/...>` |
| Constants & enum values | `kPascal` |
| Template parameters | short PascalCase (`T`, `Cfg`, `Fn`), constrained in the parameter list |
| Data members | trailing underscore (`ledger_`); public members of aggregates/structural types are plain |
| Macros / CMake | `RHP_*`; target `Rhp::rhp`, modules `Rhp::<module>` |
| Format | 4 spaces, attached braces, no column limit, `int* p`, `template <...>` on its own line, one-liners only empty/in-class, includes std → third-party → rhp (`.clang-format`) |
| Files | `.hpp` / `.cpp`, `#pragma once`; tests `<thing>_tests.cpp` |
| Strings | `std::string_view` in, `std::string` out, UTF-8 |
| Lua side | global table `rhp`; module hooks `M.on_load`, `M.on_unload`, `M.on_save`, `M.on_restore`; names dotted lowercase |
| Versions | **never** `v1` / `v2` / `V*` in identifiers, files, folders, namespaces or tags — progress is tracked as stages |

**Why:** user's established style; std-like names read naturally next to the standard library in heavy `<>::` chains.
