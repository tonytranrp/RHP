# Build, dependencies, workflow

**Decision**
- CMake ≥ 3.28, Ninja Multi-Config presets (Xcode for iOS), C++23.
- CPM.cmake 0.42.3 with every pin in `cmake/Dependencies.cmake`; consumers use CPM / `add_subdirectory` pinned to a commit.
- Static libraries, one per module (`rhp_add_module`); pure templates header-only, `.cpp` only for dependency walls.
- Warnings as errors (`/W4 /WX`, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror`).
- Sanitizer presets: MSVC ASan, Clang ASan+UBSan, Clang TSan.
- Catch2 v3 and compile-fail tests.
- No CI yet; every preset runs locally with `ctest`.
- Git: branch + PR per stage, conventional commits.
- Headers only, no C++20 modules, no C API, no reflection.

**Pins:** CPM.cmake 0.42.3, Catch2 v3.16.1 (Stage 0); Lua 5.5.1 (Stage 1, only when `RHP_ENABLE=ON`).

**Planned pins:**
- Asio 1.38.x and msgpack-c ≥ 9.0.0 (Stage 3)
- Monocypher ≥ 4.0.3, replxx, CLI11 (Stage 4)
- OpenSSL 4.0.x and mbedTLS 4.2 (Stage 5)
