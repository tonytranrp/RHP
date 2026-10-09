# Build, dependencies, workflow

**Decision**
- CMake ≥ 3.28, Ninja Multi-Config presets (Xcode for iOS), C++23.
- CPM.cmake 0.42.3 with every pin in `cmake/Dependencies.cmake`; consumers use CPM / `add_subdirectory` pinned to a commit.
- Static libraries, one per module (`rhp_add_module`); pure templates header-only, `.cpp` only for dependency walls.
- Warnings as errors (`/W4 /WX`, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror`).
- Sanitizer presets: MSVC ASan, Clang ASan+UBSan, Clang TSan.
- Catch2 v3 and compile-fail tests.
- Every preset runs locally with `ctest`; GitHub Actions (Stage 5) builds and tests Linux, Windows, macOS, the iOS simulator and Android.
- Git: branch + PR per stage, conventional commits.
- Headers only, no C++20 modules, no C API, no reflection.

**Pins:** CPM.cmake 0.42.3, Catch2 v3.16.1 (Stage 0); Lua 5.5.1 (Stage 1, only when `RHP_ENABLE=ON`).

**Planned pins:**
- Asio 1.38.x and msgpack-c ≥ 9.0.0 (Stage 3)
- Monocypher ≥ 4.0.3, replxx, CLI11 (Stage 4)
- OpenSSL 4.0.x and mbedTLS 4.2 (Stage 5)

**Stage 4 (as built):** CLI11 `v2.7.2` (header-only) and replxx `release-0.0.4` (our own static target from its sources; upstream has been quiet since 2021) are pinned for `rhp-cli` only, fetched when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON`. Monocypher's optional Ed25519 is compiled through its own wrapper translation unit. `Tools/` is built after `Tests/`; `Tests/tools` runs the real `rhp-cli` and `headless_server` binaries.

**Stage 3 (as built):** Asio `asio-1-38-2` and Monocypher `4.0.3` are pinned in `cmake/Dependencies.cmake` (live builds only). msgpack-c is not a dependency: RHP has its own MessagePack codec (see wire-format). Monocypher is compiled as C++ (`cmake/monocypher/monocypher_cxx.cpp`), so the project still enables only CXX. Tests gain `Tests/integration/` and header-only helpers in `Tests/support/rhp_test/`.

**Stage 5 (as built):** TLS: the system's OpenSSL ≥ 3.0 (`find_package`, desktop only, `RHP_TLS_OPENSSL=AUTO|ON|OFF`) and Mbed TLS `4.2.0` from its release tarball (`RHP_TLS_MBEDTLS`, its own subproject with programs, tests and install rules off; it enables C, so presets name a C compiler). Both live in `Rhp::tls` (`Src/rhp/security/tls/`); `RHP_WITH_TLS=OFF` or `RHP_ENABLE=OFF` builds neither. `RHP_FUZZ=ON` adds libFuzzer instrumentation (Clang). `.github/workflows/ci.yml` is the CI.
