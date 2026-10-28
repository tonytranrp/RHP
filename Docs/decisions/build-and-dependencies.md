# Build, dependencies, workflow

**Decision**
- CMake ≥ 3.28, Ninja Multi-Config presets (Xcode for `ios-device`), C++23.
- CPM.cmake 0.42.3 (pinned with its SHA-256 in `cmake/CPM.cmake`, the bootstrap: the one pin outside `Dependencies.cmake`) with every other pin in `cmake/Dependencies.cmake`; consumers use CPM / `add_subdirectory` pinned to a stage tag (`stage-13`) or a commit, or (Stage 8) an installed package through `find_package(rhp CONFIG)`.
- Stage 8: each git pin names the commit its tag resolved to and the configure checks the checkout against it; CPM.cmake is checked against its SHA-256; Mbed TLS keeps its tarball SHA-256. RHP's targets are exported (`RhpTargets`, namespace `Rhp::`) with the third-party archives they link; third-party headers are build-tree only. See [Stage 8 decisions](stage8-packaging-performance.md).
- Static libraries, one per module (`rhp_add_module`); pure templates header-only, `.cpp` only for dependency walls.
- Warnings as errors (`/W4 /WX`, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror`).
- Sanitizer presets: MSVC ASan, Clang ASan+UBSan, Clang TSan.
- Catch2 v3 and compile-fail tests.
- Desktop and simulator test presets use `ctest`; Android suites use the adb runner. GitHub Actions (`.github/workflows/ci.yml`) runs Linux (Clang, ASan+UBSan, TSan), Windows (MSVC, clang-cl), Apple (macOS, iOS simulator, iOS device build) and Android (emulator tests, arm64 build); platform verification is tracked in `Docs/TODO.md`.
- Git: branch + PR per stage, conventional commits.
- Header-based public API with compiled runtime/dependency walls; no C++20 modules, C API or reflection.

**Pins:** CPM.cmake 0.42.3, Catch2 v3.16.1 (Stage 0); Lua 5.5.1 (Stage 1, only when `RHP_ENABLE=ON`).

**Original planned pins (historical; the as-built notes below supersede these):**
- Asio 1.38.x and msgpack-c ≥ 9.0.0 (Stage 3)
- Monocypher ≥ 4.0.3, replxx, CLI11 (Stage 4)
- OpenSSL 4.0.x and mbedTLS 4.2 (Stage 5)

**Stage 4 (as built):** CLI11 `v2.7.2` (header-only) and replxx `release-0.0.4` (our own static target from its sources; upstream has been quiet since 2021) are pinned for `rhp-cli` only, fetched when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON`. Monocypher's optional Ed25519 is compiled through its own wrapper translation unit. `Tools/` is built after `Tests/`; `Tests/tools` runs the real `rhp-cli` and `headless_server` binaries.

**Stage 3 (as built):** Asio `asio-1-38-2` and Monocypher `4.0.3` are pinned in `cmake/Dependencies.cmake` (live builds only). msgpack-c is not a dependency: RHP has its own MessagePack codec (see wire-format). Monocypher is compiled as C++ (`cmake/monocypher/monocypher_cxx.cpp`), so the project still enables only CXX. Tests gain `Tests/integration/` and header-only helpers in `Tests/support/rhp_test/`.

**Stage 5 (as built):** TLS: the system's OpenSSL ≥ 3.0 (`find_package`, desktop only, `RHP_TLS_OPENSSL=AUTO|ON|OFF`) and Mbed TLS `4.2.0` from its release tarball (`RHP_TLS_MBEDTLS`, its own subproject with programs, tests and install rules off; it enables C, so presets name a C compiler). Both live in `Rhp::tls` (`Src/rhp/security/tls/`); `RHP_WITH_TLS=OFF` or `RHP_ENABLE=OFF` builds neither. `RHP_FUZZ=ON` adds libFuzzer instrumentation (Clang). `.github/workflows/ci.yml` is the CI.

**Stage 8 (as built):** no new dependencies. Pins by commit: Catch2 `08092139`, Lua `7579fc9d`, Asio `8806a680`, Monocypher `ab2b16dd`, CLI11 `cbd58a36`, replxx `2b248467` (full SHAs in `cmake/Dependencies.cmake` and `THIRD_PARTY_LICENSES.md`). `cmake/RhpBuildConfig.cmake` generates `<rhp/build_config.hpp>`; `cmake/RhpInstall.cmake`, `cmake/rhp-config.cmake.in`, `cmake/rhp-config-version.cmake.in` and `cmake/RhpLicenses.cmake` make the package; `Tests/package` consumes it. CI adds package, `RHP_ENABLE=OFF`, MSVC ASan and libFuzzer smoke jobs.

**Stages 6–7 (as built):** no new dependencies. Windows `rhp_net` links the system's `dnsapi`, `advapi32` and `iphlpapi`; Apple's DNS-SD API is part of libSystem. The top-level `CMakeLists.txt` sets `CMAKE_CXX_SCAN_FOR_MODULES OFF` (directory-scoped): RHP uses no C++20 modules, and clang-scan-deps mishandled clang-cl's system include paths on CI runners.
