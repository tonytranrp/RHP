# Platforms and toolchains

**Decision**
- Platforms: Windows 10 1809+, Linux glibc 2.31+, macOS 13+, iOS 16+, Android API 26+; x86_64 and arm64.
- Compilers: MSVC (VS 2026), clang-cl, Clang 17+, AppleClang, Android NDK r30 Clang. GCC is not a target.

**Presets**
- `windows-msvc`, `windows-msvc-asan`, `windows-clang-cl`
- `linux-clang`, `linux-clang-asan`, `linux-clang-tsan`
- `macos` (universal)
- `ios-sim` (tests via `simctl`, later stage), `ios-device` (build only)
- `android-x64` (emulator tests, later stage), `android-arm64` (build only)

**Verified so far (Stage 0, on the author's machine):**
- MSVC 19.51: all tests pass.
- clang-cl 22: all tests pass.
- MSVC ASan: all tests pass.
- Linux Clang 21 (WSL): all tests pass, including ASan+UBSan and TSan.
- macOS, iOS and Android presets are defined but not yet run (no Apple / NDK host available).

**Verified at Stage 1:** 118 tests (Lua 5.5.1 built as C++) pass on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan; an `RHP_ENABLE=OFF` MSVC build passes 82 tests without Lua.

**Consequences:** OS `#ifdef`s live only in `Src/rhp/platform`.

**Verified at Stage 3:** 324 tests (Asio 1.38.2 networking over loopback and TCP, Monocypher 4.0.3) pass on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan; the `RHP_ENABLE=OFF` MSVC build passes 137 tests without Lua, Asio or Monocypher.

**Verified at Stage 5:** 398 tests (TLS through Mbed TLS 4.2 on Windows and OpenSSL 3.5 + Mbed TLS on Linux, resume, fuzz replays) pass on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan (TSan builds use Mbed TLS: the system libcrypto isn't instrumented); `RHP_ENABLE=OFF` passes 155. Android NDK 29 (Clang 21) builds `android-arm64` and `android-x64`, and every suite passed on an arm64 phone (SM-S948U1, Android 16 / API 36) via `Tools/android/run_tests.py`. macOS and iOS still unverified on hardware: `.github/workflows/ci.yml` covers them (and an Android emulator) once Actions can run on the repo.
