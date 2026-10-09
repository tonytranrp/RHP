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
