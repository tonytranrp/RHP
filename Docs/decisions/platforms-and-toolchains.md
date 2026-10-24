# Platforms and toolchains

**Decision**
- Platforms: Windows 10 1809+, Linux glibc 2.31+, macOS 13.3+, iOS 16.3+, Android API 26+; x86_64 and arm64. (13.3 / 16.3 rather than 13 / 16: Apple's libc++ ships floating-point `std::to_chars`, which `std::format` of a `double` needs, only from those releases. The first hosted macOS build, Stage 6 completion, failed on it.)
- Compilers: MSVC (VS 2026), clang-cl, Clang 17+ (only Clang 21/22 have been run), AppleClang, Android NDK r29+ Clang (tested with r29). GCC is not a target.

**Presets**
- `windows-msvc`, `windows-msvc-asan`, `windows-clang-cl`
- `linux-clang`, `linux-clang-asan`, `linux-clang-tsan`, `linux-clang-fuzz` (libFuzzer, RelWithDebInfo)
- `macos` (universal)
- `ios-sim` (Ninja; tests via `Tools/ios/simctl_run.sh`), `ios-device` (Xcode, build only)
- `android-x64` (emulator tests through `Tools/android/run_tests.py`), `android-arm64` (build; with `-DRHP_BUILD_TESTS=ON` the same runner tests on a phone)

**Verified so far (Stage 0, on the author's machine):**
- MSVC 19.51: all tests pass.
- clang-cl 22: all tests pass.
- MSVC ASan: all tests pass.
- Linux Clang 21 (WSL): all tests pass, including ASan+UBSan and TSan.
- macOS, iOS and Android presets are defined but not yet run (no Apple / NDK host available).

**Verified at Stage 1:** 118 tests (Lua 5.5.1 built as C++) pass on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan; an `RHP_ENABLE=OFF` MSVC build passes 82 tests without Lua.

**Consequences:** OS `#ifdef`s live in platform code and backend translation units; public headers expose no platform or Asio handles.

**Verified at Stage 3:** 324 tests (Asio 1.38.2 networking over loopback and TCP, Monocypher 4.0.3) pass on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan; the `RHP_ENABLE=OFF` MSVC build passes 137 tests without Lua, Asio or Monocypher.

**Verified at Stage 5:** 398 tests (TLS through Mbed TLS 4.2 on Windows and OpenSSL 3.5 + Mbed TLS on Linux, resume, fuzz replays) pass on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan (TSan builds use Mbed TLS: the system libcrypto isn't instrumented); `RHP_ENABLE=OFF` passes 155. Android NDK 29 (Clang 21) builds `android-arm64` and `android-x64`, and every suite passed on an arm64 phone (SM-S948U1, Android 16 / API 36) via `Tools/android/run_tests.py`. macOS and iOS still unverified on hardware: `.github/workflows/ci.yml` covers them (and an Android emulator) once Actions can run on the repo.

**Verified at Stage 6:** [Status and TODO](../TODO.md#stage-6-2026-10-09) records full Windows/Linux suites, final ASan/UBSan/TSan transport checks, OFF stubs, all 17 Android arm64 executables on the same device, separate-process IPC, real DNS-SD TLS fleet broadcasts and 1698586 seeded fuzzer inputs. Apple DNS-SD signatures/warnings were checked against the official header. Stage 6 local checks use Debug, with RelWithDebInfo for libFuzzer.

**Verified at Stage 6 completion (hosted CI):** macOS 15 (universal, Mbed TLS) and the iOS simulator run the suites on GitHub Actions, and the iOS device preset builds; real multicast is left out on hosted Windows/macOS/iOS and the `[process]` CLI cases on macOS (an open issue: [TODO](../TODO.md#open-items)). Getting there needed macOS 13.3 / iOS 16.3 targets, no floating-point `from_chars` in `rhp-cli`, no `-ldns_sd`, Asio's real `include/` and a Ninja-generated simulator preset.

**Verified at Stage 7:** 560/560 on MSVC 19.51, clang-cl 22, MSVC ASan, Linux Clang 21, Clang ASan+UBSan and Clang TSan (Mbed TLS); `RHP_ENABLE=OFF` 169/169. Not run: Android (hosted CI covers the emulator), Apple hardware, Release builds ([TODO](../TODO.md#stage-7-2026-10-17)).
