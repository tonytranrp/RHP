# Tools

| Tool | What | Arrives |
|---|---|---|
| [`rhp-cli/`](rhp-cli) | REPL and scripting client: `connect`, `exec`, `run`, `stubs`, `blob`, `watch`, `keygen`, `pubkey`, `sign`, `discover`, `fleet`, `events` (replxx + CLI11); `--tls`, `--ca`, `--server-name`, `--cert` / `--key` | Stage 4 ✅, TLS Stage 5 ✅, discovery / fleet Stage 6 ✅, events Stage 7 ✅ |
| [`android/run_tests.py`](android/run_tests.py) | runs a build's test executables on an Android device or emulator over adb | Stage 5 ✅ |
| [`ios/simctl_run.sh`](ios/simctl_run.sh) | the `ios-sim` preset's `CMAKE_CROSSCOMPILING_EMULATOR`: runs simulator executables with `xcrun simctl spawn` | Stage 5 ✅ |

```bash
cmake --preset android-arm64 -B build/android-arm64-tests -DRHP_BUILD_TESTS=ON
```

```bash
cmake --build build/android-arm64-tests --config Debug
```

```bash
python Tools/android/run_tests.py build/android-arm64-tests
```

## Rules

- Tools are clients of the public API like any user program.
- `rhp-cli` is built when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON` (desktop presets only).
- The Android presets need `ANDROID_NDK_HOME` (NDK r29 or newer).
