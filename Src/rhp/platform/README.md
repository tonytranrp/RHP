# platform — layer 2

Operating-system facts and services behind portable C++ APIs. Namespace `Rhp::platform`. Target `Rhp::platform`; depends on `core` (privately on `bcrypt` on Windows).

| Header | What |
|---|---|
| `os.hpp` | `os_kind`, `kOs` / `kOsName`: the target OS from `RHP_PLATFORM_*` (sent in the handshake and in discovery records) |
| `random.hpp` | `random_bytes(span)` / `random_array<N>()`: OS cryptographic randomness (nonces, keys, idempotency keys) |
| `files.hpp` | `read_file`; `replace_file` (atomic: write a temporary next to it, flush, rename); `make_private_directory` (owner-only on POSIX); `stdout_is_terminal`, `stdin_is_terminal`, `enable_ansi_colors`, `binary_stdio` |
| `process.hpp` | `run_process(program, args)`: start a program that shares this process's standard streams and wait for its exit status (`rhp-cli test --exe`); `environment_variable(name)` |

```cpp
auto bytes = Rhp::platform::read_file("keys.txt");          // kNotFound / kRuntime on failure
auto nonce = Rhp::platform::random_array<32>();
auto saved = Rhp::platform::replace_file("state.bin", *bytes); // old file or new file, never a mix
```

## Rules

- This is the folder for general OS facts: it may branch on `RHP_PLATFORM_*` and include OS headers (`windows.h`, `sys/*.h`) in its `.cpp` files. `os.hpp` reads the CMake definition and nothing else. Transport and discovery backends (`net/local`, `net/mdns`) branch inside their own `.cpp` files.
- Sockets are not here: Asio (inside `Rhp::net`'s `.cpp` files) owns them.
- Randomness: `BCryptGenRandom` (Windows), `getrandom` (Linux), `arc4random_buf` (Apple, Android: bionic has it at every supported API level).
- Processes: `CreateProcessW` with arguments quoted for `CommandLineToArgvW` (Windows); `fork` + `execvp` (Linux, macOS, Android: `posix_spawn` needs Android API 28, the presets target 26). iOS apps can't start processes: `run_process` reports `kDisabled` there.
- `replace_file` can leave a `*.tmp` file behind after a crash between write and rename; the temporary is owner-readable only on POSIX and takes the folder's permissions on Windows. The release `directory_store` relies on it and on `make_private_directory`.
