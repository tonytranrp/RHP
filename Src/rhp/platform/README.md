# platform — layer 2

Operating-system facts and services behind portable C++ APIs. Namespace `Rhp::platform`.

| Header | What |
|---|---|
| `os.hpp` | `kOs` / `kOsName` — the target OS from `RHP_PLATFORM_*` (sent in the handshake) |
| `random.hpp` | `random_bytes(span)` / `random_array<N>()` — OS cryptographic randomness (nonces, idempotency keys) |
| `files.hpp` | `read_file`, `replace_file` (atomic: write a temporary, sync, rename), `stdin_is_terminal` / `stdout_is_terminal`, `enable_ansi_colors`, `binary_stdio` |
| `process.hpp` | `run_process(program, args)`: start a program sharing this process's standard streams and wait for its exit status (`rhp-cli test --exe`); `kDisabled` on iOS |

## Rules

- This is the folder for general OS facts: it may branch on `RHP_PLATFORM_*` and include OS headers (`windows.h`, `sys/*.h`) in `.cpp` files — `os.hpp` reads the CMake definition, nothing else. Transport and discovery backends (`net/local`, `net/mdns`) branch inside their own `.cpp` files.
- Sockets are not here: Asio (inside `Rhp::net`'s `.cpp` files) owns them.
- Processes: `CreateProcessW` with arguments quoted for `CommandLineToArgvW` (Windows), `fork` + `execvp` (Linux, macOS, Android: `posix_spawn` needs Android API 28, the presets target 26). iOS apps can't start processes.
- Randomness: `BCryptGenRandom` (Windows), `getrandom` (Linux), `arc4random_buf` (Apple, Android — bionic has it at every supported API level).
