# platform — layer 2

Operating-system facts and services behind portable C++ APIs. Namespace `Rhp::platform`.

| Header | What |
|---|---|
| `os.hpp` | `kOs` / `kOsName` — the target OS from `RHP_PLATFORM_*` (sent in the handshake) |
| `random.hpp` | `random_bytes(span)` / `random_array<N>()` — OS cryptographic randomness (nonces, idempotency keys) |

## Rules

- This is the **only** folder allowed to branch on `RHP_PLATFORM_*` or include OS headers (`windows.h`, `sys/*.h`), and only in `.cpp` files — `os.hpp` reads the CMake definition, nothing else.
- Sockets are not here: Asio (inside `Rhp::net`'s `.cpp` files) owns them.
- Randomness: `BCryptGenRandom` (Windows), `getrandom` (Linux), `arc4random_buf` (Apple, Android — bionic has it at every supported API level).
