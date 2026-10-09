# RHP — Remote Hot Patch

A portable C++23 static library that lets a running program accept authenticated, signed Lua scripts over pluggable transports, run them in a sandbox against a C++-declared API, stream results back, and **undo everything they did**.

Lua is the glue, not the engine: scripts only reach what your C++ exposes through `Rhp::lib<...>` and `Rhp::patch_point<...>`.

```cpp
using game_lib = Rhp::lib<"game">
    ::fn <"spawn",   &game::spawn, Rhp::undo<&game::despawn>>
    ::var<"gravity", &game::g_gravity>;

Rhp::host<Rhp::config<>> host{ Rhp::endpoint::listen("127.0.0.1", 7777), keys, signers };
host.install<game_lib>();
while (game::running()) { host.pump(); game::update(); }
```

> The snippet shows where the library is going (the network host arrives in Stage 3). Work lands in stages; today the script engine runs locally:

```cpp
float default_damage(float base, float mult) { return base * mult; }
inline constexpr Rhp::patch_point<"combat.damage", &default_damage> damage{};

Rhp::script::sandbox box;                        // one identity: a Lua 5.5 state + undo ledger
box.install<game_lib>();
auto mod = box.load("low_grav", R"(
    game.gravity = -1.6
    rhp.patch("combat.damage", function(original, b, m) return original(b, m) * 2 end)
)");
box.revert(*mod);                                // gravity and damage are back
```

See [`Examples/hello_console`](Examples/hello_console).

## Targets

Windows 10 1809+ · Linux (glibc 2.31+) · macOS 13+ · iOS 16+ · Android API 26+ — x86_64 and arm64.
Compilers: MSVC (VS 2026), clang-cl, Clang 17+, AppleClang, Android NDK Clang.

## Build

```bash
cmake --preset windows-msvc
```

```bash
cmake --build --preset windows-msvc
```

```bash
ctest --preset windows-msvc
```

Other presets: `windows-clang-cl`, `windows-msvc-asan`, `linux-clang`, `linux-clang-asan`, `linux-clang-tsan`, `macos`, `ios-sim`, `ios-device`, `android-x64`, `android-arm64`. On Windows, run from a Developer PowerShell / prompt, or open the folder in Visual Studio.

## Use it

```cmake
CPMAddPackage(NAME rhp GITHUB_REPOSITORY tonytranrp/RHP GIT_TAG <commit-sha>)
target_link_libraries(my_app PRIVATE Rhp::rhp)
```

## Stages

| Stage | Contents | State |
|---|---|---|
| 0 | layout, CMake, presets, `utils`, `core` | ✅ |
| 1 | Lua 5.5 sandbox, `Rhp::lib` DSL, patch points, ledger, revert (local) | ✅ |
| 2 | scheduler, `rhp.emit`, `lua_event`, reload + revisions, `require`, LuaLS stubs | next |
| 3 | wire format, loopback + TCP, sessions, roles | |
| 4 | client, `rhp-cli`, signing, audit, blobs, reverse mode | |
| 5 | TLS, reconnect/resume, fuzzing, mobile presets | |
| 6 | WebSocket, UDP-reliable, HTTP gateway, mDNS, fleet | |

## Layout

| Folder | What lives there |
|---|---|
| `Src/rhp/` | the library, one folder per module (`utils`, `core`, `script`, …), included as `<rhp/...>` |
| `Tests/` | unit tests, compile-fail tests (later: integration, fuzz, bench) |
| `Examples/` | `hello_console`, `custom_transport`, `headless_server` |
| `Tools/` | `rhp-cli` |
| `Docs/` | [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) and [`decisions/`](Docs/decisions/) |
| `cmake/` | build helpers and the single dependency pin file |

## License

Apache-2.0 — see [LICENSE](LICENSE).
