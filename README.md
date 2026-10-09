# RHP — Remote Hot Patch

A portable C++23 static library that lets a running program accept authenticated, signed Lua scripts over pluggable transports, run them in a sandbox against a C++-declared API, stream results back, and **undo everything they did**.

Lua is the glue, not the engine: scripts only reach what your C++ exposes through `Rhp::lib<...>` and `Rhp::patch_point<...>`.

```cpp
using game_lib = Rhp::lib<"game">
    ::fn <"spawn",   &game::spawn, Rhp::undo<&game::despawn>>
    ::var<"gravity", &game::g_gravity>;

Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 7777),
                 *Rhp::security::keyring::from_file("keys.txt"),               // who may connect, with which role
                 *Rhp::security::trusted_signers::from_file("signers.pub")};   // whose scripts may run
host.install<game_lib>();
auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
while (game::running()) { host.pump(); game::update(); }    // Lua runs only here; the network has its own thread
```

```bash
rhp-cli keygen dev                                   # dev.rhpid + the lines for keys.txt and signers.pub
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid          # REPL; every script is signed
```

```cpp
auto id = *Rhp::security::identity_file::load("dev.rhpid");
Rhp::client<> dev{Rhp::endpoint::dial("127.0.0.1", 7777), id.credential(), *id.signer_key()};
auto g   = dev.exec<double>("return game.gravity");          // Rhp::result<double>
auto mod = dev.load("low_grav", "game.gravity = -1.6");      // signed automatically
auto t   = co_await dev.async().exec<int>("return game.tick");
dev.unload(*mod);                                              // or just disconnect: everything is reverted
```

Every connection authenticates with a pre-shared key (mutual BLAKE2b challenge-response); each key is an identity with its own Lua state and a role (`observe`, `patch`, `admin`). Scripts from patch and admin must be Ed25519-signed by a developer key the host trusts. Frames carry CRC32C and a per-session MAC, are acked, nacked and resent, and a heartbeat ends dead sessions. Hosts can also dial out to a listening client (reverse mode, for phones and NAT), accept blobs into registered sinks, and keep admin-pinned modules after a disconnect. Until TLS (Stage 5) TCP stays on loopback unless you opt in with `Rhp::net::insecure_lan`.

The same script engine also runs locally, without a network:

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

Scripts can spread work over frames, and modules reload without losing state:

```cpp
Rhp::script::sandbox box{{.limits = {.slice_us = 2'000}}};   // opt-in: no script blocks a frame
box.exec("while true do rhp.next_frame() end");             // returns at once, continues in pump()
box.reload(*mod, new_source);                                // on_save() → on_restore(), old revision reverted
while (running) { box.pump(); game::update(); }
```

See [`Examples/hello_console`](Examples/hello_console), [`Examples/frame_loop`](Examples/frame_loop), [`Examples/remote_exec`](Examples/remote_exec), [`Examples/custom_transport`](Examples/custom_transport), [`Examples/headless_server`](Examples/headless_server) and [`Tools/rhp-cli`](Tools/rhp-cli).

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
| 2 | scheduler, `rhp.emit`, `lua_event`, reload + revisions, `require`, LuaLS stubs | ✅ |
| 3 | wire format, loopback + TCP, sessions, PSK roles, blocking client | ✅ |
| 4 | async client, `rhp-cli`, signing, audit, blobs, reverse mode, pin | ✅ |
| 5 | TLS, reconnect/resume, fuzzing, mobile presets | next |
| 6 | WebSocket, UDP-reliable, HTTP gateway, mDNS, fleet | |

## Layout

| Folder | What lives there |
|---|---|
| `Src/rhp/` | the library, one folder per module (`utils`, `core`, `platform`, `wire`, `net`, `security`, `exec`, `script`, `event`, `audit`, `session`, `config`, `host`, `client`), included as `<rhp/...>` |
| `Tests/` | unit, integration, tools and compile-fail tests (later: fuzz, bench) |
| `Examples/` | `hello_console`, `frame_loop`, `remote_exec`, `custom_transport`, `headless_server` |
| `Tools/` | `rhp-cli` (REPL, scripting, keys) |
| `Docs/` | [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md) and [`decisions/`](Docs/decisions/) |
| `cmake/` | build helpers and the single dependency pin file |

## License

Apache-2.0 — see [LICENSE](LICENSE).
