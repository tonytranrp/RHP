# RHP: Remote Hot Patch

A portable C++23 static library. A running program accepts authenticated, signed Lua scripts over pluggable transports, runs them in a sandbox against a C++-declared API, streams results back, and can **undo the recorded effects** of everything they did.

Lua is the glue. Non-admin scripts reach only the sandbox libraries and the C++ you expose through `Rhp::lib<...>` and `Rhp::patch_point<...>`. Application functions supply their own inverses; irreversible calls are reported, and an admin identity's standard-library side effects are not undone. The snippets below show the API's shape; [getting started](Docs/guide/getting-started.md) has complete, checked programs.

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
rhp-cli keygen dev --role patch                      # dev.rhpid; `rhp-cli pubkey -i dev.rhpid` prints the host's lines
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid          # REPL; every script is signed
```

```cpp
auto id = *Rhp::security::identity_file::load("dev.rhpid");
Rhp::client<> dev{Rhp::endpoint::dial("127.0.0.1", 7777), id.credential(), *id.signer_key()};
auto g   = dev.exec<double>("return game.gravity");          // Rhp::result<double>
auto mod = dev.load("low_grav", "game.gravity = -1.6");      // signed automatically
auto t   = co_await dev.async().exec<int>("return game.tick");
dev.unload(*mod);                                              // or close the last session: its effects are reverted
```

The same engine runs locally, without a network:

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

Scripts keep working between requests and talk through events:

```lua
rhp.every_frame(function() game.draw_text(10, 10, "fps " .. game.fps()) end)            -- every pump()
local worker = rhp.spawn(function() while true do refresh() rhp.sleep(1000) end end)    -- background task
rhp.on("game.round_over", function(winner) print(winner .. " wins") end)                -- a C++ event or a script event
rhp.publish("ui.toast", "saved")                                                         -- to this identity's handlers
```

And the Lua written against your API is tested offline, against the real bindings, with a fake clock:

```lua
describe("checkout", function()
    it("charges the customer", function()
        local c = shop.visit(200)
        assert.is_true(rules.checkout(c, { "sword" }))
        expect(c.gold).to.equal(80)          -- undone after the test
    end)
end)
```

## Features

- **Scripting:** a Lua 5.5 sandbox per identity; named modules with revisions, transactional `reload` (`on_save` / `on_restore`), `rollback`, `checkpoint` / `revert_to`, `revert`, `unload`, `pin`; `require` between modules; instruction, memory, wall-time and time-slice limits.
- **Binding C++:** `Rhp::lib<>` functions, variables, read-only values, sub-libs and opaque handles with methods and properties; `Rhp::undo<>` inverses, `Rhp::irreversible`, `Rhp::requires_role<>`; asynchronous bindings (`Rhp::async<T>`); patch points; C++ events (`Rhp::lua_event<>`); custom types through `Rhp::convert<T>`; LuaLS stubs.
- **Scheduling and events:** `rhp.wait` / `rhp.sleep` / `rhp.next_frame`, timers and frame callbacks with pause / resume / reschedule, background tasks (`rhp.spawn`), script events (`rhp.publish`, `rhp.on`, `rhp.wait_event`), a handler error policy, C++ and remote listeners (`host.on_script_event`, `client.on`).
- **Transports:** in-process loopback, TCP, WebSocket, reliable UDP, local IPC, or your own; reverse mode (the host dials out, for phones and NAT); opt-in DNS-SD discovery; an authenticated HTTP gateway; fleet broadcasts.
- **Security:** pre-shared-key mutual authentication, roles (`observe`, `patch`, `admin`), Ed25519-signed scripts, TLS 1.3 (OpenSSL or Mbed TLS) bound to the key handshake, per-frame MACs, audit events.
- **Hardening (Stage 13a):** build levels `RHP_HARDENING=dev|lan|production` that compile out what a build doesn't allow and cap limits per role; per-identity request rates, pump budgets and handler caps; admission control for unauthenticated connections; a sandbox without finalizers or address leaks that restores its shared libraries; owner-only key files; dev sessions that need no key files.
- **Sessions:** acks, resends and heartbeats; a dropped link resumes within `limits.resume_ms` with every call run exactly once.
- **Releases:** signed bundles a host keeps across restarts, with channels, anti-rollback floors, health-watched candidates, revocation and staged fleet rollout.
- **Tools:** tunables with `Rhp::range` checks, a sampling profiler, a debugger that pauses one script while the program runs, and a DAP server for editors.
- **Testing scripts:** `Rhp::test` runs Lua specs (busted and Jest style) offline with spies, fakes, a fake clock, exact costs, snapshots, property tests, fuzzing, coverage and CI reports.
- **Off switch:** `RHP_ENABLE=OFF` compiles hosts to inert stubs and patch points to direct calls, with no Lua linked.

## Quick start

Build RHP and run its tests (Windows: from an x64 Developer PowerShell):

```bash
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

Configure presets: `windows-msvc`, `windows-clang-cl`, `windows-msvc-asan`, `linux-clang`, `linux-clang-asan`, `linux-clang-tsan`, `linux-clang-fuzz` (libFuzzer, no test preset), `macos`, `ios-sim`, `ios-device` (Xcode), `android-x64`, `android-arm64`. Test presets exist for the desktop presets, `macos` and `ios-sim`; Android runs its tests through `Tools/android/run_tests.py`. The presets build Debug; pass `--config Release` for anything you time ([performance](Docs/guide/performance.md)).

Then follow the [first run](Docs/guide/getting-started.md#first-run-host-plus-rhp-cli): make a key with `rhp-cli keygen`, start `headless_server`, connect with `rhp-cli`, and embed a host and a client in your own program.

## Use it in your project

```cmake
CPMAddPackage(NAME rhp GITHUB_REPOSITORY tonytranrp/RHP GIT_TAG stage-13)   # or a commit sha
target_link_libraries(my_app PRIVATE Rhp::rhp)
```

`add_subdirectory` works the same way. Or install RHP once and use `find_package(rhp CONFIG REQUIRED)` with no version ([installed package](Docs/guide/getting-started.md#installed-package)). Releases are tagged by stage (`stage-0` ... `stage-13`); there are no version numbers. Hosts, clients and `rhp-cli` must speak the same protocol revision (Stages 7 to 9: revision 4; Stage 10: 5; Stages 11 and 12: 6; Stage 13: 7).

## Documentation

Start with the [user guide](Docs/guide/README.md):

| Read | To |
|---|---|
| [Getting started](Docs/guide/getting-started.md) | add RHP to a project, build it, run a host and `rhp-cli` |
| [Exposing C++ to Lua](Docs/guide/exposing-cpp.md) | declare the API scripts may use: functions, variables, handles, async bindings, patch points, events |
| [Writing scripts](Docs/guide/writing-scripts.md) | the `rhp` Lua API: modules, reload, undo, timers, tasks, events |
| [Scheduling and events](Docs/guide/scheduling-and-events.md) | per-frame work, background tasks, events between modules, C++ and tools |
| [Host and client](Docs/guide/host-and-client.md) | the C++ API, async calls, blobs, audit, `client.on` |
| [Connecting](Docs/guide/connecting.md) / [Networking](Docs/guide/networking.md) | endpoints, TLS, reverse mode, sessions, `rhp-cli`, transports, discovery, HTTP, fleets |
| [Releases](Docs/guide/releases.md) | signed releases kept across restarts, revocation, staged rollout |
| [Tools](Docs/guide/tools.md) | tunables, the profiler, the debugger, DAP |
| [Testing scripts](Docs/guide/testing-scripts.md) | Lua specs offline: spies, fakes, a fake clock, costs, coverage, CI, VS Code |
| [Configuration](Docs/guide/configuration.md) / [Security](Docs/guide/security.md) | config slots, limits, options, CMake switches, keys, roles, signing, hardening levels, dev sessions |
| [Performance](Docs/guide/performance.md) | what RHP costs and the settings that change it |
| [Reference](Docs/guide/reference.md) | error codes, events, wire protocol, sandbox contents |
| [Limitations](Docs/guide/limitations.md) | what RHP doesn't do (yet) |
| [Python client](clients/python/README.md) | `rhp_client`, a pure-Python client |

Examples: [`hello_console`](Examples/hello_console), [`frame_loop`](Examples/frame_loop), [`remote_exec`](Examples/remote_exec), [`custom_transport`](Examples/custom_transport), [`headless_server`](Examples/headless_server), [`lua_tests`](Examples/lua_tests) ([overview](Examples/README.md)). Command line: [`Tools/rhp-cli`](Tools/rhp-cli). Design and history: [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md), [`decisions/`](Docs/decisions/), [benchmarks](Docs/benchmarks.md), [status and TODO](Docs/TODO.md).

## Targets

Windows 10 1809+, Linux (glibc 2.31+), macOS 13.3+, iOS 16.3+, Android API 26+; x86_64 and arm64.
Compilers: MSVC (VS 2026), clang-cl, Clang 17+, AppleClang, Android NDK Clang. GCC is not a target.

## Limitations

The short list; the full one is [Docs/guide/limitations.md](Docs/guide/limitations.md).

- RHP runs remote code by design: keys, roles, signatures and TLS decide *who*, not *what*. Admin identities are fully trusted (with Lua's whole standard library in `dev` builds).
- No execution budgets by default in `dev` builds. Set `limits.instructions` / `wall_ms` / `memory` / `slice_us` on any host that accepts keys you don't fully trust; observe identities can have their own, and `lan` / `production` hardening caps them. A long C++ call can't be interrupted.
- Undo covers recorded effects (variables, patches, timers, subscriptions, tasks, functions with an inverse), not irreversible calls or admin standard-library side effects.
- Runaway timers, frame callbacks, handlers and tasks run by `pump()` can only be stopped by limits, not from the network.
- Script events stay inside one identity. Remote event delivery is rate-limited per session, and the HTTP gateway has no event stream.
- Sessions survive dropped connections (`resume_ms`), not host restarts; releases do survive restarts. Protocol revisions must match.
- macOS and iOS run in hosted CI only, not on real hardware. Recorded validation is mostly Debug builds.

## Stages

| Stage | Contents |
|---|---|
| 0 | layout, CMake, presets, `utils`, `core` |
| 1 | Lua 5.5 sandbox, `Rhp::lib` DSL, patch points, ledger, revert (local) |
| 2 | scheduler, `rhp.emit`, `lua_event`, reload and revisions, `require`, LuaLS stubs |
| 3 | wire format, loopback and TCP, sessions, PSK roles, blocking client |
| 4 | async client, `rhp-cli`, signing, audit, blobs, reverse mode, pin |
| 5 | TLS 1.3, reconnect and resume, fuzzing, Android and iOS presets |
| 6 | WebSocket, reliable UDP, local IPC, HTTP gateway, DNS-SD, fleet broadcasts |
| 7 | frame callbacks and timer control, background tasks, script events, C++ and remote event listeners, handler error policy |
| 8 | installable package (`find_package(rhp)`), hardening, benchmarks, `cancel_checks` |
| 9 | asynchronous bindings (`Rhp::async<T>`), methods and properties on handles |
| 10 | signed releases, persistence, revocation, staged rollout |
| 11 | tunables, sampling profiler, debugger, `rhp-cli dap` |
| 12 | `Rhp::test`: a test engine for Lua scripts |
| 13 | security for every deployment: 13a hardening levels, sandbox and network fixes, rate limits, dev sessions; 13b key handles and stores, operator certificates, a root of trust, capability scopes (`stage-13`); the device-key authenticator, pairing and 13c production delivery are open |

Stages 0–12 are implemented and tagged; `stage-13` tags the first part of Stage 13 (13a and the first wave of 13b). Open validation and platform items are in [Status and TODO](Docs/TODO.md).

## Layout

| Folder | What lives there |
|---|---|
| `Src/rhp/` | the library, one folder per module (`utils`, `core`, `platform`, `wire`, `net`, `security`, `exec`, `script`, `event`, `audit`, `session`, `release`, `test`, `config`, `host`, `client`), included as `<rhp/...>` |
| `Tests/` | unit, integration, tools, package, compile-fail, fuzz and benchmark tests |
| `Examples/` | `hello_console`, `frame_loop`, `remote_exec`, `custom_transport`, `headless_server`, `lua_tests` |
| `Tools/` | `rhp-cli` (REPL and subcommands), Android, iOS and benchmark helper scripts |
| `clients/` | the Python client (`clients/python`) and the VS Code test extension (`clients/vscode`) |
| `Docs/` | the [user guide](Docs/guide/README.md), [`ARCHITECTURE.md`](Docs/ARCHITECTURE.md), [`decisions/`](Docs/decisions/), [benchmarks](Docs/benchmarks.md) and the [TODO](Docs/TODO.md) |
| `cmake/` | build helpers and the single dependency pin file |

## License

Apache-2.0; see [LICENSE](LICENSE). Third-party licenses: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
