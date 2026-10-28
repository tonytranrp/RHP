# Getting started

## Requirements

- CMake 3.28+, Ninja for every preset except `ios-device` (Xcode), and a C++23 compiler with the required standard-library support (`std::expected`, `std::format`, `std::print`). A compiler's language mode alone does not establish library support; see the [tested toolchains](../decisions/platforms-and-toolchains.md). GCC is not a target.
- Target floors: Windows 10 1809+, Linux glibc 2.31+, macOS 13.3+, iOS 16.3+, Android API 26+. macOS/iOS verification remains open in [Status and TODO](../TODO.md).
- CMake fetches Lua, Asio, Monocypher and Mbed TLS. Desktop TLS uses system OpenSSL 3.0+ when found. Mbed TLS requires a C compiler; Lua and Monocypher are compiled as C++.

## Add RHP to your project

With a checkout at `external/RHP`, this is a complete consumer `CMakeLists.txt` for the host program below, saved as `main.cpp`:

```cmake
cmake_minimum_required(VERSION 3.28)
project(rhp_demo LANGUAGES CXX)

add_subdirectory(external/RHP)
add_executable(rhp_demo main.cpp)
target_link_libraries(rhp_demo PRIVATE Rhp::rhp)
```

Build that consumer project from its own root. On Windows, use an x64 Developer PowerShell:

```bash
cmake -S . -B build -G "Ninja Multi-Config" -DCMAKE_CXX_COMPILER=cl -DCMAKE_C_COMPILER=cl
cmake --build build --config Debug
```

The executable is `build/Debug/rhp_demo.exe`. Run it from the directory holding the key files. The preset commands in the next section belong to RHP's checkout, not this new consumer project.

For a project that already uses CPM, replace `add_subdirectory` with a pinned package declaration:

```cmake
CPMAddPackage(NAME rhp GITHUB_REPOSITORY tonytranrp/RHP GIT_TAG stage-13)   # or a commit sha
```

Releases are tagged by stage (`stage-0` ... `stage-13`); there are no version numbers. This guide describes `stage-13`: Stage 12 plus Stage 13's hardening, keys, operator certificates, root of trust and scopes. A host and its clients must use the same protocol revision (Stages 11 and 12 speak revision 6, Stage 13 speaks 7). RHP's tests, tools, examples and install rules default to OFF when consumed as a subproject, and its warnings aren't errors there; build the CLI from RHP's own checkout as described next.

### Installed package

RHP also installs as a CMake package. From RHP's checkout (tests and tools aren't needed for this):

```bash
cmake --preset windows-msvc -B build/package -DRHP_BUILD_TESTS=OFF -DRHP_BUILD_EXAMPLES=OFF -DRHP_BUILD_TOOLS=OFF
```

```bash
cmake --build build/package --config Release
```

```bash
cmake --install build/package --config Release --prefix C:/sdk/rhp
```

Build and install `Debug` the same way into the same prefix to have both (Debug archives carry a `d` suffix). The consumer:

```cmake
cmake_minimum_required(VERSION 3.28)
project(rhp_demo LANGUAGES CXX)

find_package(rhp CONFIG REQUIRED)   # -DCMAKE_PREFIX_PATH=C:/sdk/rhp
add_executable(rhp_demo main.cpp)
target_link_libraries(rhp_demo PRIVATE Rhp::rhp)
```

`find_package(rhp)` takes no version: RHP has no release numbers, so a versioned request never matches. A package built for another OS, pointer size, Android ABI or C++ ABI is refused. The package sets `rhp_STAGE`, `rhp_PROTOCOL_REVISION`, `rhp_ENABLE`, `rhp_HARDENING` (`dev`, `lan` or `production`), `rhp_TLS_HAS_OPENSSL`, `rhp_TLS_HAS_MBEDTLS` and `rhp_PLATFORM`; it brings the archives of the third-party code RHP compiled in (`lib/rhp/`) but none of their headers, and their licenses in `share/doc/rhp/licenses`. With MSVC a configuration only maps to an installed one with the same runtime: a Debug consumer needs a Debug RHP installed. When RHP was built with OpenSSL, the consumer's machine needs OpenSSL 3.0+ too. The generated `<rhp/build_config.hpp>` records how the package was built, so a translation unit that defines `RHP_ENABLE` (or `RHP_HARDENING`, the TLS or platform macros) differently fails to compile instead of disagreeing with the library.

`Rhp::rhp` links everything and provides `<rhp/rhp.hpp>`. For local scripting, link `Rhp::script` and include `<rhp/script/sandbox.hpp>`. A client-only tool can link `Rhp::client` and include `<rhp/client/client.hpp>` without linking Lua. Targets propagate C++23, include paths, platform definitions and `RHP_ENABLE`; use those targets rather than copying include directories and libraries by hand. RHP's public headers are ASCII and survive `<windows.h>` included first without `NOMINMAX`.

## Build RHP itself

Run these commands from the RHP repository root, in an x64 Developer PowerShell on Windows:

```bash
cmake --preset windows-msvc
cmake --build --preset windows-msvc
ctest --preset windows-msvc
```

The build/test presets select **Debug**. Select Release explicitly when needed:

```bash
cmake --build --preset windows-msvc --config Release
ctest --preset windows-msvc -C Release
```

The built tools are not installed into PATH. In PowerShell, set their paths once:

```powershell
$rhpCli = (Resolve-Path build/windows-msvc/Tools/rhp-cli/Debug/rhp-cli.exe).Path
$rhpServer = (Resolve-Path build/windows-msvc/Examples/headless_server/Debug/headless_server.exe).Path
```

Use `& $rhpCli` and `& $rhpServer` in place of the bare executable names below. On Linux, the paths end in `Tools/rhp-cli/Debug/rhp-cli` and `Examples/headless_server/Debug/headless_server` under `build/linux-clang`, without `.exe`.

Ship and measure Release builds; [performance](performance.md) covers `RHP_LTO` and the settings that change what scripts cost. Other presets and configuration switches are in [configuration](configuration.md#cmake-options). A defined preset is not evidence that its platform has been verified; see [platform decisions](../decisions/platforms-and-toolchains.md).

## First run: host plus `rhp-cli`

**1. Make a developer identity.**

```bash
rhp-cli keygen dev --role patch
```

This writes `dev.rhpid` (identity name, PSK, signing key; owner-only on every OS) and prints what the host needs, leaving the PSK in the file:

```text
wrote dev.rhpid (keep it private)
add to the host's keyring file:   dev patch <psk from dev.rhpid>   (rhp-cli pubkey -i dev.rhpid --role patch prints it whole)
add to the host's signers file:   dev <base64-ed25519-public-key>
```

Print the two lines whole and put them into the host's files:

```bash
rhp-cli pubkey -i dev.rhpid --role patch
```

The first line it prints goes into `keys.txt` (name role key), the second into `signers.pub` (name public-key). `keygen --show-secret` prints the keyring line whole instead. `keygen` refuses to replace an existing identity unless you pass `--force`. The keyring line contains a secret: keep that output, `keys.txt` and `dev.rhpid` out of source control, and `keys.txt` readable by you alone (the host below warns otherwise).

**2. Start the supplied host in another terminal**, in the directory containing those key files:

```bash
headless_server --port 7777 --keys keys.txt --signers signers.pub --audit rhp_audit.log
```

It exposes `game.gravity`, `game.tick`, `game.spawn` and other demo bindings. Leave it running while the client connects. Ctrl+C stops it and cleans up its identities.

**3. Connect and change a module.** Save this as `low_grav.lua`:

```lua
game.gravity = -1.6
return { gravity = function() return game.gravity end }
```

Connect from the directory containing the identity and script:

```bash
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid
```

```text
rhp> return game.gravity
-9.81
rhp> load low_grav low_grav.lua
rhp> status low_grav
rhp> call low_grav gravity
-1.6
rhp> unload low_grav
rhp> return game.gravity
-9.81
rhp> quit
```

`unload` removes this module's recorded effects. `revert_all` and `pin` require admin. `keygen` and `pubkey` default to `--role patch` (`--role admin` makes keygen print a warning); the role printed is only a suggestion for the host keyring, and editing an identity file cannot change the role granted by the host.

**4. Embed a host in your application.** This complete `main.cpp` checks setup failures and runs Lua on the application's frame thread. Ctrl+C exits the loop and destroys the host on that same thread:

```cpp
#include <chrono>
#include <csignal>
#include <cstdio>
#include <print>
#include <string>
#include <thread>
#include <utility>

#include <rhp/rhp.hpp>

namespace game {
float g_gravity = -9.8f;
int g_tick = 0;
} // namespace game

volatile std::sig_atomic_t running = 1;
void stop(int) {
    running = 0;
}

using game_lib = Rhp::lib<"game">::var<"gravity", &game::g_gravity>::ro<"tick", &game::g_tick>;

using host_cfg = Rhp::config<>::limits<Rhp::limits{
    .instructions = 5'000'000, .memory = 64u << 20, .wall_ms = 250, .slice_us = 2'000}>;

int main() {
    auto keys = Rhp::security::keyring::from_file("keys.txt");
    auto signers = Rhp::security::trusted_signers::from_file("signers.pub");
    if (!keys || !signers) {
        std::println(stderr, "{}", !keys ? keys.error() : signers.error());
        return 1;
    }
    for (const std::string& warning : keys->warnings()) {
        std::println(stderr, "warning: {}", warning); // keys.txt can be read by other users
    }
    Rhp::host<host_cfg> host{Rhp::endpoint::listen("127.0.0.1", 7777), std::move(*keys), std::move(*signers)};
    if (auto port = host.port(); !port) {
        std::println(stderr, "{}", port.error());
        return 1;
    }
    if (auto installed = host.install<game_lib>(); !installed) {
        std::println(stderr, "{}", installed.error());
        return 1;
    }
    Rhp::audit::file_sink sink{"rhp_audit.log"};
    if (auto ready = sink.ok(); !ready) {
        std::println(stderr, "{}", ready.error());
        return 1;
    }
    auto audit = host.on_any(sink);
    std::signal(SIGINT, stop);
    while (running) {
        host.pump();
        ++game::g_tick;
        std::this_thread::sleep_for(std::chrono::milliseconds{16});
    }
}
```

Stop the supplied server before starting this host on the same port. Its initial gravity is `-9.8`, rather than the supplied server's `-9.81`. The sample host sets illustrative execution budgets and a 2 ms cooperative slice; choose limits for your workload. In an application, call `pump()` from the existing frame loop. See [limits](configuration.md#limits) for what these budgets cover.

**5. Connect from C++.** This complete client reads the initial value, loads a signed module, and explicitly unloads it:

```cpp
#include <cstdio>
#include <print>
#include <utility>

#include <rhp/rhp.hpp>

int main() {
    auto id = Rhp::security::identity_file::load("dev.rhpid");
    if (!id) {
        std::println(stderr, "{}", id.error());
        return 1;
    }
    auto signer = id->signer_key();
    if (!signer) {
        std::println(stderr, "dev.rhpid has no signing key");
        return 1;
    }
    Rhp::client<> dev{Rhp::endpoint::dial("127.0.0.1", 7777), id->credential(), std::move(*signer)};
    auto gravity = dev.exec<double>("return game.gravity");
    if (!gravity) {
        std::println(stderr, "{}", gravity.error());
        return 1;
    }
    std::println("initial gravity: {}", *gravity);
    auto mod = dev.load("low_grav", "game.gravity = -1.6");
    if (!mod) {
        std::println(stderr, "{}", mod.error());
        return 1;
    }
    auto report = dev.unload(*mod);
    if (!report) {
        std::println(stderr, "{}", report.error());
        return 1;
    }
    if (!report->clean()) {
        for (const auto& error : report->failures) {
            std::println(stderr, "{}", error);
        }
        return 1;
    }
    std::println("unloaded: {} effects undone, {} irreversible", report->undone, report->irreversible);
}
```

Run it while the host keeps pumping. A blocking client call made on the same thread that must pump its host cannot finish until that host runs. For a same-thread setup, use async calls and alternate the host's `pump()` with the client's `poll()`; see [thread rules](host-and-client.md#thread-rules).

Destroying a client closes its session gracefully. If it was the identity's last session, cleanup happens when the host processes that closure in `pump()`. Unexpected link loss instead preserves the session during the resume window; cleanup is not necessarily immediate.

## First run shortcut: a dev session

On your own machine, with a `dev` build (`RHP_HARDENING=dev`, the default), you can skip the key files. Start the supplied host with a dev session:

```bash
headless_server --port 0 --dev-session my_game
```

```bash
rhp-cli connect --dev my_game
```

The host generates an admin identity and a signing key for this run, trusts them, and writes a connect file for `rhp-cli` into your user configuration folder (`%APPDATA%\rhp\dev\my_game.rhpdev` on Windows), readable by you alone; it removes the file when it stops. The handshake and script signatures run as usual. The same in your own program:

```cpp
#include <chrono>
#include <csignal>
#include <cstdio>
#include <print>
#include <thread>

#include <rhp/rhp.hpp>

namespace game {
float g_gravity = -9.8f;
} // namespace game

volatile std::sig_atomic_t running = 1;
void stop(int) {
    running = 0;
}

using game_lib = Rhp::lib<"game">::var<"gravity", &game::g_gravity>;

int main() {
    Rhp::host_options options;
    options.dev_session = "my_game"; // rhp-cli connect --dev my_game
    // No key files: the dev session brings its own identity and signer.
    Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 0), Rhp::security::keyring{}, Rhp::security::trusted_signers{}, options};
    const auto port = host.port();
    if (!port) {
        std::println(stderr, "{}", port.error()); // forbidden: not a dev build, or not on loopback
        return 1;
    }
    if (auto installed = host.install<game_lib>(); !installed) {
        std::println(stderr, "{}", installed.error());
        return 1;
    }
    std::println("listening on 127.0.0.1:{}; connect with: rhp-cli connect --dev my_game", *port);
    std::signal(SIGINT, stop);
    while (running) {
        host.pump();
        std::this_thread::sleep_for(std::chrono::milliseconds{16});
    }
} // the host removes the connect file here
```

A dev session listens on a loopback address or local IPC only; anywhere else, in reverse mode, above hardening `dev` or in a `lan` or `production` build the host doesn't start and `port()` reports `forbidden`. Any process you run can read the connect file, so this is for development machines. Details: [dev sessions](security.md#dev-sessions).

## Learn from the examples

Build with `RHP_BUILD_EXAMPLES=ON` (default when RHP is the top-level project). When tests are built too (the default top-level build), the four finite programs are ctest tests `example.<name>`, and the `lua_tests` spec files are `example.lua_tests.<file>`; run them all with `ctest --preset windows-msvc -R example`. `headless_server` is a long-running host exercised by the CLI process tests.

| Example | Shows |
|---|---|
| [`hello_console`](../../Examples/hello_console) | local only: `Rhp::lib`, a patch point, `load`, `revert` |
| [`frame_loop`](../../Examples/frame_loop) | per-frame `pump()`, time slicing, `rhp.wait`, reload keeping state, events, stubs |
| [`remote_exec`](../../Examples/remote_exec) | host and clients over loopback and TCP: three roles, streamed output, cancel, disconnect = revert |
| [`custom_transport`](../../Examples/custom_transport) | writing your own transport |
| [`headless_server`](../../Examples/headless_server) | a standalone host driven by `rhp-cli`: key files, audit log, blob folder, reverse mode, TLS, DNS-SD, HTTP gateway, releases, dev sessions |
| [`lua_tests`](../../Examples/lua_tests) | testing a game's Lua scripts offline with `Rhp::test` and `rhp_add_lua_tests` |

## Without any network

The script engine works on its own. This complete program changes a variable and checks its revert:

```cpp
#include <cstdio>
#include <print>

#include <rhp/rhp.hpp>

double gravity = -9.81;
using game_lib = Rhp::lib<"game">::var<"gravity", &gravity>;

int main() {
    Rhp::script::sandbox box;
    if (auto installed = box.install<game_lib>(); !installed) {
        std::println(stderr, "{}", installed.error());
        return 1;
    }
    auto mod = box.load("low_grav", "game.gravity = -1.6");
    if (!mod) {
        std::println(stderr, "{}", mod.error());
        return 1;
    }
    auto report = box.revert(*mod);
    if (!report || !report->clean()) {
        return 1;
    }
    std::println("restored gravity: {}", gravity);
}
```

The sandbox defaults to patch role and needs no credentials, signatures or transport. Its destructor reverts owned effects. For scripts that suspend, consume `sandbox_options::on_result` and keep calling `box.pump()`; see [local return conventions](writing-scripts.md#time-loops-and-limits).

## Troubleshooting the first run

| Symptom | Check |
|---|---|
| CMake cannot find `cl` | start an x64 Developer PowerShell; use the matching preset |
| `not_found` while reading key files | run in their directory or pass full paths |
| `auth` | identity name and decoded PSK must match the host keyring |
| `bad_signature` | the identity needs a signing key; its signer name and public key must be in `signers.pub` |
| `forbidden` | check the granted role and TLS policy; a patch key cannot call `revert_all` or `pin` |
| `forbidden` from `host.port()` | the host refused to start at its [hardening level](security.md#hardening-levels): `insecure_lan` or `signer<unsigned_scripts>` above `dev`, or a dev session off loopback, in reverse mode or outside a `dev` build |
| `warning: ...` lines | a key file other users can read, or a PSK that looks typed by a person: fix the file's permissions or generate a new key |
| A request keeps waiting | the host must call `pump()`; a `zero_threads` client must also progress its I/O |

The [reference](reference.md#error-codes) lists the remaining codes. Preserve the error's `where` and `traceback` when reporting script failures.
