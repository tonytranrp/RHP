# rhp-cli

The REPL and scripting client for RHP hosts. Every script it sends is signed with the identity's Ed25519 key. Built when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON`; replxx and CLI11 are fetched only then. Guides: [connecting](../../Docs/guide/connecting.md), [tools](../../Docs/guide/tools.md), [releases](../../Docs/guide/releases.md), [testing scripts](../../Docs/guide/testing-scripts.md).

## Keys

```bash
rhp-cli keygen dev
```

Writes `dev.rhpid` (name, PSK, signing key) atomically and owner-only on every OS (mode 0600 on POSIX, a DACL for your account alone on Windows): keep it private. It prints the two lines the host needs after a label; the PSK stays in the file:

```text
wrote dev.rhpid (keep it private)
add to the host's keyring file:   dev patch <psk from dev.rhpid>   (rhp-cli pubkey -i dev.rhpid --role patch prints it whole)
add to the host's signers file:   dev <public key>
```

`rhp-cli pubkey -i dev.rhpid` prints both lines whole (for scripts that write the host's files); `--show-secret` makes keygen print the keyring line whole too. `--role observe|patch|admin` (default `patch`; `admin` prints a warning) sets the keyring line's role; `-o/--out` names the file; `--force` replaces an existing one. Loading an identity file that other users can read prints a `warning:` line (never an error).

| Subcommand | Example |
|---|---|
| `keygen <name> [-o file] [--role r] [--force] [--show-secret]` | `rhp-cli keygen ci --role observe -o ci.rhpid` |
| `pubkey -i id [--role r]` | `rhp-cli pubkey -i dev.rhpid --role admin` (the bare keyring line, with the PSK, and the signers line; role default `patch`) |
| `sign <file> -i id` | `rhp-cli sign patch.lua -i dev.rhpid` (prints `signer base64-signature` for other tools) |

## Connection options

Every network subcommand takes `-c/--connect host:port` (`connect` takes the address as its first argument) and `-i/--identity file` (or `RHP_IDENTITY`), plus:

| Option | What |
|---|---|
| `--timeout ms` | wait for the session (default 10000; 600000 with `--listen`) |
| `--listen` | reverse mode: listen at the address and wait for the host to dial in |
| `--tls` | TLS on loopback too (non-loopback addresses always use it) |
| `--ca pem` / `--server-name n` | check the host's certificate (by default it isn't: the key handshake is bound to the TLS channel instead) |
| `--cert pem` / `--key pem` | with `--listen`: this side's certificate (default: ephemeral self-signed) |
| `--insecure-lan` | plaintext to a non-loopback address (trusted networks only) |

A dropped connection is redialed and the session resumed on its own. When rhp-cli exits its session ends, and the host reverts what it did except pinned modules. Exit status: 0 when every command succeeded, 1 otherwise, 2 for usage errors.

## The REPL

```bash
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid
```

```text
rhp> return game.gravity
-9.81
rhp> for i = 1, 3 do
...>   print(i)
...> end
rhp> load low_grav scripts/low_grav.lua
rhp> call low_grav set -1.6
rhp> rollback low_grav 1
rhp> pin low_grav
rhp> stubs > rhp_api.lua
rhp> watch scripts
```

| Command | What |
|---|---|
| any Lua / `exec <lua>` | run in your scratch module; unfinished blocks continue on the next line (`...>`) |
| `load` / `reload <module> <file>` | load or reload a module from a file |
| `call <module> <fn> [args]` | args are Lua literals (`42`, `-1.5`, `"text"`, `true`, `nil`); quoted ones stay strings (`"42"`) |
| `rollback <module> [n]`, `revert <module>`, `unload <module> [force]` | lifecycle (patch) |
| `checkpoint <tag>`, `revert_to <tag>` | ledger marks (patch) |
| `revert_all` | the panic button (admin) |
| `pin` / `unpin <module>` | keep a module after you disconnect (admin) |
| `list`, `status <module>`, `whoami` | introspection |
| `stubs [file]`, `stubs > file` | LuaLS annotations for your role |
| `blob <sink> <file> [name]` | push a file to a host blob sink |
| `watch <folder>` / `unwatch` | reload `<folder>/*.lua` whenever one is saved |
| `subscribe <event>` / `unsubscribe <event>` | print each delivery of a host C++ event, or of an `rhp.publish` of your identity (`*`: every publish) |
| `tunables [prefix]` / `tune <path> <value>` | list the host's variables with their tags / set one (journaled) |
| `profile start [interval]`, `profile show`, `profile stop [file.folded]` | sample your scripts; print the top functions; write folded stacks |
| `break <module> [line ...]`, `pause`, `paused` | set (no lines: clear) breakpoints, pause the next line, list paused scripts |
| `continue [req]`, `step [into\|over\|out] [req]` | resume or step a paused script |
| `stack [req]`, `locals [frame] [path]`, `upvalues [frame] [path]`, `globals [frame] [path]`, `print <name.path> [frame]` | inspect a paused script (no Lua runs) |
| `help` / `?`, `quit` / `exit` | |

A script that pauses at a breakpoint (an expression, `call`, `load` or `reload`) goes to the background: the prompt stays free for `stack`, `locals` and `continue`, and its result prints when it finishes.

Tab completes commands, lib names and functions (from the host's stubs) and loaded modules. Ctrl+C cancels the running script on the host; at a `...>` prompt it drops the unfinished Lua. History lives in `~/.rhp/history`. When stdin is not a terminal, `connect` reads one command per line (scripted sessions); unfinished Lua at the end of the input is an error.

## Subcommands

| Subcommand | Example |
|---|---|
| `connect <host:port>` | `rhp-cli connect 127.0.0.1:7777 -i dev.rhpid` (the REPL) |
| `run <file> [--pin] [--name m]` | `rhp-cli run patch.lua -c 127.0.0.1:7777 -i dev.rhpid --pin` (exec a file, or load it as a module and pin it) |
| `exec "<lua>"` | `rhp-cli exec "return game.tick" -c 127.0.0.1:7777 -i dev.rhpid` (prints what it returns) |
| `stubs [-o file]` | `rhp-cli stubs -c 127.0.0.1:7777 -i dev.rhpid -o rhp_api.lua` |
| `blob <sink> <file> [--name n]` | `rhp-cli blob configs game.ini -c 127.0.0.1:7777 -i dev.rhpid` (`--name`: what the sink sees, default the file name) |
| `watch <folder>` | `rhp-cli watch scripts -c 127.0.0.1:7777 -i dev.rhpid` (reload on save until Ctrl+C) |
| `events <name>...` | `rhp-cli events game.round_over "*" -c 127.0.0.1:7777 -i dev.rhpid` (until Ctrl+C or the session ends) |
| `tune [path [value]]` | `rhp-cli tune game.speed 2.5 -c 127.0.0.1:7777 -i dev.rhpid` (no value: list what starts with `path`) |
| `profile [--seconds s] [--interval i] [-o out.folded]` | `rhp-cli profile --seconds 10 -o game.folded -c 127.0.0.1:7777 -i dev.rhpid` (defaults 5 s, 1000 instructions) |
| `dap [--root folder]` | `rhp-cli dap -c 127.0.0.1:7777 -i dev.rhpid --root scripts` (Debug Adapter Protocol on stdin / stdout; `<root>/game/combat.lua` is module `game.combat`) |
| `discover [--app a] [--build b] [--platform p] [--wait ms]` | `rhp-cli discover --app my_game` (prints `name address:port platform app build transport` per host; `--wait` 1..60000, default 1500) |
| `fleet <file> -i id [discovery filters] [--timeout ms] [--tls] [--insecure-lan] [--ca pem] [--server-name n]` | `rhp-cli fleet stats.lua -i dev.rhpid --app my_game` (discover TCP hosts, run one signed script on all, one result or error per host) |
| `test [--exe program] [--api-from host:port --api-identity id] <runner args>` | `rhp-cli test -s scripts tests/` (see below) |

Discovery requires the host's explicit `advertise()`. Discovery grants no authority and cannot enable plaintext.

## Releases, revocations, rollouts

| Subcommand | Example |
|---|---|
| `release build --channel C --module [name=]file ... [-i id ...] [-o out]` | `rhp-cli release build --channel game.balance --module tuning.lua -i dev.rhpid -o balance.rhprel`; also `--seq` (default `auto`: Unix time), `--label`, `--app`, `--build`, `--platform`, `--not-before`, `--not-after`, `--role patch\|admin`, `--lib`, `--fail-event`, `--max-handler-failures` |
| `release sign <file> -i id` | `rhp-cli release sign balance.rhprel -i lead.rhpid` (add a signature in place) |
| `release inspect <file>` | `rhp-cli release inspect balance.rhprel` (a `.rhprel` or `.rhprev`) |
| `release apply <file> [--confirm now\|health\|manual]` | `rhp-cli release apply balance.rhprel -c host:7777 -i admin.rhpid --confirm health` (admin) |
| `release status` | `rhp-cli release status -c host:7777 -i dev.rhpid` |
| `release confirm <channel>` / `release deactivate <channel> [--hold]` | `rhp-cli release deactivate game.balance --hold -c host:7777 -i admin.rhpid` (admin) |
| `revoke build [--seq n] [--release id] [--key b64] [--floor channel=seq] -i id [-o out]` | `rhp-cli revoke build --floor game.balance=12 -i lead.rhpid` |
| `revoke sign <file> -i id` / `revoke apply <file>` | `rhp-cli revoke apply revocations.1761400000.rhprev -c host:7777 -i dev.rhpid` |
| `rollout <file> -i id [--host h:p ...] [--canary name] [--stage fraction:ms ...] [--max-failures n] [--keep-on-failure] [discovery filters] [--tls] [--ca pem] [--server-name name] [--insecure-lan]` | `rhp-cli rollout balance.rhprel -i admin.rhpid --stage 0.5:30000 --stage 1:0` (hosts discovered when no `--host`; default stages `0.1:30000 0.5:30000 1:0`) |

## Lua tests

`rhp-cli test` is the offline test runner (`Rhp::test`) with the `rhp` API only, or with fakes: `--api FILE.json`, or `--api-from host:port` (with `--api-identity`, `--api-tls`, `--api-ca`, `--api-server-name`, `--api-insecure-lan`) to fake the libs of a running host. `--exe program` runs a program's own test executable (its real libs) with the other arguments instead. `rhp-cli test --help` lists the runner's options.

```bash
rhp-cli test -s scripts tests/combat_spec.lua --reporter junit:report.xml
```

## Layout

| File | What |
|---|---|
| `src/text.hpp/.cpp` | endpoints, the Lua-completeness heuristic, value formatting, words and literals, names from stubs |
| `src/shell.hpp` | `rhp_cli::shell<Cfg>`: the command language over one client (tests run it in-process over loopback; rhp-cli instantiates it in `main.cpp`) |
| `src/dap.hpp` | `rhp_cli::dap_server<Cfg>`: the Debug Adapter Protocol server (`rhp-cli dap`) |
| `src/release_files.hpp/.cpp` | building, signing and describing `.rhprel` / `.rhprev` files; rollout stage parsing |
| `src/json.hpp` | rhp-cli's names for `Rhp::json` |
| `src/commands.hpp` | `rhp_cli::command` and every family's `add_<name>`: each subcommand adds itself with an options struct of its own and the function that runs it |
| `src/connection.hpp/.cpp` | the terminal, the connection options network subcommands share, `open_connection`, `load_identity` (prints its warnings), `load_signer` |
| `src/keys.cpp` | `keygen`, `pubkey`, `sign` |
| `src/fleet.cpp` | `discover`, `fleet`, `rollout` |
| `src/releases.cpp` | `release ...`, `revoke ...` |
| `src/test_command.cpp` | `test` |
| `src/main.cpp` | the replxx REPL (`connect`), the subcommands that run through the shell (`run`, `exec`, `stubs`, `blob`, `events`, `watch`, `tune`, `profile`, `dap`), Ctrl+C, and running the subcommand parsed |

`rhp_cli_core` (the text helpers, the release files and the header-only shell and DAP server) is a static library so `Tests/tools/rhp_cli_tests.cpp` can drive the shell in-process.
