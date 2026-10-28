# rhp-cli

The REPL and scripting client for RHP hosts. Every script it sends is signed with the identity's Ed25519 key. Built when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON`; replxx and CLI11 are fetched only then. Guides: [connecting](../../Docs/guide/connecting.md), [tools](../../Docs/guide/tools.md), [releases](../../Docs/guide/releases.md), [testing scripts](../../Docs/guide/testing-scripts.md).

## Keys

```bash
rhp-cli keygen dev
```

Writes two files (decision AL11), each atomically and owner-only on every OS (mode 0600 on POSIX, a DACL for your account alone on Windows): `dev.rhpid`, the connection identity (`name`, `psk`, `env`), and `dev.rhpsign` beside it, the Ed25519 key that signs scripts and releases (`signer`, `signing_key`, `env`). Keep both private. It prints the two lines the host needs after a label; the PSK stays in the file:

```text
wrote dev.rhpid (connection identity) and dev.rhpsign (signing key): keep them private
add to the host's keyring file:   dev patch <psk from dev.rhpid> env=dev   (rhp-cli pubkey -i dev.rhpid --role patch prints it whole)
add to the host's signers file:   dev <public key> env=dev
```

`rhp-cli pubkey -i dev.rhpid` prints both lines whole (for scripts that write the host's files); `--show-secret` makes keygen print the keyring line whole too. `--role observe|patch|admin` (default `patch`; `admin` prints a warning) sets the keyring line's role; `--env dev|prod` (default `dev`) tags both keys and their host lines (`env=prod`; production hosts will refuse dev keys); `-o/--out` names the identity file (the signing key goes beside it with the extension `.rhpsign`); `--force` replaces existing files.

- `--passphrase` seals the signing key (Argon2i, then XChaCha20-Poly1305): typed twice on the terminal, or taken from `RHP_PASSPHRASE`. Every command that signs asks for it again (or reads `RHP_PASSPHRASE`); without it the identity still connects but signs nothing.
- `--device` writes an Ed25519 device key (`alg`, `device_key`) instead of a PSK, for hosts that authenticate device keys, and prints its allow-list line (`name role ed25519 <public key> env=..`) instead of a keyring line.

`-i` takes the `.rhpid`; the `.rhpsign` beside it is found by its name. Identity files that hold their signing key themselves (what keygen wrote before Stage 13b, and dev session files) still work. Loading a key file that other users can read, or whose PSK looks chosen by a person rather than random, prints a `warning:` line (never an error).

| Subcommand | Example |
|---|---|
| `keygen <name> [-o file] [--role r] [--env dev\|prod] [--passphrase] [--device] [--force] [--show-secret]` | `rhp-cli keygen ci --role observe --env prod -o ci.rhpid` |
| `pubkey -i id [--role r]` | `rhp-cli pubkey -i dev.rhpid --role admin` (the bare keyring line, with the PSK, or a device key's allow-list line, and the signers line; role default `patch`) |
| `sign <file> -i id` | `rhp-cli sign patch.lua -i dev.rhpid` (prints `signer base64-signature` for other tools) |

### Operator certificates

Hosts with `signer<Rhp::security::certified>` trust an offline operator CA instead of each operator (decision AL11). The CA signs short-lived certificates for operators' keys; scripts are signed with the operator's key plus claims (expiry, app, environment, host id, identity, a nonce) so a signed script can't be replayed elsewhere or later.

| Subcommand | Example |
|---|---|
| `ca init <name> [-o file] [--env dev\|prod] [--force]` | `rhp-cli ca init ops --env prod` (writes `ops.rhpca` owner-only, prints the host's trusted-CA line `name base64-key [env=...]`) |
| `cert issue --ca file --principal p --key k [--hours N] [--max-role r] [--app a]... [--env e]... [--scope s]... [--serial n] [-o file]` | `rhp-cli cert issue --ca ops.rhpca --principal alice --key alice.rhpid --hours 8 --max-role patch --app game` (`--key`: an identity file or a `[name] base64-public-key` line; only the public half is used; a dev CA's certificates are tagged `env=dev`) |
| `cert show <file> [--trusted cas]` | `rhp-cli cert show alice.rhpcert --trusted rhp_operator_cas.txt` (prints the fields; with `--trusted`, checks it now) |

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
| `--cert-file rhpcert` | sign scripts with this operator certificate and the identity's signing key (the key the certificate names); `--claim-app`, `--claim-env`, `--claim-audience` add claims (default: any) |

A dropped connection is redialed and the session resumed on its own. When rhp-cli exits its session ends, and the host reverts what it did except pinned modules. Exit status: 0 when every command succeeded, 1 otherwise, 2 for usage errors.

## The REPL

```bash
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid
rhp-cli connect --dev            # a dev session of a program on this machine
rhp-cli connect --dev my_game    # when several programs have one
```

`--dev [app]` needs no address and no identity file: a dev build of a program that listens only on loopback or local IPC can open a dev session (`host_options::dev_session`), which writes a connect file with a fresh identity and signing key to `<user config>/rhp/dev/<app>.rhpdev` (`%APPDATA%`, `~/Library/Application Support`, `$XDG_CONFIG_HOME` or `~/.config`) and removes it when it stops. Without an app rhp-cli uses the only file there and lists them when there are several; it refuses a file whose endpoint isn't a loopback TCP address or local IPC. The usual handshake and script signatures still run. `--timeout` applies; the other connection options don't.

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
| `connect <host:port>` / `connect --dev [app]` | `rhp-cli connect 127.0.0.1:7777 -i dev.rhpid` (the REPL; `--dev`: a local program's dev session) |
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

## Root of trust and identity revocations

Keys are `id=base64` (an Ed25519 public key), `id=alg:base64`, or an identity file (its signer name is the key id, its public key the key); a release key may end in `@game.*,ui.menu` (the channels it signs). A role given replaces that role's keys; a threshold of 0 keeps the earlier one (1 for a new role). Keys no role names any more are retired (what they signed stays valid).

| Subcommand | Example |
|---|---|
| `root init --root-key K ... [--root-threshold n] [--release-key K[@patterns] ...] [--revocation-key K ...] [--operator-ca-key K ...] [--<role>-threshold n] [--expires unix \| --expires-in days] [--sign id ...] [-o out]` | `rhp-cli root init --root-key a.rhpid --root-key b.rhpid --root-threshold 2 --release-key rel.rhpid@game.* --revocation-key rev.rhpid --expires-in 365 --sign a.rhpid --sign b.rhpid` (writes `root.1.rhproot`) |
| `root next <file> [role options] [--compromise id ...] [--retire id ...] [--sign id ...] [-o out]` | `rhp-cli root next root.1.rhproot --compromise rev --revocation-key rev2.rhpid --expires-in 365 --sign a.rhpid --sign b.rhpid` (version N+1; signed by the root keys of both versions) |
| `root sign <file> -i id ...` | `rhp-cli root sign root.2.rhproot -i c.rhpid` (offline signers add theirs in turn) |
| `root show <file> [--previous file]` | `rhp-cli root show root.2.rhproot --previous root.1.rhproot` (keys, roles, signers, whether the thresholds hold) |
| `revoke-identity [--seq n] [--serial s ...] [--signer K ...] [--device K ...] --sign id ... [-o out]` | `rhp-cli revoke-identity --signer ops.rhpid --serial 1001 --sign rev.rhpid` (writes `identities.<seq>.rhpidrev`; K: base64, `alg:base64` or an identity file) |
| `trust push <host:port> <file> ... -i id` | `rhp-cli trust push host:7777 root.2.rhproot identities.1761400000.rhpidrev -i ops.rhpid` (observe is enough; prints the root version and identity revocation seq the host holds) |

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
| `src/release_files.hpp/.cpp` | building, signing and describing `.rhprel` / `.rhprev` / `.rhproot` / `.rhpidrev` files; rollout stage parsing |
| `src/json.hpp` | rhp-cli's names for `Rhp::json` |
| `src/commands.hpp` | `rhp_cli::command` and every family's `add_<name>`: each subcommand adds itself with an options struct of its own and the function that runs it |
| `src/connection.hpp/.cpp` | the terminal, the connection options network subcommands share, `open_connection`, `open_dev_connection` (TCP or local IPC), `load_identity` (prints its warnings), `load_signer` |
| `src/dev.hpp/.cpp` | `connect --dev`: which dev session file (`pick_dev_session`) and where it may point (`dev_endpoint`) |
| `src/keys.cpp` | `keygen`, `pubkey`, `sign` |
| `src/certs.cpp` | `ca init`, `cert issue`, `cert show` |
| `src/cli_signer.hpp` | `rhp_cli::cli_signer`: rhp-cli's signer policy, an identity's Ed25519 key or a certified key behind one type |
| `src/fleet.cpp` | `discover`, `fleet`, `rollout` |
| `src/releases.cpp` | `release ...`, `revoke ...` |
| `src/trust.cpp` | `root ...`, `revoke-identity`, `trust push` |
| `src/test_command.cpp` | `test` |
| `src/main.cpp` | the replxx REPL (`connect`), the subcommands that run through the shell (`run`, `exec`, `stubs`, `blob`, `events`, `watch`, `tune`, `profile`, `dap`), Ctrl+C, and running the subcommand parsed |

`rhp_cli_core` (the text helpers, the release files, the dev session choice and the header-only shell and DAP server) is a static library so `Tests/tools/rhp_cli_tests.cpp` can drive the shell in-process.
