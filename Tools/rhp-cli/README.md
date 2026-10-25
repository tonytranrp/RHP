# rhp-cli

The REPL and scripting client for RHP hosts. Every script it sends is signed with the identity's Ed25519 key.

```bash
rhp-cli keygen dev
```

Writes `dev.rhpid` (name, PSK, signing key; owner-only on POSIX — keep it private) and prints the two lines the host needs, after a label (`add to the host's keyring file:   dev admin <psk>`, `add to the host's signers file:   dev <public key>`): copy the part after the colon. `--role` defaults to `admin`; `-o/--out` names the file and `--force` replaces an existing one. `pubkey -i dev.rhpid --role patch` prints the bare lines again.

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
rhp> rollback low_grav 1
rhp> pin low_grav
rhp> stubs > rhp_api.lua
rhp> watch scripts
```

| Command | What |
|---|---|
| any Lua / `exec <lua>` | run in your scratch module; unfinished blocks continue on the next line |
| `load` / `reload <module> <file>` | load or reload a module from a file |
| `call <module> <fn> [args]` | args are Lua literals (`42`, `-1.5`, `"text"`, `true`, `nil`) |
| `rollback <module> [n]`, `revert`, `unload <module> [force]` | lifecycle |
| `pin` / `unpin <module>` | keep a module after you disconnect (admin) |
| `checkpoint <tag>`, `revert_to <tag>`, `revert_all` | ledger marks, the panic button (admin) |
| `list`, `status <module>`, `whoami` | introspection |
| `stubs [> file]` | LuaLS annotations for your role |
| `blob <sink> <file> [name]` | push a file to a host blob sink |
| `watch <folder>` / `unwatch` | reload `<folder>/*.lua` whenever one is saved |
| `subscribe <event>` / `unsubscribe <event>` | print each delivery of a host C++ event, or of an `rhp.publish` of your identity (`*`: every publish) |

Releases ([guide](../../Docs/guide/releases.md)) have subcommands of their own:

| Command | What |
|---|---|
| `release build --channel C --module [name=]file ... -i id.rhpid -o out.rhprel` | make (and sign) a release; `--seq` (default `auto`), `--label`, `--app`, `--build`, `--platform`, `--not-before`, `--not-after`, `--role`, `--lib`, `--fail-event`, `--max-handler-failures` |
| `release sign file -i id.rhpid` / `release inspect file` | add a signature / describe a `.rhprel` or `.rhprev` |
| `release apply file -c host -i id [--confirm now\|health\|manual]` | run it on a host (admin) |
| `release status`, `release confirm <channel>`, `release deactivate <channel> [--hold]` | inspect and steer a host's channels |
| `revoke build [--release id] [--key b64] [--floor channel=seq] -i id` / `revoke sign` / `revoke apply file` | revocation lists |
| `rollout file -i id [--host h:p ...] [--canary name] [--stage fraction:ms] [--max-failures n]` | spread a release over hosts (discovered when no `--host`) stage by stage |

Tab completes commands, lib names and functions (from the host's stubs) and loaded modules. Ctrl+C cancels the running script on the host; at a `...>` prompt it drops the unfinished Lua. History lives in `~/.rhp/history`. When stdin is not a terminal, `connect` reads one command per line (scripted sessions); unfinished Lua at the end of the input is an error. `call` arguments in double quotes stay strings (`"42"`), bare ones are parsed (`42`).

| Subcommand | What |
|---|---|
| `run <file> -c host:port -i id [--pin] [--name m]` | exec a file, or load it as a module (and pin it) |
| `exec "<lua>" -c … -i …` | run one chunk, print what it returns |
| `stubs -c … -i … [-o file]` | fetch LuaLS annotations |
| `blob <sink> <file> [--name n] -c … -i …` | push a file (`--name`: the name the sink sees, default the file name) |
| `watch <folder> -c … -i …` | reload on save until Ctrl+C |
| `events <name>... -c … -i …` | print host events (as `subscribe`) until Ctrl+C or the session ends |
| `sign <file> -i …` | print `signer base64-signature` for other tools |
| `discover [--app a] [--build b] [--platform p] [--wait ms]` | browse DNS-SD (`--wait` 1…60000 ms) and print `name address:port platform app build transport` per host |
| `fleet <file> -i … [discovery filters] [--timeout ms] [--tls] [--insecure-lan] [--ca pem] [--server-name n]` | discover TCP hosts and run one signed script on all (the identity needs a signing key); print a result or error per host |

Connection options: `-i/--identity` (or `RHP_IDENTITY`), `--listen` (reverse mode: listen at the address and wait for the host to dial in), `--timeout ms`. TLS: non-loopback addresses always use it; `--tls` asks for it on loopback too; `--ca pem` (+ `--server-name`) checks the host's certificate (by default the key handshake is bound to the TLS channel instead); with `--listen`, `--cert` / `--key` set this side's certificate. `--insecure-lan` is plaintext to a non-loopback address. A dropped connection is redialed and the session resumed on its own. Exit status: 0 when every command succeeded, 1 otherwise, 2 for usage errors.

Discovery requires the host's explicit `--advertise` opt-in. `--wait` is the browse duration (default 1500 ms); fleet uses `--timeout` as its broadcast deadline. Discovery grants no authority and cannot enable plaintext. Fleet effects follow ordinary session lifetime when the command exits. See [networking and fleet](../../Docs/guide/networking.md).

## Layout

| File | What |
|---|---|
| `src/text.hpp/.cpp` | endpoints, the Lua-completeness heuristic, value formatting, words and literals, names from stubs |
| `src/shell.hpp` | `rhp_cli::shell<Cfg>`: the command language over one client (tests run it in-process over loopback) |
| `src/main.cpp` | CLI11 subcommands, the replxx REPL, Ctrl+C |

Built when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON`; replxx and CLI11 are fetched only then.
