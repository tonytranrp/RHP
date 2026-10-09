# rhp-cli

The REPL and scripting client for RHP hosts. Every script it sends is signed with the identity's Ed25519 key.

```bash
rhp-cli keygen dev
```

Writes `dev.rhpid` (name, PSK, signing key; owner-only on POSIX — keep it private) and prints the two lines the host needs: one for its keyring file (`dev admin <psk>`) and one for its trusted-signers file (`dev <public key>`). `pubkey -i dev.rhpid --role patch` prints them again.

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

Tab completes commands, lib names and functions (from the host's stubs) and loaded modules. Ctrl+C cancels the running script on the host; at a `...>` prompt it drops the unfinished Lua. History lives in `~/.rhp/history`. When stdin is not a terminal, `connect` reads one command per line (scripted sessions); unfinished Lua at the end of the input is an error. `call` arguments in double quotes stay strings (`"42"`), bare ones are parsed (`42`).

| Subcommand | What |
|---|---|
| `run <file> -c host:port -i id [--pin] [--name m]` | exec a file, or load it as a module (and pin it) |
| `exec "<lua>" -c … -i …` | run one chunk, print what it returns |
| `stubs -c … -i … [-o file]` | fetch LuaLS annotations |
| `blob <sink> <file> -c … -i …` | push a file |
| `watch <folder> -c … -i …` | reload on save until Ctrl+C |
| `sign <file> -i …` | print `signer base64-signature` for other tools |

Connection options: `-i/--identity` (or `RHP_IDENTITY`), `--insecure-lan` (a non-loopback address before TLS), `--listen` (reverse mode: listen at the address and wait for the host to dial in), `--timeout ms`. Exit status: 0 when every command succeeded, 1 otherwise, 2 for usage errors.

## Layout

| File | What |
|---|---|
| `src/text.hpp/.cpp` | endpoints, the Lua-completeness heuristic, value formatting, words and literals, names from stubs |
| `src/shell.hpp` | `rhp_cli::shell<Cfg>`: the command language over one client (tests run it in-process over loopback) |
| `src/main.cpp` | CLI11 subcommands, the replxx REPL, Ctrl+C |

Built when `RHP_BUILD_TOOLS=ON` and `RHP_ENABLE=ON`; replxx and CLI11 are fetched only then.
