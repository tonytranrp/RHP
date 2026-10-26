# headless_server

A standalone host for `rhp-cli`, and a template for your own. It runs a tiny "game" (`game.gravity`, read-only `game.tick`, `game.entities` and `game.score`, `game.spawn` and `game.add_score` with undo), reads its keyring and trusted signers from files, writes an audit log, takes blobs into a folder, and runs until Ctrl+C. It can also dial out (reverse mode), advertise itself through DNS-SD, serve the HTTP gateway and serve signed releases.

## Build

From the repository root:

```bash
cmake --build --preset windows-msvc --target headless_server rhp-cli
```

The executables are `build/windows-msvc/Examples/headless_server/Debug/headless_server.exe` and `build/windows-msvc/Tools/rhp-cli/Debug/rhp-cli.exe` (Linux: under `build/linux-clang`, without `.exe`). It is not a ctest test itself; the CLI process tests start it.

## Run

```bash
rhp-cli keygen dev --role patch
```

Put the two printed lines (the text after each colon) into `keys.txt` and `signers.pub`, then:

```bash
headless_server --port 7777 --keys keys.txt --signers signers.pub --audit audit.log --blobs incoming
```

```bash
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid
```

| Option | What |
|---|---|
| `--host H --port N` | listen address (default `127.0.0.1`; port 0 = any free port). `--port` is required unless `--reverse` is given |
| `--keys FILE` | keyring: `name role base64-psk` per line (required) |
| `--signers FILE` | trusted signers: `name base64-public-key` per line; without it only observe sessions can run code |
| `--audit FILE` | every host event as a JSON line |
| `--blobs DIR` | blob sink `files` (admin): pushed files land in `DIR` (file name only) |
| `--reverse H:N` | reverse mode: dial a listening `rhp-cli ... --listen` instead of listening |
| `--port-file FILE`, `--stop-file FILE`, `--seconds N` | for scripts and tests: write the bound port, stop when a file appears, stop after N seconds |
| `--insecure-lan` | plaintext to and from non-loopback addresses (no TLS) |
| `--tls` | TLS on every connection, loopback included (non-loopback peers always get it) |
| `--cert FILE --key FILE` | the host's certificate chain and key (PEM); default: an ephemeral self-signed certificate |
| `--ca FILE` | reverse mode: check the listening `rhp-cli`'s certificate against this CA |
| `--advertise` | publish this listening host through DNS-SD |
| `--name NAME --app APP --build BUILD` | discovery instance and filter metadata |
| `--advertise-libs` | also publish installed library names; requires `--advertise` |
| `--http-port N` | serve the HTTP gateway on the listen address; port 0 selects a free port |
| `--releases DIR` | serve signed releases (`rhp-cli release apply`, `rollout`) and keep what runs in `DIR` across restarts (needs `--release-signers`) |
| `--release-signers FILE` | who may sign releases: `name base64-public-key [pattern,...]` per line |

Some sessions to try, with a second identity made by `rhp-cli keygen admin` (role admin) added to both files:

```bash
rhp-cli run low_grav.lua -c 127.0.0.1:7777 -i admin.rhpid --pin --name low_grav   # stays after rhp-cli exits
rhp-cli blob files settings.json -c 127.0.0.1:7777 -i admin.rhpid                 # lands in the --blobs folder
```

Reverse mode, with the CLI listening on the developer's PC and the host dialing it:

```bash
rhp-cli connect 0.0.0.0:7777 -i dev.rhpid --listen
headless_server --reverse 10.0.0.5:7777 --keys keys.txt --signers signers.pub
```

`Tests/tools/rhp_cli_tests.cpp` drives it as a separate process: keygen, key files, `run --pin`, a scripted REPL, blob, stubs, an unsigned identity refused and the audit log checked; reverse mode; TLS (`--tls` on both ends, plaintext refused); DNS-SD discovery followed by a signed fleet broadcast to two hosts; releases across a restart.

The executable uses TCP; other transports are selected through the library's configuration type. See the guides for [connecting](../../Docs/guide/connecting.md), [networking](../../Docs/guide/networking.md) (HTTP routes and headers, discovery, fleets) and [releases](../../Docs/guide/releases.md).
