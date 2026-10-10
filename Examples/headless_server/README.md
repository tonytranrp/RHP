# headless_server

A standalone host for `rhp-cli`: a tiny "game" (`game.gravity`, `game.tick`, `game.spawn` with undo, `game.add_score`) that reads its keyring and trusted signers from files, writes an audit log, takes blobs into a folder, and runs until told to stop.

```bash
rhp-cli keygen dev
```

Put the two printed lines into `keys.txt` and `signers.pub`, then:

```bash
headless_server --port 7777 --keys keys.txt --signers signers.pub --audit audit.log --blobs incoming
```

```bash
rhp-cli connect 127.0.0.1:7777 -i dev.rhpid
```

| Option | What |
|---|---|
| `--host H --port N` | listen address (default `127.0.0.1`; port 0 = any free port) |
| `--keys FILE` | keyring: `name role base64-psk` per line (required) |
| `--signers FILE` | trusted signers: `name base64-public-key` per line |
| `--audit FILE` | every host event as a JSON line |
| `--blobs DIR` | blob sink `files` (admin): pushed files land in `DIR` (file name only) |
| `--reverse H:N` | reverse mode: dial a listening `rhp-cli … --listen` instead of listening |
| `--port-file FILE`, `--stop-file FILE`, `--seconds N` | for scripts and tests |
| `--insecure-lan` | plaintext to and from non-loopback addresses (no TLS) |
| `--tls` | TLS on every connection, loopback included (non-loopback peers always get it) |
| `--cert FILE --key FILE` | the host's certificate chain and key (PEM); default: an ephemeral self-signed certificate |
| `--ca FILE` | reverse mode: check the listening `rhp-cli`'s certificate against this CA |
| `--advertise` | explicitly publish this listening host through DNS-SD |
| `--name NAME --app APP --build BUILD` | discovery instance and filter metadata |
| `--advertise-libs` | additionally publish installed library names; requires `--advertise` |
| `--http-port N` | enable the HTTP gateway on the listen address; port 0 selects a free port |

`Tests/tools/rhp_cli_tests.cpp` drives it as a separate process: keygen → key files → `run --pin` → a scripted REPL → blob → stubs → an unsigned identity refused → the audit log checked, reverse mode, TLS (`--tls` on both ends, plaintext refused), and DNS-SD discovery followed by a signed fleet broadcast to two hosts.

See the [networking guide](../../Docs/guide/networking.md) for HTTP headers/routes and discovery/fleet usage. The supplied executable uses TCP; other transports are selected through the library's configuration type.
