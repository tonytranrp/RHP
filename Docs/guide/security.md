# Security

RHP deliberately accepts remote code. Authentication, roles, signatures and TLS control who may use it; the build's [hardening level](#hardening-levels) decides what is in the binary at all. In a `dev` build execution budgets remain unlimited by default and must be chosen for the application, and an admin identity is trusted with the process's full Lua standard-library capabilities.

## The layers

| Layer | What it does |
|---|---|
| Hardening | `RHP_HARDENING=dev\|lan\|production` is the most a build allows; a config or a host may only raise it ([hardening levels](#hardening-levels)) |
| Bind rules | the application chooses the endpoint; tutorials use loopback. A non-loopback endpoint needs a keyring **and** TLS, or an explicit `Rhp::net::insecure_lan` (plaintext with local peers only, `dev` only) |
| Admission | unauthenticated connections: a total cap, a per-source cap, a first-byte deadline, and the oldest silent connection gives its slot to a newcomer |
| Authentication | pre-shared keys; mutual keyed-BLAKE2b challenge-response. The client verifies the host's proof before sending its own. Unknown key names receive the same challenge shape as known ones, rather than an explicit unknown-name response |
| Identity and role | each key is an **identity** (its own Lua state) with a **role**: `observe`, `patch`, `admin` |
| Script signing | `patch` and `admin` code must be Ed25519-signed by a key in the host's trusted signers. `observe` may send unsigned code, except at hardening `production`. A signature that is present must verify for every role |
| Channel | TLS 1.3 on networks, bound to the key handshake. Post-authentication frames also have a per-session, per-direction keyed MAC |
| Sandbox | allow-listed Lua libraries, no `__gc` finalizers, addresses shown as keyed hashes; `admin` gets the full standard library only in a `dev` build at hardening `dev` |
| Limits | per identity, by role: observe has limits of its own, capped from `lan` up; every role is capped at `production`; per-identity request rates, pump budgets and handler counts |
| Audit | request events; source-bearing operations include BLAKE2b-256 hash and signer; a suspended request is reported when it finishes, with its final outcome; `auth_failed` names the key a refused peer tried |
| Kill switches | compile time `RHP_ENABLE=OFF`; run time `host.set_enabled(false)` (every session closed, no scripts run until it is switched on again) |

## Setting up keys

Do this once per developer with the CLI:

```bash
rhp-cli keygen alice                        # alice.rhpid (private); prints the host's lines, the PSK left in the file (role patch by default)
rhp-cli pubkey -i alice.rhpid               # the keyring line (PSK included) and the signers line, whole
rhp-cli pubkey -i alice.rhpid --role admin  # the keyring line with another role
```

Host-file format (one entry per line, `#` starts a comment). Values below are abbreviated illustrations, not valid keys; use the generated CLI lines:

```text
# keys.txt          name  role   base64-psk
alice  admin  q3J...
bob    patch  w8K...
viewer observe e1D...
```

```text
# signers.pub       name  base64-ed25519-public-key
alice  MCow...
bob    hF2...
```

Load and validate `keyring::from_file` and `trusted_signers::from_file` before constructing the host; the [checked host example](getting-started.md#first-run-host-plus-rhp-cli) shows the full setup. `key::from_env` / `from_file` read a base64-encoded PSK, not an Ed25519 identity file. Keep `keys.txt` owner-only: `keyring::from_file` puts a line in `warnings()` when other users can read it. The host doesn't print that itself; show it, as the example does.

A PSK is 16–64 **decoded bytes**; generation uses 32 bytes, then base64-encodes them. An Ed25519 private key is a 32-byte seed. Managed secret-key buffers are wiped on destruction. `keygen` keeps the PSK in the identity file: its keyring line reads `alice patch <psk from alice.rhpid>` unless you pass `--show-secret`. `pubkey` prints the PSK so the host can be provisioned, so its output is not entirely public: protect it as well as the identity file. `keygen --role admin` prints a warning; an unknown role exits with status 2.

The identity file looks like this and must be kept private. It is written atomically and owner-only on every OS (POSIX: created exclusively with mode 0600, then renamed into place; Windows: an explicit DACL for your account alone, with the folder's permissions blocked):

```text
name        = "dev"
psk         = "base64…"          # shared with the host's keyring
signing_key = "base64…"          # Ed25519 private key; the host trusts the public half
signer      = "dev"              # optional: name the host's signers file uses (default: name)
```

The PSK identity name and the signer name can differ, so one person can sign with a key whose name is not the connection key's.

Loading an identity file that other users can read, or whose PSK looks chosen by a person rather than generated (printable text, a repeated pattern), adds a line to `identity_file::warnings`; `rhp-cli` prints them as `warning: ...`. Neither refuses the file.

## Roles in practice

| Give | To | Because |
|---|---|---|
| `observe` | dashboards, QA readers | binding permissions deny application mutations when functions are correctly tagged; observe can't register timers, handlers or tasks; budgets still matter (capped from `lan` up) |
| `patch` | developers | can change state, but only through bindings you wrote, and only reversibly or with `irreversible` marking |
| `admin` | very few people | `revert_all`, blobs, `pin`, admin-tagged bindings, **and, in a `dev` build at hardening `dev`, the whole Lua stdlib including `io` and `os.execute`** |

Roles are checked twice: the host checks request permissions and bindings check their own roles. Purity is an application contract, not something the binder can prove; an untagged mutating function or an explicit lower role on a mutating binding defeats the intended observe boundary.

A client signs with `Rhp::security::signing_key` (from its identity file); the host checks with `Rhp::security::trusted_signers`. Both keep a small process-wide cache (64 entries each) of recent signatures, keyed by the public key, the signature and the source's BLAKE2b-256, so a repeated script is signed and verified once. The host still looks up the named signer in its own trusted signers before it looks in the cache: an untrusted signer is refused, and another key, signature or source misses the cache and is checked in full.

Signing covers `exec`, `load` and `reload` source. A signer authorizes those source bytes, not every future execution context: `call` invokes existing exports and rollback reloads stored source. The host's in-memory keyring/trusted-signers configuration is not watched for file changes; restart or reconstruct the host when updating those files.

## Hardening levels

A build's `RHP_HARDENING` (CMake: `dev`, the default, `lan` or `production`; `Rhp::kBuildHardening` in C++, `rhp_HARDENING` in the installed package) is the most it allows. A config may raise it (`Rhp::config<>::hardening<Rhp::hardening::kLan>`; a level below the build's doesn't compile), and so may a host (`host_options::hardening`): the host runs at the strictest of the three. What the build's level doesn't allow is compiled out, so no config, option or memory patch turns it back on.

| | `dev` | `lan` | `production` |
|---|---|---|---|
| for | your own machine | test phones, QA and internal builds | builds you ship |
| admin's full Lua standard library (`io`, `os`, `package`, `debug`, finalizers) | yes | no: admin gets patch's libraries and keeps its admin rights | no |
| unsigned observe code | yes | yes | refused (`kBadSignature`) |
| remote debugger (`client.debug`) | yes | yes | refused (`kForbidden`) |
| `insecure_lan` (host, gateway, client), `signer<unsigned_scripts>` | yes | refused | refused |
| [dev sessions](#dev-sessions) | on loopback or local IPC | refused | refused |
| observe limits | `host_options::observe_limits` as set | capped by `kObserveCaps` | capped by `kObserveCaps` and `kProductionCaps` |
| patch and admin limits | as configured | as configured | capped by `kProductionCaps` |
| `host.advertise()` | yes | yes | refused (`kForbidden`) |
| HTTP gateway | yes | yes | only with `http_require_binding` |

Compiled out: admin's full standard library and dev sessions from `lan` and `production` builds; unsigned observe code and the debugger from `production` builds. A `host<Cfg>` whose config says `signer<unsigned_scripts>` doesn't compile above `dev` (`Rhp::host_configuration`); in a `dev` build, a host raised above `dev` by its options refuses to start with it.

The caps (`<rhp/core/hardening.hpp>`):

| Field | `Rhp::kObserveCaps` (observe, from `lan`) | `Rhp::kProductionCaps` (every role, `production`) |
|---|---|---|
| `instructions` | 2,000,000 | none |
| `memory` | 64 MiB | 512 MiB |
| `wall_ms` | 20 | 1000 |
| `cancel_checks` | `kEverything` | `kEverything` |
| `event_queue` | 1024 | 65,536 |
| `request_rate` | 10 | none |
| `pump_requests` | 2 | none |
| `handlers` | none (observe can't register any) | none |

`Rhp::capped(limits, caps)` turns 0 (unlimited) and any value above a cap into the cap and keeps a smaller value you set; `cancel_checks` becomes the stricter scope. It covers `instructions`, `memory`, `wall_ms`, `event_queue`, `async_ms`, `request_rate`, `pump_requests` and `handlers`; network and wire limits (`max_frame`, the handshake limits, heartbeats) are host-wide and never capped.

```cpp
using lan_cfg = Rhp::config<>::hardening<Rhp::hardening::kLan>; // a host or client of this config is lan at least

Rhp::host_options options;
options.hardening = Rhp::hardening::kLan; // raises the config's level, never lowers it
options.observe_limits = Rhp::limits{.instructions = 1'000'000, .wall_ms = 10, .request_rate = 5};
```

A refusal shows where it happens: a host that can't start at its level (an `insecure_lan` endpoint, `unsigned_scripts`, a dev session) listens on nothing and `port()` says why (`kForbidden`); a refused gateway is reported by `gateway_port()`, a refused advertisement by `advertise()`; a client above `dev` refuses an `insecure_lan` endpoint on its first call (an `rhp-cli` built at `lan` or `production` refuses `--insecure-lan`). Release channels (`release::manager`) follow the build's level only: a `dev` build gives an admin channel the full standard library.

## Dev sessions

In a `dev` build, a host that listens only on this machine can open a dev session: a connection without key files on either side.

```cpp
Rhp::host_options options;
options.dev_session = "my_game";
Rhp::host<> host{Rhp::endpoint::listen("127.0.0.1", 0), Rhp::security::keyring{}, Rhp::security::trusted_signers{}, options};
```

```bash
rhp-cli connect --dev my_game     # or --dev alone while one program has a session open
```

- The host generates an identity named `dev-session` (a fresh PSK, role admin) and an Ed25519 signer of the same name for this run, and accepts them next to the keys and signers you passed. Once it listens it writes the connect file `<config>/rhp/dev/my_game.rhpdev` (`%APPDATA%`, `~/Library/Application Support`, `$XDG_CONFIG_HOME` or `~/.config`), atomically and owner-only; the host's destructor removes it. `Rhp::security::dev_session_path(app)` says where and `read_dev_session` reads one (`<rhp/security/dev_session.hpp>`, not in `<rhp/rhp.hpp>`). App names are 1–64 letters, digits, `.`, `_` or `-`, starting with a letter or digit.
- `rhp-cli connect --dev` reads that file and runs the usual handshake and script signatures. It connects only to TCP on a loopback address or local IPC, takes the only file when no app is named and lists them when there are several; `--timeout` applies, the other connection options don't.
- The identity is admin because the file is the developer's own: any process that can read it runs as the same user and could change the program anyway. It also means any process of that user can connect: dev machines only.
- Refused, with `kForbidden` from `port()` and no file written: a non-loopback address, the in-process `loopback` transport (no other process can reach it), reverse mode, an authenticator other than `psk_keyring` or a signer other than `ed25519` (the defaults), and a host above hardening `dev`. A `lan` or `production` build leaves dev sessions out. iOS and Android have no user configuration folder: the host stops listening and `port()` reports why.
- `headless_server --port 0 --dev-session my_game` opens one too.

The [getting started](getting-started.md#first-run-shortcut-a-dev-session) page has a complete program.

## Hardening checklist

- Choose the level: `production` for anything you ship, `lan` for test devices and QA builds, `dev` for your own machine only. One build can serve several hosts: raise each with `config<>::hardening` or `host_options::hardening`.
- Keep the host on loopback unless you need the network. If you need the network, leave TLS on. `insecure_lan` exists only at `dev`, and even there speaks plaintext only with loopback, private (RFC 1918, RFC 4193) and link-local peers.
- One key per person, so the audit log and revert scopes mean something. Revoke by removing the line and restarting the host.
- Give `admin` sparingly. Prefer `Rhp::requires_role<Rhp::role::kAdmin>` on only the dangerous bindings.
- Set `limits` (`instructions`, `wall_ms`, `memory`, and `slice_us` for games) on any host that hands out keys to people you do not fully trust; in a `dev` build the defaults are unlimited. Observe identities run under `host_options::observe_limits` (default: the config's limits), capped by `kObserveCaps` from `lan` up; `production` caps every role. `limits.request_rate`, `pump_requests` and `handlers` bound how often one identity runs and how much it keeps scheduled. `observe` code is unsigned below `production` and can otherwise hold the pump thread or grow memory until someone cancels it.
- Remote event subscription (`client.on`, `kSubscribe`) needs only observe and covers every C++ `lua_event` in the process: don't put secrets in C++ event arguments, or don't hand keys to untrusted readers.
- The HTTP gateway authenticates every request with its own proof and signs every answer (`X-RHP-Proof`); `host_options::http_require_binding` makes the TLS channel binding mandatory, and `production` requires it ([networking](networking.md)).
- Run `host.on_any(Rhp::audit::file_sink{...})` in anything shared.
- Use `RHP_ENABLE=OFF` for builds that must not accept remote code; an enabled release build remains an execution endpoint. The runtime switch, `set_enabled(false)`, closes every session (each identity reverts as on a disconnect, except modules an admin pinned), refuses new connections, stops a reverse-mode host's dialing and runs no requests, handlers, tasks or release channels until `set_enabled(true)`. Patches held by pinned modules and release channels still run when game code hits them: send `revert_all` and deactivate the channels first to remove them.
- Never use `signer<Rhp::security::unsigned_scripts>` outside tests and fully trusted setups; a host refuses it above `dev`.
- Handshake DoS: at most `limits.pending_handshakes` (64) unauthenticated connections at once and `handshakes_per_source` (8) from one IPv4 address or IPv6 /64, native and HTTP together. A connection that sends nothing within `first_byte_ms` (2 s) is closed, a newcomer takes the slot of the oldest silent one, and any connection not authenticated after `handshake_timeout_ms` (5 s) is closed. Reliable UDP answers a first Hello with a stateless cookie, so a spoofed source address gets no slot.
- Keep key files owner-only and read the `warning:` lines rhp-cli and your loaders print.

## Known limits

- A connection that has sent something keeps its slot until it authenticates or `handshake_timeout_ms` closes it. When every slot under a cap is held that way, new connections (a resume included) are refused until one times out.
- A probe can tell a known session id from an unknown one.
- Without `ca_pem`, the host's certificate is not validated; protection comes from binding the PSK handshake to the TLS channel. That is sound for PSK users but is not a PKI.
- Mbed TLS calls are serialized by a process-wide lock.
- Platform verification is tracked in [Status and TODO](../TODO.md): hosted CI passes, but macOS and iOS haven't run on real hardware. An existing preset is not a passed platform build.
- In a `dev` build at hardening `dev`, admin retains `dofile`, `loadfile`, `collectgarbage` and `string.dump`, along with `io`, `debug` and native library loading. RHP's source loaders and replaced `load` are text-only; the admin state is not a containment boundary, and those outside effects are not journaled.
- Caps bound one identity, not the host: under `kObserveCaps` an observe identity can still take 40 ms of a `pump()` (2 runs of 20 ms) and 200 ms of every second (10 runs), and each observe key gets as much.
- A dev session's connect file can be read by any process of the same user.
- Identity files the Python client writes on Windows get their folder's permissions (`rhp-cli keygen` sets an owner-only DACL).
- Stage 13b (device keys and pairing, operator certificates, a root of trust, capability scopes; protocol revision 7) and 13c (signed releases pulled over HTTPS, support sessions through a relay, a hash-chained audit, a signed remote disable) are planned, not built ([decisions](../decisions/stage13-security.md)).
