# Security

RHP deliberately accepts remote code. Authentication, roles, signatures and TLS control who may use it; execution budgets remain unlimited by default and must be chosen for the application. An admin identity is trusted with the process's full Lua standard-library capabilities.

## The layers

| Layer | What it does |
|---|---|
| Bind rules | the application chooses the endpoint; tutorials use loopback. A non-loopback endpoint needs a keyring **and** TLS, or an explicit `Rhp::net::insecure_lan` |
| Authentication | pre-shared keys; mutual keyed-BLAKE2b challenge-response. The client verifies the host's proof before sending its own. Unknown key names receive the same challenge shape as known ones, rather than an explicit unknown-name response |
| Identity and role | each key is an **identity** (its own Lua state) with a **role**: `observe`, `patch`, `admin` |
| Script signing | `patch` and `admin` code must be Ed25519-signed by a key in the host's trusted signers. `observe` may send unsigned code. A signature that is present must verify for every role |
| Channel | TLS 1.3 on networks, bound to the key handshake. Post-authentication frames also have a per-session, per-direction keyed MAC |
| Sandbox | allow-listed Lua libraries; `admin` gets the full standard library (an admin key is fully trusted) |
| Audit | request events; source-bearing operations include BLAKE2b-256 hash and signer. Suspended-script final outcomes have an [open reporting defect](../TODO.md#confirmed-issues-at-the-current-commit) |
| Kill switches | compile time `RHP_ENABLE=OFF`; run time `host.set_enabled(false)` |

## Setting up keys

Do this once per developer with the CLI:

```bash
rhp-cli keygen alice                       # alice.rhpid (private) + two lines for the host
rhp-cli pubkey -i alice.rhpid --role patch # prints the host lines again with another role
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

Load and validate `keyring::from_file` and `trusted_signers::from_file` before constructing the host; the [checked host example](getting-started.md#first-run-host-plus-rhp-cli) shows the full setup. `key::from_env` / `from_file` read a base64-encoded PSK, not an Ed25519 identity file.

A PSK is 16–64 **decoded bytes**; generation uses 32 bytes, then base64-encodes them. An Ed25519 private key is a 32-byte seed. Managed secret-key buffers are wiped on destruction. The CLI intentionally prints the PSK in `keygen` and `pubkey` output so the host can be provisioned: `pubkey` output is not entirely public. Protect that output as well as the identity file.

The identity file looks like this and must be kept private (written owner-only on POSIX):

```text
name        = "dev"
psk         = "base64…"          # shared with the host's keyring
signing_key = "base64…"          # Ed25519 private key; the host trusts the public half
signer      = "dev"              # optional: name the host's signers file uses (default: name)
```

The PSK identity name and the signer name can differ, so one person can sign with a key whose name is not the connection key's.

## Roles in practice

| Give | To | Because |
|---|---|---|
| `observe` | dashboards, QA readers | binding permissions deny application mutations when functions are correctly tagged; budgets still matter |
| `patch` | developers | can change state, but only through bindings you wrote, and only reversibly or with `irreversible` marking |
| `admin` | very few people | `revert_all`, blobs, `pin`, admin-tagged bindings, **and the whole Lua stdlib including `io` and `os.execute`** |

Roles are checked twice: the host checks request permissions and bindings check their own roles. Purity is an application contract, not something the binder can prove; an untagged mutating function or an explicit lower role on a mutating binding defeats the intended observe boundary.

Signing covers `exec`, `load` and `reload` source. A signer authorizes those source bytes, not every future execution context: `call` invokes existing exports and rollback reloads stored source. The host's in-memory keyring/trusted-signers configuration is not watched for file changes; restart or reconstruct the host when updating those files.

## Hardening checklist

- Keep the host on loopback unless you need the network. If you need the network, leave TLS on; do not use `insecure_lan` outside a network you control.
- One key per person, so the audit log and revert scopes mean something. Revoke by removing the line and restarting the host.
- Give `admin` sparingly. Prefer `Rhp::requires_role<Rhp::role::kAdmin>` on only the dangerous bindings.
- Set `limits` (`instructions`, `wall_ms`, `memory`, and `slice_us` for games) on any host that hands out keys to people you do not fully trust; defaults are unlimited. `observe` code is unsigned and can otherwise hold the pump thread or grow memory until someone cancels it.
- Run `host.on_any(Rhp::audit::file_sink{...})` in anything shared.
- Use `RHP_ENABLE=OFF` for builds that must not accept remote code; an enabled release build remains an execution endpoint. The runtime switch refuses new request dispatch but does not undo prior effects or cancel a request already executing.
- Never use `signer<Rhp::security::unsigned_scripts>` outside tests and fully trusted setups.
- Handshake DoS: at most `limits.pending_handshakes` (64) unauthenticated connections, each closed after `handshake_timeout_ms` (5 s).

## Known limits

- Idle unauthenticated connections count against `pending_handshakes` and can delay a resume.
- A probe can tell a known session id from an unknown one.
- Without `ca_pem`, the host's certificate is not validated; protection comes from binding the PSK handshake to the TLS channel. That is sound for PSK users but is not a PKI.
- Mbed TLS calls are serialized by a process-wide lock.
- Platform verification and the YAML/billing blockers for CI are tracked in [Status and TODO](../TODO.md). An existing preset/workflow is not a passed platform build.
- Default admin retains `dofile`, `loadfile`, `collectgarbage` and `string.dump`, along with `io`, `debug` and native library loading. RHP's source loaders and replaced `load` are text-only; the admin state is not a containment boundary, and those outside effects are not journaled.
