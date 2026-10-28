# remote_exec

A host and its clients in one process: a "game" thread pumps `Rhp::host`, the main thread plays three developers with three keys.

| Key | Role | Tries |
|---|---|---|
| `viewer` | observe (signed: a production-hardened host runs no unsigned code) | reads `game.gravity`; writing it and loading a module fail with `kForbidden` |
| `qa` | patch | loads `scripts/moon.lua` (gravity -1.6), calls a reversible binding, reads `status` and the LuaLS stubs (`describe`) over the wire, starts `while true do end` and cancels it with `client.cancel()` while the game thread is stuck in it, then disconnects: everything it did is reverted |
| `dev` | admin | prints (the line streams back through `client_options::on_output`), lists modules, calls `revert_all` |

Scripts from `qa` and `dev` are signed by one developer key (`Rhp::security::signing_key`) that the host trusts (`Rhp::security::trusted_signers`); the same `qa` key without a signing key is refused with `kBadSignature`. The tour runs twice: over the in-process loopback transport (`config<>::transport<Rhp::net::loopback>`), then over TCP on `127.0.0.1` with port 0 (`host.port()` reports the real one). Finally a wrong key is refused with `kAuth`.

The keyring, identities and signer are built in code here; a real host reads them from files ([security](../../Docs/guide/security.md#setting-up-keys)).

## Build and run

From the repository root:

```bash
cmake --build --preset windows-msvc --target remote_exec
ctest --preset windows-msvc -R example.remote_exec --output-on-failure
```

Or run `build/windows-msvc/Examples/remote_exec/Debug/remote_exec.exe` directly. It exits with 0 when every check passed.

For a host in a separate process, driven by `rhp-cli`, see [`headless_server`](../headless_server). The C++ API is in [host and client](../../Docs/guide/host-and-client.md).
