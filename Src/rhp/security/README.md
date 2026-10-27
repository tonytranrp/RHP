# security — layer 3

Who may connect, what each frame proves, and who signed a script. Namespace `Rhp::security`. Target `Rhp::security`; depends on `wire` and `platform`, privately on Monocypher. Usage: [security guide](../../../Docs/guide/security.md); decisions: [security model](../../../Docs/decisions/security-model.md).

| Header | What |
|---|---|
| `authenticator.hpp` | the `authenticator` / `credential` concepts (`config<>::auth<A>`, clients use `A::credential`); `host_handshake` / `client_handshake` (one per connection); `auth_grant` (identity, role, per-direction frame sealers) |
| `keyring.hpp` | `keyring`: name → key → role; `parse` / `from_file` read one `name role base64-key` per line (`#` comments) |
| `psk_keyring.hpp` | `psk_identity` (a client's name + key), `psk_keyring` (the default authenticator, made from a `keyring`) |
| `key.hpp` | `key` (16..64-byte secret, wiped on destruction): `from_base64` / `from_bytes` / `from_env` / `from_file` / `generate`, `to_base64`; `secure_wipe`, `base64_encode`, `base64_decode` |
| `signer.hpp` | the `signer` concept (`config<>::signer<S>`: `S::key` signs, `S::trust` verifies), `kScriptSignatureDomain`, `unsigned_scripts` (the typed opt-out) |
| `ed25519.hpp` | `ed25519` (the default signer): `ed25519_secret_key` / `ed25519_public_key`, `signing_key` (client: name + secret, `sign(source)`), `trusted_signers` (host: `parse` / `from_file` of `name base64-public-key` lines, `verify(source, signature)` → signer name) |
| `identity_file.hpp` | a developer's `.rhpid` file (`load`, `parse`, `generate`, `to_text`, `save`): name, PSK, signing key; `credential()`, `signer_key()`, and the host's `keyring_line(role)` / `signers_line()`; `warnings` (a file other users can read) |
| `dev_session.hpp` | a dev session's connect file (`<user config>/rhp/dev/<app>.rhpdev`, decision AL7): `dev_session` (app, transport, host, port, identity; `parse`, `to_text`, `endpoint()`), `write_dev_session` / `read_dev_session`, `dev_session_directory`, `dev_session_path(app)` |
| `hash.hpp` | `blake2b_256`, `digest256`, `to_hex` (audit hashes, release ids); `keyed_blake2b_256` (a MAC of domain || data: the release bytecode cache), `digests_equal` (constant time) |
| `http_auth.hpp` | per-request HTTP proofs (`http_proof`, `http_authorization`, `verify_http_authorization`) with optional TLS channel binding, answer proofs (`http_answer_proof`, `verify_http_answer`), the `http_authenticator` concept, `http_replay_guard`, the `X-RHP-Signature` encoding: see the [networking guide](../../../Docs/guide/networking.md) |
| `tls/` | `Rhp::security::tls` (target `Rhp::tls`): TLS 1.3 engines behind the `tls::backend` concept: [tls/README.md](tls/README.md) |

```cpp
auto me = *Rhp::security::identity_file::load("dev.rhpid");      // rhp-cli keygen dev
std::println("{}", me.keyring_line(Rhp::role::kPatch));            // for the host's keyring file
auto keys = *Rhp::security::keyring::from_file("keys.txt");       // host
auto signers = *Rhp::security::trusted_signers::from_file("signers.pub");
auto who = signers.verify(source, *me.signer_key()->sign(source)); // "dev", or kBadSignature
```

## PSK handshake

```text
client → hello     {key = name, nonce = Nc}
host   → challenge {nonce = Nh, proof = MAC(psk, "rhp/host"   ‖ T)}     T = len ‖ name ‖ Nc ‖ Nh
client → response  {proof = MAC(psk, "rhp/client" ‖ T)}                  only after the host's proof checked out
host   → welcome   (first MAC'd frame)
frame keys         MAC(psk, "rhp/c2h" ‖ T), MAC(psk, "rhp/h2c" ‖ T)
under TLS          T also ends with the connection's tls-exporter value (bind_channel): a relay that
                   terminates TLS on both sides has two values, so no proof matches
```

MAC = keyed BLAKE2b-256 (Monocypher). Proofs and MACs are compared in constant time (`digests_equal`, Monocypher's `crypto_verify32`).

## Rules

- `monocypher.h` only in this folder's `.cpp` files. The session layer sees `host_handshake`, `client_handshake` and `wire::frame_sealer` only.
- Authentication is mutual: a client never sends its proof to a host that failed to prove the key first.
- An unknown key name gets a normal-looking challenge (made with a random secret), so key names can't be probed.
- HTTP requests carry a per-request MAC instead of the handshake. Unknown key names are checked against a per-process decoy key, so timing can't probe them either. Proofs are accepted once (`http_replay_guard`, a quota per key). With `X-RHP-Channel: tls-exporter` they are channel-bound like the handshake; answers carry `X-RHP-Proof`, a MAC under a key derived from the request's MAC, so clients can check them without trusting the transport.
- Secrets are wiped (`secure_wipe` / `crypto_wipe`) when keys, handshakes and sealers die.
- Files holding secrets (identity files, dev session files) are written with `platform::write_private_file`: atomically, and their owner's alone on every OS (POSIX 0600, a Windows DACL for the current user with inheritance blocked). Loading one that other users can read puts a line in `warnings`; the loaders have no logger, so callers show them (rhp-cli prints `warning: ...`). Nothing here refuses a file for it.
- A dev session file says where its host listens but security doesn't know transports: whoever connects refuses anything but a loopback address or local IPC (rhp-cli does).
- Script signatures are Ed25519 (RFC 8032) over `"rhp/script\0" ‖ source`; the host checks them before anything runs, except unsigned code from observe sessions. A signature that is present must verify.
- Signing and verifying share a process-wide cache (64 recent signatures made, 64 found valid), keyed by public key, signature and the source's BLAKE2b-256, under one mutex. Ed25519 is deterministic, so a repeated signed exec signs and verifies once. Both are facts about bytes: `trusted_signers::verify` still checks that it trusts the signer before it looks; a different key, signature or source misses.
- `RHP_ENABLE=OFF`: keys, the keyring, signing keys, trusted signers, identity and dev session files still build (`signing_keys.cpp`); signing and verifying report `kDisabled` (`ed25519_disabled.cpp`); the handshake and hashing aren't built and Monocypher isn't fetched.
