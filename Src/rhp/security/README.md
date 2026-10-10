# security — layer 3

Who may connect and what each frame proves. Namespace `Rhp::security`.

| Header | What |
|---|---|
| `authenticator.hpp` | `authenticator` / `credential` concepts; `host_handshake` / `client_handshake` (one per connection); `auth_grant` (identity, role, per-direction frame MAC keys) |
| `keyring.hpp` | `keyring`: name → key → role |
| `psk_keyring.hpp` | `psk_identity` (a client's name + key), `psk_keyring` (the default authenticator) |
| `key.hpp` | `key` (16..64-byte secret, wiped on destruction): `from_base64` / `from_env` / `from_file` / `generate`; base64 helpers |
| `signer.hpp` | the `signer` concept (`config<>::signer<S>`), `kScriptSignatureDomain`, `unsigned_scripts` (the typed opt-out) |
| `ed25519.hpp` | `ed25519` (the default signer): `ed25519_secret_key` / `ed25519_public_key`, `signing_key` (client), `trusted_signers` (host; parses `name base64-public-key` files) |
| `identity_file.hpp` | a developer's `.rhpid` file: name, PSK, signing key; prints the host's keyring / signers lines |
| `hash.hpp` | `blake2b_256`, `to_hex` (audit hashes) |
| `http_auth.hpp` | per-request HTTP proofs (`http_proof`, `http_authorization`, `verify_http_authorization`), the `http_authenticator` concept, `http_replay_guard`, the `X-RHP-Signature` encoding: see the [networking guide](../../../Docs/guide/networking.md#authenticating-requests) |
| `tls/` | `Rhp::security::tls` — TLS 1.3 engines (OpenSSL, Mbed TLS) behind the `tls::backend` concept: see [tls/README.md](tls/README.md) |

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

MAC = keyed BLAKE2b-256 (Monocypher). Proofs and MACs are compared in constant time (`crypto_verify32`).

## Rules

- `monocypher.h` only in this folder's `.cpp` files. The session layer sees `host_handshake`, `client_handshake` and `wire::frame_sealer` only.
- Authentication is mutual: a client never sends its proof to a host that failed to prove the key first.
- HTTP requests carry a per-request MAC instead of that handshake. Unknown key names are checked against a per-process decoy key, so timing can't probe them either. Proofs are accepted once (`http_replay_guard`, a quota per key). They aren't channel-bound: HTTPS clients must verify the host certificate.
- An unknown key name gets a normal-looking challenge (made with a random secret), so key names can't be probed.
- Secrets are wiped (`crypto_wipe`) when keys, handshakes and sealers die.
- Script signatures are Ed25519 (RFC 8032) over `"rhp/script\0" ‖ source`; the host checks them before anything runs, except unsigned code from observe sessions.
- `RHP_ENABLE=OFF`: keys, keyring, signing keys, trusted signers and identity files still build (`signing_keys.cpp`); signing and verifying report `kDisabled` (`ed25519_disabled.cpp`); the handshake and hashing aren't built.
