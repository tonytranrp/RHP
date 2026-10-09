# security — layer 3

Who may connect and what each frame proves. Namespace `Rhp::security`.

| Header | What |
|---|---|
| `authenticator.hpp` | `authenticator` / `credential` concepts; `host_handshake` / `client_handshake` (one per connection); `auth_grant` (identity, role, per-direction frame MAC keys) |
| `keyring.hpp` | `keyring`: name → key → role |
| `psk_keyring.hpp` | `psk_identity` (a client's name + key), `psk_keyring` (the default authenticator) |
| `key.hpp` | `key` (16..64-byte secret, wiped on destruction): `from_base64` / `from_env` / `from_file` / `generate`; base64 helpers |

## PSK handshake

```text
client → hello     {key = name, nonce = Nc}
host   → challenge {nonce = Nh, proof = MAC(psk, "rhp/host"   ‖ T)}     T = len ‖ name ‖ Nc ‖ Nh
client → response  {proof = MAC(psk, "rhp/client" ‖ T)}                  only after the host's proof checked out
host   → welcome   (first MAC'd frame)
frame keys         MAC(psk, "rhp/c2h" ‖ T), MAC(psk, "rhp/h2c" ‖ T)
```

MAC = keyed BLAKE2b-256 (Monocypher). Proofs and MACs are compared in constant time (`crypto_verify32`).

## Rules

- `monocypher.h` only in this folder's `.cpp` files. The session layer sees `host_handshake`, `client_handshake` and `wire::frame_sealer` only.
- Authentication is mutual: a client never sends its proof to a host that failed to prove the key first.
- An unknown key name gets a normal-looking challenge (made with a random secret), so key names can't be probed.
- Secrets are wiped (`crypto_wipe`) when keys, handshakes and sealers die.
- Script signing (Ed25519) arrives in Stage 4; TLS in Stage 5.
