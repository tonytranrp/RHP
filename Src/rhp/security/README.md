# security — layer 3

Who may connect, what each frame proves, and who signed a script. Namespace `Rhp::security`. Target `Rhp::security`; depends on `wire` and `platform`, privately on Monocypher and `Rhp::tls` (P-256 for key handles). Usage: [security guide](../../../Docs/guide/security.md); decisions: [security model](../../../Docs/decisions/security-model.md).

| Header | What |
|---|---|
| `authenticator.hpp` | the `authenticator` / `credential` concepts (`config<>::auth<A>`, clients use `A::credential`); `host_handshake` / `client_handshake` (one per connection); `auth_grant` (identity, role, scopes, per-direction frame sealers) |
| `keyring.hpp` | `keyring`: name → key → role and scopes (`keyring_entry::scopes`, an `Rhp::scope_set`, everything by default); `parse` / `from_file` read one `name role base64-key [scopes] [env=dev\|prod]` per line (scopes: comma-separated patterns such as `lib:game,!cap:economy.grant`, decision AL13; old lines without the column allow everything; `#` comments); `env_of(name)` / `set_env`; `warnings()` (a file other users can read) |
| `psk_keyring.hpp` | `psk_identity` (a client's name + key), `psk_keyring` (the default authenticator, made from a `keyring`; `with(entry)`: a copy that also accepts one more key, as a host's dev session adds its own) |
| `key.hpp` | `key_env` (`kDev` / `kProd`, `parse_key_env`, `parse_env_field` for `env=` tags); `key` (16..64-byte secret, wiped on destruction): `from_base64` / `from_bytes` / `from_env` / `from_file` / `generate`, `to_base64`, `looks_weak` (printable or patterned bytes: a warning, never a refusal); `secure_wipe`, `base64_encode`, `base64_decode` |
| `key_handle.hpp` | `key_handle` (decision AL10): a type-erased signing key, `alg()` (`key_algorithm::kEd25519` / `kP256`), `public_key()`, `fingerprint()`, `sign(message)`; made `from_private_key` (software Ed25519 seed or P-256 scalar), `from_ed25519`, or `from_callback` (hardware keys: the private half never enters RHP); `verify(alg, public_key, message, signature)`, `key_fingerprint`, `generate_private_key` |
| `key_store.hpp` | `key_store` (`load` / `store` / `remove` by name; decision AL10) with `file_key_store` (owner-only `<name>.rhpkey` files: plain, passphrase-sealed or wrapped), `dpapi_key_store` (Windows), `keychain_key_store` (Apple, untested on hardware), `callback_key_store` (the app's functions: Android Keystore wrapping); `store_key` / `load_key` (private keys as `key_handle`s); `seal_with_passphrase` / `open_with_passphrase` (Argon2i + XChaCha20-Poly1305) |
| `signer.hpp` | the `signer` concept (`config<>::signer<S>`: `S::key` signs, `S::trust` verifies), `kScriptSignatureDomain`, `unsigned_scripts` (the typed opt-out); the optional context overloads: `signature_context` / `context_trust` / `verify_in_context` (hosts), `signing_context` / `context_key` / `sign_in_context` (clients) |
| `operator_cert.hpp` | operator certificates (decision AL11): `operator_cert_fields` (serial, principal, alg, pub, validity, `max_role`, apps, envs, scopes, critical), `issue_operator_cert`, `encode_operator_cert` / `decode_operator_cert` (canonical), the `.rhpcert` text (`operator_cert_to_text`, `load_operator_cert`, `save_operator_cert`), `trusted_cas` (`name base64-public-key [env=dev\|prod]` lines), `verify_operator_cert`, `operator_ca_key` (the CA's key file, `rhp-cli ca init`) |
| `certified.hpp` | the `certified` signer policy: `script_claims` (`encode_claims` / `decode_claims`), `certified::key` (operator key + certificate + `claim_options`), `certified::trust` (trusted CAs, `trust_options`, `revoke(serial)`, `set_revocation_check`) |
| `pairing.hpp` | pairing formats (decision AL10): `pairing_link` (`rhp-pair://<host>:<port>?secret=<base64url 32 bytes>&fp=<fingerprint>&name=<percent-encoded>`: `parse` / `to_text`, strict: an IPv6 host in brackets, port 1..65535, canonical base64url, `fp` a `key_fingerprint`, every key once, unknown keys refuse the link); `pairing_secret` / `pairing_book` (the host's one-time secrets: `issue(lifetime)`, `consume(bytes)` once and in constant time: `kAuth` / `kExpired`, a capacity of unexpired secrets); builds with `RHP_ENABLE=OFF` |
| `pairing_cpace.hpp` | `cpace` (decision AL10): the CPace PAKE of draft-irtf-cfrg-cpace-21, suite CPACE-X25519-SHA512, initiator-responder: `start(role, {prs, ci, sid, ad})`, `message()` (Ya / Yb, 32 bytes), `finish(peer_message, peer_ad)` → the 64-byte ISK as a `key` (`kAuth` for a low-order peer point); `cpace_generator`; checked against the draft's X25519 vectors |
| `ed25519.hpp` | `ed25519` (the default signer): `ed25519_secret_key` / `ed25519_public_key`, `signing_key` (client: name + secret, `sign(source)`), `trusted_signers` (host: `parse` / `from_file` of `name base64-public-key` lines, `verify(source, signature)` → signer name) |
| `identity_revocations.hpp` | `identity_revocation_list` (certificate serials, signer keys, device keys as `public_key_ref {alg, pub}`), `revoked_identities` (the thread-safe union: `is_revoked_serial`, `is_revoked_signer`, `is_revoked_device`, `seq`, `snapshot`, `merge`, `replace`); the signed document is `release/identity_revocations.hpp`, the union a `release::manager` keeps |
| `identity_file.hpp` | key files (decision AL11): `identity_file`, a connection identity `.rhpid` (`load`, `parse`, `generate`, `generate_device`, `to_text`, `save`): name and PSK or device key (`alg`, `device_key`), `env`; `load` also reads the `signing_key_file` beside it (`.rhpsign`: `signer`, `signing_key` plain or passphrase-sealed, `env`), and the combined format from before (signing key inside) still reads; `credential()`, `signer_key()`, `device_key()`, and the host's `keyring_line(role)` / `signers_line()` / `device_line(role)` (tagged `env=..`); `warnings` (a file other users can read, a PSK that looks chosen by a person, a sealed signing key left closed) |
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

## CPace

```text
g    = map_to_curve_elligator2(decodeUCoordinate(SHA-512(lv_cat("CPace255", PRS, zpad, CI, sid))[0..32]))
Ya   = X25519(ya, g)        initiator (client) -> responder: Ya (32 bytes), ADa
Yb   = X25519(yb, g)        responder (host)   -> initiator: Yb (32 bytes), ADb
K    = X25519(y, Y_peer)    all zero (a low-order point): kAuth
ISK  = SHA-512(lv_cat("CPace255_ISK", sid, K) || lv_cat(Ya, ADa) || lv_cat(Yb, ADb))   64 bytes
```

Monocypher's `crypto_elligator_map` reads 254 bits of its input while `decodeUCoordinate` keeps 255; the map depends only on r², so the generator reduces u mod p and uses p - u when u ≥ 2^254 (in constant time). The draft's B.1 vectors (generator, Ya, Yb, K, ISK) and its low-order points (B.1.10) are unit tests.

## Rules

- `monocypher.h` only in this folder's `.cpp` files. The session layer sees `host_handshake`, `client_handshake` and `wire::frame_sealer` only.
- Authentication is mutual: a client never sends its proof to a host that failed to prove the key first.
- An unknown key name gets a normal-looking challenge (made with a random secret), so key names can't be probed.
- HTTP requests carry a per-request MAC instead of the handshake. Unknown key names are checked against a per-process decoy key, so timing can't probe them either. Proofs are accepted once (`http_replay_guard`, a quota per key). With `X-RHP-Channel: tls-exporter` they are channel-bound like the handshake; answers carry `X-RHP-Proof`, a MAC under a key derived from the request's MAC, so clients can check them without trusting the transport.
- Secrets are wiped (`secure_wipe` / `crypto_wipe`) when keys, handshakes and sealers die.
- Files holding secrets (identity files, dev session files) are written with `platform::write_private_file`: atomically, and their owner's alone on every OS (POSIX 0600, a Windows DACL for the current user with inheritance blocked). Loading one that other users can read, or whose PSK looks chosen by a person, puts a line in `warnings`; so does a host's keyring file other users can read (`keyring::warnings()`). The loaders have no logger, so callers show them (rhp-cli and the headless server example print `warning: ...`). Nothing here refuses a file for it.
- A dev session file says where its host listens but security doesn't know transports: whoever connects refuses anything but a loopback address or local IPC (rhp-cli does).
- Key handles: Ed25519 keys are 32-byte public keys and RFC 8032 signatures; P-256 keys are 65-byte SEC1 uncompressed public keys (`0x04 || X || Y`) and ECDSA over SHA-256 as raw `r || s` (64 bytes). P-256 runs on the TLS backend's crypto (`tls/p256.hpp`: OpenSSL where built, else Mbed TLS) and reports `kDisabled` without one; software P-256 signatures are randomized. A callback key's function may return a P-256 signature as DER (what the Secure Enclave, Android Keystore and PKCS#11 give); the handle turns it into `r || s`. A fingerprint is the first 16 bytes of BLAKE2b-256(`alg name || ":" || public key`) in unpadded base64url (22 characters).
- Passphrase sealing: Argon2i (one lane; default 64 MiB and 3 passes, written into the value as `argon2i:m=<KiB>,t=<passes>:`, which is also the AEAD's associated data) derives a 32-byte key from the passphrase and a random 16-byte salt; XChaCha20-Poly1305 (`crypto_aead_lock`, random 24-byte nonce) encrypts. The value is `header || base64(salt || nonce || mac || ciphertext)`. A wrong passphrase or a changed value is `kAuth`; a value asking for more than 1 GiB or 64 passes is refused before any work.
- Key stores check names (1..64 of letters, digits, `.`, `_`, `-`; not starting with `.`) before touching files or callbacks. A file store writes through `platform::write_private_file`; DPAPI and the Keychain are `platform/key_storage.cpp`. Without RHP (`RHP_ENABLE=OFF`) plain and wrapped files still work; sealing reports `kDisabled`.
- Script signatures are Ed25519 (RFC 8032) over `"rhp/script\0" ‖ source`; the host checks them before anything runs, except unsigned code from observe sessions. A signature that is present must verify.
- Certified signatures (decision AL11) are `{cert, claims, sig}`: Ed25519 by the certificate's operator key over `"rhp/script-claims\0" || canonical claims || source`; certificates are signed by an operator CA over `"rhp/opcert\0" || canonical body`. Bodies use the release manifest's encoding (`detail/canonical.hpp`: `wire::msgpack` over a fixed-order map, lists sorted and unique; decoding re-encodes and refuses anything that isn't canonical). `verify` checks, in order: the chain to a trusted CA and the certificate's validity (`kBadSignature`, `kExpired`), critical options (none is understood yet: any refuses the certificate, `kForbidden`), dev tags on a production host (`kForbidden`), revoked serials (`kRevoked`), the signature, the claims' expiry (in the future, within the certificate and `trust_options::max_lifetime`: `kExpired`), app / env / audience / identity and the certificate's apps / envs (`kOutOfScope`, empty = any), `max_role` against the session's role (`kForbidden`), the nonce (`kBadSignature` when replayed). The signer name is `principal#serial`.
- The replay cache is per trust (copies share it): nonces are kept until their claims' `not_after`, at most `trust_options::replay_entries`; when it is full of live ones a new signature is refused (`kLimitExceeded`) rather than evicting one that could then be replayed. Claims live at most `max_lifetime` (1 h by default; keys sign for 10 min), which bounds the cache's turnover.
- Critical options: neither `source-address` (the signature check doesn't see the peer's address) nor `observe-only` (`max_role observe` says the same) is implemented, so every critical entry refuses the certificate: a host never accepts a restriction it can't enforce.- Signing and verifying share a process-wide cache (64 recent signatures made, 64 found valid), keyed by public key, signature and the source's BLAKE2b-256, under one mutex. Ed25519 is deterministic, so a repeated signed exec signs and verifies once. Both are facts about bytes: `trusted_signers::verify` still checks that it trusts the signer before it looks; a different key, signature or source misses.
- `RHP_ENABLE=OFF`: keys, the keyring, signing keys, trusted signers, identity and dev session files, operator certificates' files and the trusted-CA file still build (`signing_keys.cpp`, `operator_cert.cpp`, `certified.cpp`); signing, issuing and verifying report `kDisabled` (`ed25519_disabled.cpp`), and so does every key handle (`key_handle_disabled.cpp`) and CPace (`pairing_cpace_disabled.cpp`); the handshake and hashing aren't built and Monocypher isn't fetched.
