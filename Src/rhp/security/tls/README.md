# security/tls — layer 3

TLS 1.3 for links that leave the machine. Namespace `Rhp::security::tls`; target `Rhp::tls` (layer 3, depends on `core` and `platform`; privately on OpenSSL and / or Mbed TLS). Options: `RHP_WITH_TLS`, `RHP_TLS_OPENSSL=AUTO|ON|OFF`, `RHP_TLS_MBEDTLS` ([configuration guide](../../../../Docs/guide/configuration.md)). Who gets TLS (non-loopback dials over network transports, `require_tls`) is decided by `session::channel_policy`.

| Header | What |
|---|---|
| `tls.hpp` | `settings` (`cert_pem`, `key_pem`, `ca_pem`, `server_name`), `engine` (one connection, sans-IO: `start`, `receive`, `send`, `close`, `established`, `binding`), `context` (`make_engine`), the `backend` concept, `backend_ops`, `none` (no TLS: non-loopback endpoints then need `insecure_lan`) |
| `openssl.hpp` | `openssl` — the system's OpenSSL ≥ 3.0 (desktop, when CMake finds it) |
| `mbedtls.hpp` | `mbedtls` — Mbed TLS 4.2 (mobile, and the fallback without OpenSSL) |
| `p256.hpp` | internal: `detail::p256_public_from_private`, `p256_sign`, `p256_verify` (ECDSA P-256 with SHA-256, raw `r || s`) and `p256_backend()`, for `security::key_handle`; plain bytes in and out, no backend types |
| `auto_backend.hpp` | `auto_backend`: OpenSSL where built, else Mbed TLS, else `none` (`config<>::tls<>`'s default) |

```cpp
using cfg = Rhp::config<>::tls<Rhp::security::tls::mbedtls>;   // pick one, or keep auto_backend
Rhp::host_options o;
o.tls.cert_pem = read("host.pem");                               // default: ephemeral self-signed
o.tls.key_pem = read("host.key");
Rhp::client_options c;
c.tls.ca_pem = read("ca.pem");                                  // default: no certificate check —
c.tls.server_name = "game.lan";                                 // the PSK handshake is bound to the channel
```

## Rules

- Engines never touch sockets: ciphertext in, ciphertext and plaintext out (`session::tls_client` / `tls_server` drive them over any link).
- TLS 1.3 only; no session tickets (a reconnect resumes RHP's session, not TLS's).
- A client's `server_name` is a DNS name (checked against the certificate's DNS names and sent as SNI) or an IP address in text (checked against its IP addresses; OpenSSL sends no SNI for it, Mbed TLS can't leave it out).
- `binding()` is RFC 9266 tls-exporter (`"EXPORTER-Channel-Binding"`, 32 bytes, empty context); authenticators mix it into their proofs.
- OpenSSL / Mbed TLS headers only in `openssl.cpp` / `mbedtls.cpp`. Every Mbed TLS call takes one process-wide lock (its PSA core isn't thread-safe in the default configuration).
- A backend this build doesn't have still links: its factories report `kDisabled` (`unavailable.cpp`). `RHP_TLS_HAS_OPENSSL` / `RHP_TLS_HAS_MBEDTLS` say which exist.
- P-256 for key handles runs on the backend `auto_backend` would pick: OpenSSL's `EVP` (keys built with `EVP_PKEY_fromdata`, DER signatures converted to `r || s`) where it is built, else Mbed TLS's PSA (volatile keys, imported per call, under the same lock); with neither (and with `RHP_ENABLE=OFF`) `unavailable.cpp` reports `kDisabled`. `Rhp::security` links `Rhp::tls` privately for it, so `security/tls` comes before `security` in the layer order.
