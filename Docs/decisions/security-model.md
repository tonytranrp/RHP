# Security model

**Decision**
- Loopback / IPC by default.
- Non-loopback requires a keyring **and** TLS (OpenSSL on desktop, mbedTLS on mobile) or an explicit `insecure_lan` opt-in.
- PSK mutual challenge-response with keyed BLAKE2b (Monocypher ≥ 4.0.3); each key → identity → role (`kObserve`, `kPatch`, `kAdmin`).
- All code is Ed25519-signed, except `kObserve`, which may run unsigned code because it can't mutate.
- Sandbox: string, table, math, utf8, coroutine, `os.time` / `os.clock`. `kAdmin` gets the full standard library (io, os, `package.loadlib`, debug).
- Audit event with a BLAKE2b-256 hash.
- At most 64 pending unauthenticated handshakes, 5 s timeout.
- Kill switches: compile-time `RHP_ENABLE=OFF` + runtime `set_enabled(false)`.
- mDNS advertises host, platform, protocol_rev and app + build id; lib names only when the host opts in.

**Why:** RHP is a remote-code-execution endpoint by design, so the defaults must be the safe ones and anything weaker must be typed explicitly.

**Alternatives:** HMAC-SHA256 (Monocypher has no SHA-256), mTLS (painful certificate provisioning on mobile), our own channel crypto (rejected — use TLS).

**Consequences:**
- An admin key is fully trusted.
- iOS store builds should compile RHP out.
