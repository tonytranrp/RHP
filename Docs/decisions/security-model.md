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

**Stage 3 (as built)**
- Monocypher 4.0.3 arrives in Stage 3 (it was planned for Stage 4) because PSK authentication needs keyed BLAKE2b. It is compiled as C++ through one wrapper translation unit, like Lua.
- `psk_keyring` (default `config<>::auth<>`): hello `{key, Nc}` → challenge `{Nh, MAC(psk, "rhp/host" ‖ T)}` → response `{MAC(psk, "rhp/client" ‖ T)}` with T = name ‖ Nc ‖ Nh; the client checks the host's proof before proving anything (mutual). Frame keys: `MAC(psk, "rhp/c2h" ‖ T)` and `MAC(psk, "rhp/h2c" ‖ T)` — fresh per session, one per direction, so frames can't be replayed into another session or reflected. Comparisons are constant time; secrets are wiped.
- An unknown key name gets an ordinary-looking challenge (made with a random secret): key names can't be probed.
- Keys: 16–64 bytes, base64 text, from env, file or `key::generate()` (32 bytes from the OS RNG in `Rhp::platform`).
- Roles: the host checks each request's minimum role (`wire::required_role`) before running it; bindings check theirs inside Lua. `revert_all` over the network is the admin panic button for every identity.
- Unsigned scripts run in Stage 3 (signing is Stage 4). Non-loopback TCP needs `insecure_lan` until TLS (Stage 5).
- At most `limits.pending_handshakes` (64) unauthenticated connections; more are closed at once; `handshake_timeout_ms` (5 s) closes slow ones.
