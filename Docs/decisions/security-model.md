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

**Stage 4 (as built)**
- Script signing: `config<>::signer<S>` (concept `Rhp::security::signer`), default `Rhp::security::ed25519` — standard RFC 8032 Ed25519 from Monocypher's optional file, over `"rhp/script\0" ‖ source`, sent as `{signer, sig}`. The host checks `exec` / `load` / `reload` against its `trusted_signers` before running anything; observe sessions may send unsigned code, but a signature that is present must verify for every role. `Rhp::security::unsigned_scripts` is the typed opt-out.
- Files: identity file (`name`, `psk`, `signing_key`, optional `signer`), keyring file (`name role base64-psk`), trusted-signers file (`name base64-public-key`); `rhp-cli keygen` writes the first and prints lines for the other two. Secrets are wiped.
- Audit: `host.on<E>()` / `on_any()` and `Rhp::audit::file_sink` — every request that runs code or changes state (with its BLAKE2b-256 source hash, signer and outcome), sessions, failed handshakes, blobs and reverts, as JSON lines.
- Blobs are admin-only unless a sink says otherwise (`host.on_blob(name, fn, role)`); the role is checked before a byte is buffered.
- `host.set_enabled(false)` is the runtime kill switch: new connections closed, requests `kDisabled`.
- `pin` (admin) keeps a module after its identity disconnects; `revert_all` still removes it; `revert` / `unload` / `revert_to` can't touch it until unpinned.
- `rhp-cli keygen` writes identity files owner-only (0600 on POSIX).
- Unsigned observe code can't mutate anything, but under the default (unlimited) limits it can still hold the pump thread or grow memory until cancelled: a host that hands observe keys to people it doesn't trust should set `limits` (`instructions`, `wall_ms`, `memory`).

**Stage 5 (as built)**
- TLS 1.3 on non-loopback endpoints (and wherever `Rhp::net::require_tls` asks), OpenSSL or Mbed TLS behind `config<>::tls<>`.
- The PSK transcript ends with the TLS connection's tls-exporter value (RFC 9266): a relay that terminates TLS on both sides fails the handshake, so the host's certificate can be ephemeral and self-signed. `client_options::tls.ca_pem` (+ `server_name`) adds certificate checks; `host_options::tls.cert_pem` / `key_pem` set the host's certificate.
- Plaintext reaches a host only from loopback peers, local transports or an endpoint that says `insecure_lan`; `require_tls` refuses it everywhere.
- A resume request is sealed with the session's MAC key and a control counter (replaying one is refused, nothing secret crosses the wire), and both resume frames prove the new connection's channel binding: a relay terminating TLS on the redial can't take a session over.
- Known limits: idle unauthenticated connections count against `pending_handshakes` and can delay a resume; a probe can tell a known session id from an unknown one.

**Stages 6–7 (as built)**
- HTTP gateway: per-request keyed-BLAKE2b proofs (±30 s, one use, per-key replay quota), answer proofs (`X-RHP-Proof`) and opt-in RFC 9266 channel binding (`X-RHP-Channel`, `host_options::http_require_binding`) — see [Stage 6 networking](stage6-networking.md).
- Remote event subscription (`kSubscribe`) needs only observe and covers every C++ `lua_event` in the process (script events only within the subscriber's identity): keep secrets out of C++ event arguments, or don't hand out keys to untrusted readers ([Stage 7](stage7-scheduling-events.md)).

**Stage 13a (as built)** — decisions AL1–AL9 in [Stage 13](stage13-security.md); 13b (AL10–AL13) is below, 13c (AL14–AL16) is planned.
- Hardening levels: `RHP_HARDENING=dev|lan|production` (default `dev`) is written into `<rhp/build_config.hpp>` and read as `Rhp::kBuildHardening` (`core/hardening.hpp`); `config<>::hardening<H>` (a weaker `H` doesn't compile) and `host_options::hardening` only raise it, and the host runs at the strictest of the three. What the build's level doesn't allow is left out with `if constexpr`: admin's full standard library and dev sessions outside `dev` builds, unsigned observe code and the debugger op in `production` builds. A `host<Cfg>` with `signer<unsigned_scripts>` needs hardening `dev` (`Rhp::host_configuration`).
- Above `dev`: `insecure_lan` endpoints (host, gateway, client) and dev sessions are refused, `unsigned_scripts` doesn't start, admin sandboxes get patch's libraries (`sandbox_options::admin_stdlib`; admin release channels too, at the level of the host that serves them), observe identities run under `host_options::observe_limits` (default: the config's) capped by `kObserveCaps` (2,000,000 instructions, 64 MiB, 20 ms, `kEverything`, a cancel check at least every 10,000 instructions, 1024 queued events, 10 requests a second, 2 a pump). At `production` also: observe code must be signed, `kDebug` and `advertise()` are refused, the HTTP gateway needs `http_require_binding`, and every identity's limits are capped by `kProductionCaps` (512 MiB, 1000 ms, `kEverything`, a cancel check at least every 10,000 instructions, 65,536 queued events). A refused start is `kForbidden` from `port()`, a refused gateway from `gateway_port()`.
- The sandbox, at every level: non-admin `setmetatable` refuses a metatable with `__gc` (finalizers run with Lua's hooks off); `lstrlib.c` is patched so pattern matching and plain find charge their steps to the run (limits, cancels and deadlines reach them); observe can't register timers, frame callbacks, subscriptions or tasks; `tostring` / `%p` show a SipHash-2-4 of the address under a per-sandbox key; changes to the shared library tables and the string metatable are undone by `revert_all`.
- Limits per identity: `limits.request_rate` (a token bucket on the host's clock, `kLimitExceeded` / HTTP 429), `pump_requests` (requests started per identity per pump, identities in turn) and `handlers` (timers, frame callbacks, subscriptions and tasks alive at once); 0 keeps them off.
- Admission (`session::admission`, shared by a host's listener and gateway; a listening client has its own): `pending_handshakes` at once, `handshakes_per_source` (8) from one IPv4 address or IPv6 /64, a `first_byte_ms` (2 s) deadline, and a newcomer takes the slot of the oldest silent connection, else of the oldest still unauthenticated after a quarter of `handshake_timeout_ms`, so silent or stalled connections can't hold out a client or a resume. `auth_failed` carries the key name tried. A listening client authenticates candidates side by side. Reliable UDP answers a first Hello with a stateless cookie (rudp packet revision 2), so spoofed sources get no state.
- `insecure_lan` speaks plaintext only with loopback, private (RFC 1918, RFC 4193) and link-local peers (`net::ip_address::is_local` from `link::address()`); CGNAT and links without an address don't count. A `server_name` is an IP address only if it parses as one. The Python client checks host names against its CA's certificate.
- `set_enabled(false)` is a hard kill switch: every session closed (identities revert, pinned modules stay), connections refused, reverse dialing stopped, and `pump()` runs no requests, handlers, tasks or release channels until it is enabled again.
- Key files: identity and dev session files are written atomically and owner-only on every OS (`platform::write_private_file`: POSIX `O_EXCL` 0600 then rename, Windows an explicit DACL for the current user); loading warns (`warnings`) when other users can read one or a PSK looks chosen by a person, and `keyring::warnings()` when a keyring file is readable by others. `rhp-cli keygen` and the Python client default to the patch role and keep the PSK out of their output unless asked (`--show-secret`; `rhp-cli pubkey` prints it).
- Dev sessions (`host_options::dev_session`): in a `dev` build at hardening `dev`, a host listening on loopback or local IPC adds a generated admin PSK identity and Ed25519 signer (`dev-session`) and writes `<config>/rhp/dev/<app>.rhpdev` owner-only for `rhp-cli connect --dev`; the file goes with the host. Any process of the same user can read it (decided: acceptable on a dev machine).
- Releases (AL9): a seq may move at most `manager_options::max_seq_jump` (2^32) past what the host has seen (its clock in Unix seconds where it has seen nothing), for releases, revocation lists and the floors a list raises; one stolen `*` key can no longer lock out every later list.
- Known limits: connections that have sent something hold their slots until `handshake_timeout_ms`; caps bound one identity, not the host (an observe identity under `kObserveCaps` can take 40 ms of a pump and 200 ms of a second); a dev session file is readable by the same user's processes.

**Stage 13b (as built)** — decisions AL10–AL13 in [Stage 13](stage13-security.md), formats there too.
- Keys: `key_handle` signs with Ed25519 or P-256 (ECDSA with SHA-256, raw r||s; P-256 through the TLS backend, `kDisabled` without one), in software or through an app callback, so hardware keys never enter RHP; `key_store`: owner-only files (optionally sealed: Argon2i, 64 MiB and 3 passes by default, then XChaCha20-Poly1305), DPAPI, Apple Keychain (not run on a device yet), callbacks. `rhp-cli keygen` writes the connection identity (`.rhpid`) and the signing key (`.rhpsign`) apart, both tagged `env=dev|prod`; combined files from before still load.
- `env=` tags: at effective hardening `production` a host copies its keyring, device allow-list and trusted signers without the `env=dev` entries, once, in its constructor (`without`); `certified` refuses dev-tagged CAs and certificates there.
- Device keys (`security::device_keys`): each side signs the transcript (both keys, both nonces, the TLS channel binding), so TLS is required and a TLS-terminating relay fails; an unlisted or revoked client key is challenged like a listed one and fails at verify. Clients pin host keys per endpoint (`known_hosts`); a changed key is refused, an unknown one only with a trust-on-first-use callback (`rhp-cli`: asked on a terminal, `--trust-new-host`).
- Operator certificates (`security::certified`): an offline CA signs `{serial, principal, alg, pub, validity, max_role, apps, envs, scopes, critical}`; every script signature carries claims `{not_after, app, env, audience, nonce, identity}` checked against `host_options::app` / `env` / `host_id` and the session (a nonce is accepted once); the audit's signer is `principal#serial`.
- Root of trust (`release::root_of_trust`, held by `release::manager`): threshold-signed versions naming the release, revocation and operator-CA keys; walks need the previous and the new root thresholds; compromised keys' lists are dropped and what they raised undone; identity revocation lists withdraw certificate serials, signer keys and device keys (`manager.identities()`, thread-safe); `kTrust` (op 44) delivers both and needs only observe.
- Capability scopes (`Rhp::scope_set`): `lib:` / `cap:` / `patch:` / `event:` / `op:` patterns per identity and per certificate; certificate scopes narrow the request they sign (`sandbox::narrow`), a narrowed exec can't register handlers, and a certificate that denies a lib the identity has is refused rather than hiding it.
- Known limits: pairing isn't wired into hosts; `--sign-cmd` is open; the Python client, `rhp-cli fleet` and `rollout` are PSK-only.
