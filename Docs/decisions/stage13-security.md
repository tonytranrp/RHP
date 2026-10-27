# Stage 13: security for every deployment

**Status:** in progress. 13a (hardening, sandbox and network fixes, dev sessions) on branch `stage-13a-hardening`; 13b (identities, certificates, root of trust, wire revision 7) and 13c (production delivery) follow as their own PRs. ARCHITECTURE §39 (AL1–AL16).

RHP is a remote-code endpoint by design, and it is now used in four very different places: on one developer PC, against a test phone on the LAN, on internal / QA builds, and in store apps on end users' phones driven from an operator's VPS. One security posture can't fit all four: the developer wants no friction, the store app wants nothing an attacker (or the phone's owner) can turn on. Five research passes (a code audit, deployment to phones, secure update prior art, channel and authentication cryptography, the Lua sandbox and dev tooling) found confirmed bugs and structural gaps; the questionnaire of 2026-10-27 decided what to do about them. The research notes are summarized in the PR descriptions.

Threat model (decided): remote attackers (LAN, internet), stolen operator keys, malicious script authors, **and** the device owner (detect and, where the platform allows, resist tampering with the clock, the store and rollback).

## Decisions

### 13a: hardening, sandbox, network, dev

- **AL1 — three hardening levels, a build ceiling that runtime can only tighten.** `RHP_HARDENING=dev|lan|production` (CMake, default `dev` = everything, today's behavior) is written into `<rhp/build_config.hpp>` and read as `Rhp::kBuildHardening`. `config<>::hardening<Rhp::hardening::kLan>` and `host_options::hardening` may only raise it; the effective level is the strictest of the three (a config below the build's level fails to compile). What a production build doesn't allow isn't in the binary (`if constexpr` on the build level), so tampered config, intents or memory patches can't turn it back on. The name avoids `RHP_PROFILE`, which is Stage 11's profiler.
- **AL2 — what each level allows.**

  | | dev | lan | production |
  |---|---|---|---|
  | admin full standard library (io, os, package, debug) | yes | no (admin = patch libraries + admin ops) | compiled out |
  | unsigned observe code | yes | yes (observe limits forced) | compiled out |
  | remote debugger (`kDebug`) | yes | yes | compiled out |
  | `insecure_lan`, `signer<unsigned_scripts>` | yes | refused | refused / compiled out |
  | dev session (auto identity, connect file) | loopback / IPC only | refused | compiled out |
  | observe limits | as configured | capped (AL4) | capped |
  | limits for patch / admin | as configured | as configured | capped (AL4) |
  | mDNS advertise, HTTP gateway | yes | yes | advertise refused; gateway only with `http_require_binding` |
- **AL3 — the sandbox bounds what untrusted code can do.** Measured gaps closed for every level:
  - `__gc` finalizers run with Lua's hooks off (no instruction, wall or cancel check), so a script could hang the pump thread forever. Non-admin scripts get a `setmetatable` that refuses a metatable with a `__gc` field (as Luau does); `<close>` variables still work and stay limited.
  - Pattern matching and plain find run in C, where no hook fires: `lstrlib.c` is patched at configure time (exact-match sites, like `lvm.c`) so the matcher and `lmemfind` charge the run's budget and honor cancels and deadlines every few thousand steps.
  - Observe identities can't register lasting handlers (`rhp.after`, `every`, `every_frame(s)`, `on`, `spawn`): those are mutations of the host's schedule.
  - `tostring` / `%p` show an identity-keyed hash instead of a C address (no address-space layout leak to unsigned code).
  - Changes to the shared library tables (`string`, `table`, `math`, `utf8`, `coroutine`, `os`, `rhp`) and the string metatable are undone with the identity: the sandbox snapshots them when it is made and restores them when the identity reverts, so a disconnect leaves no changed builtins behind. (A read-only proxy would add a lookup to every `string.x` and method call on strings.)
- **AL4 — limits per role, and rate limits.** Observe identities get their own limits (`host_options::observe_limits`, default the config's limits). From `lan` up, observe limits are capped by `Rhp::kObserveCaps` (and `cancel_checks = kEverything`); in `production` every role is capped by `Rhp::kProductionCaps`. A cap replaces 0 (unlimited) and any larger value. New `limits` fields, per identity: `request_rate` (requests per second, token bucket), `pump_requests` (requests started per `pump()`, served round-robin across identities), `handlers` (timers, frame callbacks, subscriptions and tasks alive at once). 0 keeps today's unlimited behavior in `dev`.
- **AL5 — admission control and transport fixes.**
  - Handshakes: a per-source cap (`limits.handshakes_per_source`, IPv4 address or IPv6 /64), a first-byte deadline (`limits.first_byte_ms`) separate from the handshake deadline, the oldest idle pending connection evicted instead of a new one refused, and resumes never blocked behind stalled handshakes. `auth_failed` names the key that was tried.
  - Reliable UDP: a stateless cookie (a keyed MAC over the source address, port and a time bucket) is echoed before any peer state or handshake slot exists, so spoofed Hellos cost nothing (rudp packet revision, not the wire protocol).
  - A reverse-mode (listening) client authenticates candidates before one becomes its session, so an unauthenticated connection can't hold the slot.
  - `insecure_lan` accepts only private, link-local and loopback peers (RFC 1918, RFC 4193, link-local, CGNAT excluded); TLS is the only way past that.
  - A `server_name` is an IP address only if it parses as one (names such as `cafe1` and `db1.de` were treated as addresses and skipped the hostname check); the Python client checks host names.
- **AL6 — a hard kill switch.** `host.set_enabled(false)` refuses connections, closes every session (identities revert as on disconnect; pinned modules stay), stops reverse dialing and stops running scripts: `pump()` runs no requests, handlers, tasks or release channels until it is enabled again. The signed, persisted remote disable is 13c (AL15).
- **AL7 — dev sessions without key files.** In a `dev` build, a host listening only on loopback or local IPC can open a dev session (`host_options::dev_session`): it generates an identity and a signing key for this run, trusts that signer, and writes a connect file (endpoint, identity, signing key) owner-only into the user's config directory (`<config>/rhp/dev/<app>.rhpdev`), removed at shutdown. `rhp-cli connect --dev [app]` reads it. The same wire protocol (the PSK handshake and signatures still run); a non-loopback endpoint refuses the dev session, and any process of the same user can read the file (decided: acceptable on a dev machine). Phone pairing (QR one-time secret, a 6-digit CPace code, trust on first use, `adb forward`) is 13b, because it enrolls a device key (AL10).
- **AL8 — key files are owner-only on every OS.** Identity files are created atomically and owner-only: POSIX `O_CREAT|O_EXCL` 0600 then rename, Windows an explicit DACL for the current user (inheritance off). `std::filesystem::permissions` only toggles the read-only attribute on Windows. Loading warns when a key file is readable by others. `rhp-cli keygen` and the Python client default to the patch role (admin must be asked for), never print the PSK unless asked, and the Python client writes 0600.
- **AL9 — release state can't be fast-forwarded.** A revocation list's seq and every floor it raises may move at most `max_seq_jump` past what the host has seen, and a channel's first release is capped the same way (from the host's clock-based ceiling when it has seen nothing), so one stolen `*` key can no longer set seq or floors near 2^63 and lock out every later list. Recovery from a compromised key over the air is the root of trust (AL12).

### 13b: identities and trust (wire revision 7)

- **AL10 — device keys, hosts store only public keys.** A new authenticator: each side holds a key pair, the host an allow-list of client public keys and roles, the client the host keys it pinned (pairing or trust on first use). Both sign the handshake transcript bound to the TLS exporter (TLS required: it is certificate-free already). Ed25519 in software, ECDSA P-256 through a sign callback for hardware keys (Secure Enclave, StrongBox, TPM: the private key never enters RHP), behind a `key_store` interface with file, DPAPI and Apple Keychain built-ins and an app callback (Android Keystore). PSK identities stay for dev and LAN. Pairing: QR with a full-entropy one-time secret and on-device approval, a 6-digit code over CPace (X25519 in Monocypher, checked against the draft's vectors), trust on first use with a prompt, and `adb forward` documented.
- **AL11 — operator certificates and script claims.** Hosts trust an offline operator CA; operators carry short-lived certificates (principal, public key, validity, max role, apps, environments, capability scopes, serial; unknown critical options refuse the certificate). Every script signature carries claims (expiry, app, environment, audience, nonce) under a new signature domain, so a signed script can't be replayed elsewhere or later. Keys and certificates are tagged `env=dev|prod`; production-hardened hosts refuse dev keys. Key custody: split connection and signing files, optional passphrase encryption (Argon2 + XChaCha20-Poly1305), `rhp-cli --sign-cmd` for external signers (YubiKey, KMS, Vault), OS key stores.
- **AL12 — a root of trust.** A versioned root document, signed by an offline threshold, lists the release, revocation and operator-CA keys with roles, thresholds and expiry. Version N+1 needs thresholds of both N and N+1; keys marked compromised drop what they signed (TUF's recover step), retired keys keep it. Revocation lists also cover operator certificates (by serial), signers and device keys.
- **AL13 — capability scopes.** `lib:`, `cap:`, `patch:`, `event:` and `op:` patterns (deny wins) granted per identity (keyring column) and per operator certificate; bindings tag capabilities with `Rhp::cap<"economy.write">`. Checked when a lib is installed, a patch attached, an event subscribed and a request dispatched; a call costs one mask test.

### 13c: production delivery

- **AL14 — releases are the production path, support sessions are opt-in.** Phones pull signed release and revocation files over HTTPS with the OS network stack and hand the bytes to RHP; a signed, short-expiry channel index defeats freeze attacks (`max_staleness`). Release state is MAC'd with a platform-keystore key and can use an app-provided monotonic counter. Live sessions on store builds are support sessions: started by the user, in the foreground, time-limited, reverted at the end, through `Tools/rhp-relay` (phones and operators both dial it over `wss://` on 443; it splices streams and sees only RHP's end-to-end TLS). A `mobile` limits preset and `host.pause_network()` / `resume_network()` fit iOS and Android background rules.
- **AL15 — operations.** Hash-chained audit (sequence, previous hash, signed checkpoints, host id, app and build on every event), forwarded to operators over the session and to an app collector hook; attestation hooks (Play Integrity, Android Key Attestation, App Attest) bound to the transcript and exporter, verified by the app or VPS; a signed, persisted remote disable; hybrid ML-KEM where OpenSSL 3.5+ is used; Mbed TLS stays at 4.2 with a recorded fallback plan.
- **AL16 — store tiers.** dev (everything), store (production hardening: releases and support sessions), off (`RHP_ENABLE=OFF`). Store builds must disclose remote updates (App Store 2.5.2 / 2.5.19, DPLA 3.3.1(B); Play Device and Network Abuse, Malware, Deceptive Behavior); the guide carries the review-notes and consent pattern.

## Alternatives

- **Runtime-only profiles:** a production binary would still contain every dev feature, one config change away.
- **No authentication on loopback in dev:** any local process, or a browser through DNS rebinding, could run code (the Node `--inspect` and Chrome remote-debugging incidents).
- **A Noise channel for encryption without TLS:** TLS already works without certificates (ephemeral host certificate, RFC 9266 binding); a second channel stack is new cryptography to review and keep in step. Kept TLS-only.
- **Length caps instead of patching `lstrlib.c`:** heuristic; a short pattern can still backtrack for minutes.
- **A finalizer budget instead of refusing `__gc`:** more patching of Lua's collector for a feature scripts rarely need.

## Consequences

`dev` builds behave as before except where a confirmed hole closed for every level: no `__gc` for non-admin scripts, observe can't register handlers, changed builtins are restored on revert, pattern matching is limited, revocation and first releases are capped, key files are owner-only, keygen defaults to patch. 13b changes the wire protocol (revision 7) and the signature format.
