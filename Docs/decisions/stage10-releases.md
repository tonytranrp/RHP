# Stage 10: release manifests, persistence and rollout

**Status:** implemented (branch `stage-10-releases`). ARCHITECTURE §36 (AI1–AI10). Usage: [Releases](../guide/releases.md).

Until Stage 9 every change a client made lived as long as its session (pinned modules aside): a restart lost it, and nothing stopped an old script from replacing a newer one. Stage 10 adds a second way to ship Lua: a signed release that a host keeps.

## Decisions

- **AI1 — a release is a signed manifest plus sources.** The manifest (channel, seq, label, app / builds / platforms, validity window, role, libs, modules with BLAKE2b-256 source hashes, health policy) is canonical MessagePack: fixed field order, sorted sets, minimal integers, strict decode that re-encodes and compares. One manifest has one byte string, so a signature can't be re-wrapped into another meaning and the BLAKE2b-256 of the body is the release's id. The envelope around it (sources, signatures, an optional revocation list) is lenient and unsigned: sources are bound by their hashes.
- **AI2 — separate signing domains and keys.** Release bodies are signed over `"rhp/release\0" || body`, revocation lists over `"rhp/revocation\0" || body`, scripts over their own domain, so no signature transfers between them. Release keys come from their own trust list with channel patterns (`game.*`); revocation lists need keys trusted for `*`; a threshold counts distinct keys.
- **AI3 — channels are the manager's sandboxes.** A channel runs one release at a time in a sandbox the manager owns, with the release's role (`patch` by default, `admin` only up to `manager_options::max_role`), independent of identities and sessions: a release survives every disconnect. The manager is usable without a host (`apply`, `pump`); `host.serve(manager)` adds the wire ops and pumps it.
- **AI4 — the checks, in order.** Envelope and canonical body; signatures (threshold, channel, revoked keys); revoked or quarantined id; app / build / platform scope; validity window with skew; seq above the channel's floor and within `max_seq_jump`; role; libs; source hashes. Each failure has its own code (`kBadSignature`, `kRevoked`, `kOutOfScope`, `kExpired`, `kSuperseded`, `kOutOfRange`, `kForbidden`, `kNotFound`, `kIntegrity`); four new `errc` values joined at the end of the enum.
- **AI5 — anti-rollback.** Each channel has a seq floor that only rises: on every accepted release, from revocation lists. A rolled-back or deactivated release can't come back; the fix is a new release with a higher seq. `rhp-cli release build --seq auto` uses the Unix time.
- **AI6 — swap in place, fail closed.** Modules load in manifest order into the running sandbox: same-name modules reload (state carries through `on_save` / `on_restore`), new ones load, dropped ones unload afterwards. Any failure (an error, a top level that suspends) undoes what changed (rollback / forced unload) and the old release keeps running. A role change builds a fresh sandbox that replaces the old one only after it loaded.
- **AI7 — candidates and health.** `confirm_mode::kNow` activates at once (the previous release is kept as the fallback); `kHealth` runs a candidate watched for `health_window` (module faults, handler failures over the manifest's allowance, the manifest's fail events) and confirms it after a quiet window; `kManual` waits for `confirm()`. Rolling back runs the fallback, never lowers the floor.
- **AI8 — persistence.** The store holds the state (per channel: floor, active / previous / candidate ids, confirm mode, boot attempts, held, quarantined ids; the revocation seq), checksummed with BLAKE2b-256, and the envelopes the state names (garbage-collected otherwise). The envelope is written before the state names it. `restore()` re-verifies everything it loads. A candidate's boot attempt is counted before it loads, so a candidate that crashes the program on load is quarantined after `max_boot_attempts` restarts. `directory_store` writes through `platform::replace_file` (temporary file, flushed to the device, renamed over, directory synced on POSIX).
- **AI9 — revocation lists.** Cumulative, monotonic seq, signed; they revoke ids and keys and raise floors. A running release that is revoked, or whose only valid signers were revoked, falls back. Any identity may send one (it carries its own signatures); a release envelope may carry one to apply first.
- **AI10 — rollout is a client algorithm.** `Rhp::fleet::rollout` applies to canaries then cumulative fractions (members ordered by a hash of the release id and the host, so the same hosts go first for one release), health-watched, observes each stage by polling `kReleaseStatus`, confirms, and on more than `max_failures` failures deactivates the release where it still runs. The fleet reads only the envelope's channel and id (the client doesn't link the script engine); hosts do every check.

## Wire

Protocol revision 5: `kReleaseApply` (admin) `{envelope, confirm}` → `release_apply_reply`; `kReleaseConfirm` / `kReleaseDeactivate` (admin) `{channel, hold}`; `kReleaseStatus` (observe) → `release_status_reply` (app, build, platform, revocation seq, channels); `kRevoke` (observe) `{envelope}` → channels changed. Host event `release_changed` (applied, confirmed, rolled_back, refused, revocations) reaches audit sinks.

## Alternatives

- **Releases as pinned modules of an identity:** reuses Stage 4's pinning, but ties a release to whoever applied it and gives it that identity's role; channels are clearer.
- **The host keeping releases itself (no manager object):** simpler wiring, but a standalone sandbox user (no network) couldn't use releases, and tests would need a host for every case.
- **A server-side rollout (hosts coordinating):** needs host-to-host trust; a client that already holds admin keys can drive it with the existing wire.
- **TUF-style role delegation:** more than a game-tooling library needs today; channel patterns, thresholds and revocation lists cover the common cases.

## Consequences

`Rhp::release` (layer 4) depends on script, security, wire and platform; the host links it. The client doesn't (it parses only what rollout needs). `platform/files.hpp` is the one place file durability is OS-specific. With `RHP_ENABLE=OFF` manifests still encode and decode, everything else reports `kDisabled`. Not done: release ops on the HTTP gateway, the Python client's release calls, delta updates.
