# release — layer 4

Signed releases that a program keeps and brings back after a restart (Stage 10). Namespace `Rhp::release`. Target `Rhp::release`; depends on `script`, `security`, `wire`, `platform` and `core`. Usage: [releases guide](../../../Docs/guide/releases.md); decisions: [Stage 10](../../../Docs/decisions/stage10-releases.md).

| Header | What |
|---|---|
| `manifest.hpp` | `manifest` (the signed part: channel, seq, label, app, builds, platforms, validity window, `run_as`, required libs, modules, `health_policy`), `module_entry`, canonical `encode_manifest` / strict `decode_manifest`, `validate`, `release_id` (`to_hex`, `id_from_hex`, `short_id`), the signature domains and size caps |
| `release.hpp` | `release` (manifest + sources + signatures), `make_release`, `sign`, `encode_release` / `decode_release` (`.rhprel`); `revocation_list` (release ids, keys, `seq_floor`s), `signed_revocations`, `make_revocations`, `encode_revocations` / `decode_revocations` (`.rhprev`) |
| `root_of_trust.hpp` | the root of trust (decision AL12): `root_document` (version, expiry, keys by id with their algorithm and channels, the `root` / `release` / `revocation` / `operator_ca` roles with thresholds, compromised ids), `signed_root`, canonical `encode_root_document` / strict `decode_root_document`, `make_root`, `sign`, `encode_root` / `decode_root` (`.rhproot`), `verify_root` (an anchor), `verify_next_root`, `verify_chain` (several versions; expiry), `role_trust`, `role_public_keys`, `compromised_keys`, `trusted_keys`, `signed_only_by` |
| `trust.hpp` | `trust`: release signer keys with channel patterns and a threshold (`add`, `parse`, `from_file`, `set_threshold`, `verify`); `channel_matches` (`Rhp::name_matches`, shared with capability scopes) |
| `store.hpp` | the `storage` concept (`read`, `write`, `remove`, `keys`), `any_store`, `memory_store`, `directory_store` |
| `bytecode.hpp` | the compiled-chunk cache's entries (`bytecode/<hex id>` beside the envelope): `compiled_release`, `compiled_module`, `seal_compiled` / `open_compiled` (keyed BLAKE2b-256 MAC, `kBytecodeMacDomain`), `compiled_build`, `compiled_store_key` |
| `manager.hpp` | `manager`: channels (sandboxes it owns), `install<L>`, `restore`, `apply` (`confirm_mode` `kNow` / `kHealth` / `kManual`), `confirm`, `deactivate`, `revoke`, `harden`, `status`, `pump`, `on_event`; `manager_options`, `channel_status`, `apply_result`, `restore_report`, `release_event`; `manager_options::bytecode_key` and `bytecode_cache_stats()` (the compiled-chunk cache) |

```cpp
Rhp::release::manager releases{*Rhp::release::trust::from_file("rhp_release_signers.pub"),
                               {.app = "mygame", .build = "1.4.2"},
                               Rhp::release::directory_store{"save/releases"}};
(void)releases.install<game_lib>();
(void)releases.restore();          // what ran before the restart runs again
(void)host.serve(releases);        // clients apply / confirm / deactivate (admin), read status and revoke (observe);
while (running) { host.pump(); }   // host.pump() pumps the manager; changes are release_changed host events
```

Clients reach it through `client.release_apply` / `release_confirm` / `release_deactivate` / `release_status` / `revoke`, `fleet.rollout` (staged, `client/rollout.hpp`) and `rhp-cli release` / `revoke` / `rollout`.

## Rules

- The manifest encoding is canonical: a field added to `manifest` must be added to `manifest_value` and `manifest_from` (`manifest.cpp`) at a fixed position, and changes every existing release id. Envelope fields may be added freely (decoding ignores unknown keys).
- Everything a manager runs goes through `manager_impl::check` (revoked ids and seq floors, trust and threshold, app / build / platform, validity window with `clock_skew`, `max_role`, required libs) — on apply and on every restore. Never run a stored envelope without it.
- The store is written envelope first, state second; garbage collection only removes envelopes no channel names (with their `bytecode/` cache entries). The state is checksummed against torn writes, not against someone who can write the store.
- A change (apply, confirm, deactivate) needs the last state saved: while a save keeps failing they fail too (`pump()` retries). A revocation list takes effect even when it can't be saved.
- A channel's floor only rises. Rolling back, deactivating and quarantining never lower it. Revocations only add up.
- Seqs only move so far at once (AL9, `manager_impl::check_move`): a release's at most `max_seq_jump` past its channel's floor, a revocation list's past the last list's, a floor a list raises past the highest seq its channel has seen; where nothing was seen yet (a channel's first release or floor, a host's first list), past the host's clock in Unix seconds. Counters and Unix-time seqs pass; a seq near 2^63 from one stolen key doesn't. A move past the cap is refused (`kOutOfRange`, a `kRefused` event; a list then applies nothing), never cut down, and nothing refused is kept, so a wrong clock only delays a first seq. Restores take the stored state and lists as they are, even past the caps (an older build may have accepted them): lowering them would undo revocations, refusing them would leave the store unusable.
- A swap has no gap: modules reload in place, and a failure leaves the old release running. A candidate that keeps failing to be confirmed across restarts (`max_boot_attempts`) is quarantined.
- Channels run at `manager_options::hardening` (decisions AL2, AL4; the build's `RHP_HARDENING` is a floor), as a host's identities do: admin's full standard library only at `kDev`, observe channels capped by `kObserveCaps` above it, every channel by `kProductionCaps` at `kProduction` (`make_box`). `harden` only raises it and moves running channels into sandboxes made at the new level (one that can't load there stops, with a `kRolledBack` event); `host.serve` calls it with the host's level.
- The manager is single-threaded (the pump thread), refused from a channel's own scripts, and not moved while a host serves it. Its sandboxes follow the sandbox rules. `host.serve` pumps it and answers the wire ops on the host's pump thread.
- Cached bytecode (`manager_options::bytecode_key`) is read only after its MAC checks out under the host's key, and only for a release that just passed `check`; it is bound to the release id, each module's hash and `compiled_build()`. Any mismatch discards the entry and parses the sources (`bytecode_cache_stats`). No key: nothing is written or read. Never load bytecode that came over the wire ([decision](../../../Docs/decisions/compiled-chunk-cache.md)).
- `detail/` is private to this folder: `codec.hpp` (strict MessagePack readers, store key prefixes, the signed message), `state.hpp` (the manager's state document), `compiled_cache.hpp` (the manager's compiled-chunk cache). With `RHP_ENABLE=OFF` manifests, the store and trust still build; making, checking and running releases report `kDisabled` (`release_disabled.cpp`).
