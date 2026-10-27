# release — layer 4

Signed releases that a program keeps and brings back after a restart (Stage 10). Namespace `Rhp::release`. Target `Rhp::release`; depends on `script`, `security`, `wire`, `platform` and `core`. Usage: [releases guide](../../../Docs/guide/releases.md); decisions: [Stage 10](../../../Docs/decisions/stage10-releases.md).

| Header | What |
|---|---|
| `manifest.hpp` | `manifest` (the signed part: channel, seq, label, app, builds, platforms, validity window, `run_as`, required libs, modules, `health_policy`), `module_entry`, canonical `encode_manifest` / strict `decode_manifest`, `validate`, `release_id` (`to_hex`, `id_from_hex`, `short_id`), the signature domains and size caps |
| `release.hpp` | `release` (manifest + sources + signatures), `make_release`, `sign`, `encode_release` / `decode_release` (`.rhprel`); `revocation_list` (release ids, keys, `seq_floor`s), `signed_revocations`, `make_revocations`, `encode_revocations` / `decode_revocations` (`.rhprev`) |
| `trust.hpp` | `trust`: release signer keys with channel patterns and a threshold (`add`, `parse`, `from_file`, `set_threshold`, `verify`); `channel_matches` |
| `store.hpp` | the `storage` concept (`read`, `write`, `remove`, `keys`), `any_store`, `memory_store`, `directory_store` |
| `bytecode.hpp` | the compiled-chunk cache's entries (`bytecode/<hex id>` beside the envelope): `compiled_release`, `compiled_module`, `seal_compiled` / `open_compiled` (keyed BLAKE2b-256 MAC, `kBytecodeMacDomain`), `compiled_build`, `compiled_store_key` |
| `manager.hpp` | `manager`: channels (sandboxes it owns), `install<L>`, `restore`, `apply` (`confirm_mode` `kNow` / `kHealth` / `kManual`), `confirm`, `deactivate`, `revoke`, `status`, `pump`, `on_event`; `manager_options`, `channel_status`, `apply_result`, `restore_report`, `release_event`; `manager_options::bytecode_key` and `bytecode_cache_stats()` (the compiled-chunk cache) |

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
- A swap has no gap: modules reload in place, and a failure leaves the old release running. A candidate that keeps failing to be confirmed across restarts (`max_boot_attempts`) is quarantined.
- The manager is single-threaded (the pump thread), refused from a channel's own scripts, and not moved while a host serves it. Its sandboxes follow the sandbox rules. `host.serve` pumps it and answers the wire ops on the host's pump thread.
- Cached bytecode (`manager_options::bytecode_key`) is read only after its MAC checks out under the host's key, and only for a release that just passed `check`; it is bound to the release id, each module's hash and `compiled_build()`. Any mismatch discards the entry and parses the sources (`bytecode_cache_stats`). No key: nothing is written or read. Never load bytecode that came over the wire ([decision](../../../Docs/decisions/compiled-chunk-cache.md)).
- `detail/` is private to this folder: `codec.hpp` (strict MessagePack readers, store key prefixes, the signed message), `state.hpp` (the manager's state document), `compiled_cache.hpp` (the manager's compiled-chunk cache). With `RHP_ENABLE=OFF` manifests, the store and trust still build; making, checking and running releases report `kDisabled` (`release_disabled.cpp`).
