# release — layer 4

Signed releases that a program keeps (Stage 10). Namespace `Rhp::release`. Usage: [Docs/guide/releases.md](../../../Docs/guide/releases.md); decisions: [Docs/decisions/stage10-releases.md](../../../Docs/decisions/stage10-releases.md).

| Header | What |
|---|---|
| `manifest.hpp` | `manifest` (the signed part), `module_entry`, `health_policy`, canonical `encode_manifest` / strict `decode_manifest`, `validate`, release ids |
| `release.hpp` | `release` (manifest + sources + signatures), `make_release`, `sign`, envelopes; `revocation_list`, `signed_revocations` |
| `trust.hpp` | `trust`: release signer keys with channel patterns and a threshold; `channel_matches` |
| `store.hpp` | the `storage` concept, `any_store`, `memory_store`, `directory_store` |
| `manager.hpp` | `manager`: channels (sandboxes it owns), apply / confirm / deactivate / revoke / restore / pump, status and events |

## Rules

- The manifest encoding is canonical: a field added to `manifest` must be added to `manifest_value` and `manifest_from` at a fixed position, and changes every existing release id. Envelope fields may be added freely (decoding ignores unknown keys).
- Everything a host loads goes through `manager_impl::check` — on apply and on every restore. Never run a stored envelope without it.
- The store is written envelope first, state second; garbage collection only removes envelopes no channel names.
- A channel's floor only rises. Rolling back, deactivating and quarantining never lower it.
- The manager is single-threaded (the pump thread); its sandboxes follow the sandbox rules. `host.serve` pumps it and answers the wire ops on the host's pump thread.
- `detail/codec.hpp` is private to this folder.
