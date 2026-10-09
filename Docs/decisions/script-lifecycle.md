# Script lifecycle and revert

**Decision**
- Ops: `exec`, `load`, `call`, `reload`, `rollback`, `checkpoint` / `revert_to`, `revert`, `unload`, `pin` / `unpin`, `revert_all`, `cancel`, `list` / `status` / `describe`, `blob`.
- Every mutation goes through an **owner-keyed undo ledger**; revert walks it in reverse sequence order.
- `exec` effects are kept, owned by one scratch module per identity.
- Faults auto-revert and leave the module in `Faulted`.
- Revisions: per-module counter (default 8 kept, configurable) with the content hash shown in `status`; `on_save` / `on_restore` carry state across reloads.
- Disconnect reverts the identity's modules (after the heartbeat window); `pin(mod)` hands a module to the host so it survives.
- Module names are dotted lowercase; chunk names are `@module_name`.
- `require` resolves only to loaded modules of the same identity; unloading a required module needs `force`.

**Why:** the same owner-keyed cleanup pattern as GMod `hook.Add` ids, Neovim augroups and Roblox Maid/Trove — proven for hot reload.

**Alternatives:** full state restart on every change (simple, but loses all live tuning); no revert (rejected — the core promise of RHP).

**Consequences**
- Irreversible bindings must be marked `Rhp::irreversible` and are reported in revert results.
- Unmarked bindings are treated as pure.
