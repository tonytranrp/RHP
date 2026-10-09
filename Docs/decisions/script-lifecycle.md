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

**Stage 1 (as built)** — `Rhp::script::sandbox` implements exec, load, call, revert, unload, checkpoint / revert_to and revert_all locally.
- Variable writes and patch layers live in process-wide per-target stacks: undoing an older write hands its saved value to the next newer one, so modules (and sandboxes) can be reverted in any order and the target ends up as if the undone write never happened.
- A failed `exec` reverts only the effects of that run; the scratch module keeps earlier effects.
- A patch handler that errors falls back to the next layer (or the C++ default) and its module is faulted on the next `pump()`.
- Deferred to Stage 2: transactional reload (loading a loaded name returns `kAlreadyLoaded`), revisions, `on_save` / `on_restore`, `require`, `Rhp::lua_event` — all built in Stage 2 below.

**Stage 2 (as built)**
- Reload overlaps: the new revision (own `_ENV`) runs its top level and `on_load` while the old one is live, then `new.on_restore(old.on_save())`, then the old revision's effects, timers, subscriptions and suspended requests are removed. Any failure reverts only the new revision. Reverted and faulted modules can be reloaded. `load` of a loaded name reloads it.
- Ledger entries carry module, revision and request (`effect_owner`); `revert_revision`, `revert_request` and `revert_entry` revert exactly one of them.
- `rollback(mod, n)` reloads the source kept `n` revisions back, as a new revision; at most `limits.revisions` (default 8) are kept.
- `require` returns a live read-only proxy; cycles fail; `unload` needs `force` while dependents exist, after which they get `kUnloaded`.
- Lifecycle operations requested from inside a running script are queued until the outermost operation returns (they report `deferred`).
