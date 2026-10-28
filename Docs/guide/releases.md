# Releases: signed, persistent, rolled out

`exec`, `load` and `reload` change a running program for as long as the session that sent them lives. A **release** is for changes that should stay: a signed bundle of Lua modules that a host keeps across restarts, checks against what it is (app, build, platform), refuses to roll back past, and can confirm only after it has watched it run. A fleet can spread one over many hosts stage by stage and pull it back if a stage goes wrong.

```text
 developer                       host (Rhp::release::manager)
 ┌────────────────────────┐      ┌───────────────────────────────────────────────┐
 │ rhp-cli release build  │      │ channel "game.balance": one sandbox            │
 │  manifest + sources    │ ───▶ │   checks: signers, channel, app/build/platform,│
 │  signed (Ed25519)      │      │           validity window, seq floor, libs     │
 │ rhp-cli rollout        │      │   runs it: active, or a watched candidate      │
 └────────────────────────┘      │   keeps it: the store (survives restarts)      │
                                 └───────────────────────────────────────────────┘
```

## The pieces

| | What it is |
|---|---|
| **channel** | A named slot (`game.balance`, dotted lowercase) that runs at most one release at a time, in a sandbox of its own that the manager owns (not an identity's). |
| **manifest** | The signed part: channel, `seq`, label, the app / builds / platforms it is meant for, a validity window, the role its sandbox runs as (`patch` or `admin`), the libs it needs, its modules (name + BLAKE2b-256 of the source) and its health policy. Canonical MessagePack: one manifest, one byte string, so its hash is its id. |
| **envelope** (`.rhprel`) | The manifest's bytes, the module sources, the signatures, and optionally a revocation list to apply first. |
| **revocation list** (`.rhprev`) | Release ids and signing keys to stop trusting, and channel floors at or below which every release is revoked. A host adds each list it accepts (higher `seq`) to what it revoked already: nothing a list revoked comes back. |
| **trust** | The keys that may sign releases (separate from script signers), each limited to channel patterns (`game.*`, `*`), with a threshold of distinct signers. Either a file the app ships, or the release role of a root of trust. |
| **root of trust** (`.rhproot`) | Optional, Stage 13b: a versioned document signed by a threshold of offline root keys that names the release, revocation and operator-CA keys. The app embeds one version as its anchor; newer versions reach a host over the wire ([below](#root-of-trust)). |
| **identity revocation list** (`.rhpidrev`) | Optional, Stage 13b: operator certificate serials, script signer keys and device keys to stop trusting, signed by the root's revocation role. |
| **store** | Where a manager keeps its state (`state`), every revocation list it accepted (`revocations/<seq>`), the envelopes it may run again (`releases/<id>`), the root versions and identity revocation lists it accepted (`trust/root/<version>`, `trust/identities/<seq>`) and, with a bytecode key, their compiled chunks (`bytecode/<id>`): `memory_store` or `directory_store` (one file per key, written through a synced rename). Anything that models `Rhp::release::storage` works. |

## Running releases in C++

```cpp
#include <rhp/rhp.hpp>

Rhp::release::manager_options options;
options.app = "mygame";
options.build = "1.4.2";
Rhp::release::manager releases{*Rhp::release::trust::from_file("rhp_release_signers.pub"), options,
                               Rhp::release::directory_store{"save/releases"}};
releases.install<game_lib>();                  // every channel gets the libs you install
auto restored = releases.restore();            // brings back what ran before the restart
host.serve(releases);                          // clients may now apply / inspect releases; host.pump() pumps it
```

`restore()` reads the store before anything changes. If you don't call it, the first `apply`, `confirm`, `deactivate` or `revoke` does. While the store can't be read (or its state fails its checksum) those calls fail too and the store is left as it is: fix the store (or move it away) and the next call restores. The report lists the channels that run again (`restored`), releases given up on (`failed`: revoked, expired, no longer in scope, missing from the store, failing to load), channels that run nothing this time but keep their releases (`deferred`: an unreadable file, a lib installed after `restore()`, a clock outside the validity window, a load that ran out of time or memory, a candidate whose boot attempt couldn't be saved; tried again at the next start) and quarantined candidates.

A host that serves a manager (`host.serve`) shows no channels in `release_status` until something restores it: call `restore()` before serving (as `headless_server` does) so a restart brings the releases back at once. The manager is single-threaded (the pump thread). A host keeps a reference to the manager it serves, so don't move a served manager. `on_event` returns a subscription; any number of listeners may subscribe (the host is one).

Without a host, call `releases.pump()` every frame and `releases.apply(envelope)` yourself (a release file shipped with an update, downloaded at startup).

From a client (an admin identity) the same operations go over the wire:

```cpp
std::vector<std::byte> envelope = read_file("balance.rhprel");      // your own file reading
auto applied = admin.release_apply(envelope, "health");              // "now", "health" or "manual"
if (applied) {
    std::println("{} seq {}: {}", applied->channel, applied->seq, applied->running); // "active" or "candidate"
}
auto status = admin.release_status();                                // every channel: active, candidate, floor
auto stopped = admin.release_deactivate("game.balance");             // fall back to the previous release
```

`rhp_release_signers.pub` has one key per line, the same shape as the script signers file plus optional channel patterns:

```text
# name  base64-public-key                              channels (default *)
dev     Hn1b6yX...=                                    game.*
ops     9QdK2pA...=                                    *
```

`manager_options`:

| Field | Default | Meaning |
|---|---|---|
| `app`, `build`, `platform` | empty, empty, this OS | compared with the manifest's `app`, `builds`, `platforms` (an empty manifest field accepts any) |
| `max_role` | `patch` | releases asking to run as more are refused (`kForbidden`) |
| `clock_skew` | 300 s | allowance on `not_before` / `not_after` |
| `expire_running` | true | a running release past `not_after` stops |
| `max_boot_attempts` | 2 | restarts a candidate may run through unconfirmed before it is quarantined |
| `health_window` | 60 s | a `health` candidate is confirmed after this long without a failure |
| `max_seq_jump` | 2^32 | how far a seq may move at once: a release past its channel's floor, a revocation list past the last list, a floor a list raises past the highest seq its channel has seen; where nothing was seen yet, past the host's clock in Unix seconds |
| `limits` | host-like (`wall_ms` 10 s) | the channels' sandboxes, capped for `hardening` |
| `hardening` | `dev` | the level the channels run at; the build's `RHP_HARDENING` is always the floor ([below](#hardening)) |
| `wall_clock`, `clock` | system / steady | injectable for tests |
| `output` | none | `print()` of the channels' scripts, with the channel |

## What a host checks

In order, before anything runs: the envelope decodes, its body is canonical and every source matches its hash (`kIntegrity`); the release isn't revoked and its `seq` isn't at or below a revoked floor (`kRevoked`); enough trusted, unrevoked keys signed it for its channel (`kBadSignature`); it is meant for this app, build and platform (`kOutOfScope`); now is inside its validity window (`kExpired`); its role is allowed (`kForbidden`); every lib it needs is installed (`kNotFound`). Then, for the channel: the exact release that runs is `already`; one quarantined here is refused (`kRevoked`); its `seq` must be above the channel's floor (`kSuperseded`) and at most `max_seq_jump` above it, or, for a channel's first release, at most `max_seq_jump` past the host's clock in Unix seconds (`kOutOfRange`). The same release checks run again on every release a restart brings back.

## Swapping without a gap

A new release's modules load into the channel's sandbox in manifest order: a module the old release had too is **reloaded** (its `on_save` / `on_restore` carry state across), a new one is loaded, and the old release's leftover modules are unloaded afterwards. If any module fails, what changed is undone and the old release keeps running. A release asking for a different role gets a fresh sandbox that replaces the old one once everything loaded.

## Confirming: now, health, manual

| `confirm` | The release... |
|---|---|
| `now` | becomes active at once; the previous one is kept to fall back to |
| `health` | runs as a **candidate** for `health_window`; a module fault, more handler failures than `health.max_handler_failures` or one of the manifest's `health.fail_events` (an `rhp.publish`) rolls it back; a quiet window confirms it |
| `manual` | runs as a candidate until `confirm(channel)`, or `deactivate(channel)` rolls it back |

`deactivate(channel)` falls back (candidate → active, then the previous one; active → previous); with `hold` the channel runs nothing until a new release arrives, and the release it would have fallen back to stays as the previous one. `confirm` and `deactivate` return the id of the release they confirmed or stopped, and take an optional expected id: with one, they fail with `kSuperseded` unless that release is the one running (a rollout uses this so it never stops a release a host already replaced). The floor never goes down: a release that was rolled back can't be applied again (build a new one with a higher `seq`). A candidate that keeps crashing the program never gets confirmed: after `max_boot_attempts` restarts it is quarantined and the active release runs instead.

## Hardening

Channels run at a [hardening level](security.md#hardening-levels) as a host's identities do. `manager_options::hardening` sets it, and the build's `RHP_HARDENING` is always the floor: a lower value counts as the build's level.

| | `dev` | `lan` | `production` |
|---|---|---|---|
| an admin channel's libraries | Lua's full standard library | patch's libraries (it keeps its admin rights) | patch's libraries |
| a channel's limits | `manager_options::limits` | as at `dev` | capped by `kProductionCaps`: 1 s wall time per run, 512 MiB, cancel checks on every run, `cancel_check_instructions` at most 10,000 |

`manager::harden(level)` raises the level and never lowers it (a lower `level` changes nothing); `host.serve(manager)` calls it with the host's level, so a manager served by a `production` host runs at `production` even in a `dev` build. Raising it moves each running channel into a fresh sandbox made at the new level, as a role change does: the release loads there from scratch (no `on_save` / `on_restore`: module state doesn't carry over), then the old sandbox goes, undoing what it did; a `health` candidate keeps its health window. A channel whose release can't load at the new level (it needs `io`, say) stops, with a `kRolledBack` event that says why; its stored state is kept (the release stays in the store, the channel's floor and active release unchanged), so nothing is lost but nothing runs there until a release that loads at that level. Call `harden` before `restore()` (or set `manager_options::hardening`) to load releases only once. `harden` is refused from a channel's own scripts.

## Revocation

A revocation list (signed by keys trusted for `*`) stops what it names: revoked releases fall back like a deactivate, releases at or below a floor it lists are revoked (running ones stop, and none of them is fallen back to), releases whose only valid signatures were by revoked keys stop too, and channel floors rise (also for channels that never ran anything). It reaches a host through `kRevoke` (any identity may send one: it carries its own signatures), inside a release envelope, or `manager.revoke(bytes)` locally.

Revocations only add up. A host keeps the union of every list it accepted in its state and every list in its store (each under its own key); it takes a list into effect even when it can't be saved (the error says so, and the save is retried); a newer list can't un-revoke anything, and a key any list revoked can't sign a later list (so a stolen key can't forgive itself). Repeating older entries in a new list is harmless. On restore the stored list counts even if its signer has since been removed from the trust: it only ever withdraws trust.

Seqs can't be fast-forwarded. A list's seq may move at most `max_seq_jump` past the last list's (past the host's clock in Unix seconds for its first list), and each floor it raises at most `max_seq_jump` past the highest seq its channel has seen (past the clock when the channel has seen none). A list past a cap is refused whole (`kOutOfRange`, a `refused` event) and applies nothing, so one stolen `*` key can't set a seq or floor near 2^63 and lock out every later list. A refused list isn't remembered: send the real one with a seq inside the cap (`rhp-cli revoke build --seq N`). Recovering from a compromised release key over the air is what the [root of trust](#root-of-trust) is for.

## Root of trust

A trust file can't change once the app ships: a stolen release key stays trusted until the next build. A root of trust (decision AL12, `<rhp/release/root_of_trust.hpp>`) moves that decision to keys kept offline. It names keys and four roles, each with a threshold:

| Role | Signs |
|---|---|
| `root` | the next version of the root |
| `release` | releases (each key limited to channel patterns, like a trust file) |
| `revocation` | revocation lists and identity revocation lists |
| `operator_ca` | operator certificates ([security](security.md#keys-certificates-and-the-root-of-trust)) |

Make the first version offline and embed it in the app; the manager takes its release and revocation trust from it:

```bash
rhp-cli root init --root-key a.rhpid --root-key b.rhpid --root-threshold 2 --release-key rel.rhpid@game.* --revocation-key rev.rhpid --expires-in 365 --sign a.rhpid --sign b.rhpid
```

```cpp
auto anchor = Rhp::release::decode_root(embedded_root_bytes);   // root.1.rhproot, shipped with the app
Rhp::release::manager releases{std::move(*anchor), options, Rhp::release::directory_store{"save/releases"}};
```

- **Rotation.** `rhp-cli root next root.1.rhproot ...` makes version 2, which must be signed by a threshold of version 1's root keys and of its own. `rhp-cli trust push host:7777 root.2.rhproot -i ops.rhpid` (or `client.trust({...})`, `manager.update_root`) walks a host to it; versions must follow one another, and a host keeps each one in its store and walks them again from the anchor on restore. An expired root is refused as an update, but the root a host holds stays in force after it expires, so a late operator can't lock devices out.
- **Compromise.** `--compromise <key id>` in the next version takes the key out of every role and drops what it signed: revocation lists signed only by it are thrown away and what they raised (seqs, floors, revoked releases and keys) is taken back, and releases signed only by it stop. A key that is simply left out (`--retire`) keeps what it signed.
- **Identity revocations.** `rhp-cli revoke-identity --serial 1001 --signer ops.rhpid --device phone.rhpid --sign rev.rhpid` makes a list signed by the revocation role; `trust push` sends it. `manager.identities()` holds what every accepted list revoked; a served host refuses scripts from revoked signer keys (`kRevoked`), and certificate and device-key checks ask it too. Lists add up and their seqs are capped like revocation lists.
- `trust push` (op `kTrust`) needs only observe: the documents carry their own signatures. `release_status` reports the root version and identity revocation seq a host holds.
- A manager made from a trust file (no root) behaves as before; `update_root` reports `kNotFound`, and identity revocation lists are signed by its `*` keys.

## rhp-cli

```bash
rhp-cli release build --channel game.balance --module tuning.lua --module spawns=spawn_rules.lua -i dev.rhpid -o balance.rhprel
```

```bash
rhp-cli release inspect balance.rhprel
```

```bash
rhp-cli release apply balance.rhprel -c 127.0.0.1:7777 -i admin.rhpid --confirm health
```

```bash
rhp-cli release status -c 127.0.0.1:7777 -i admin.rhpid
```

```bash
rhp-cli rollout balance.rhprel -i admin.rhpid --host 10.0.0.5:7777 --host 10.0.0.6:7777 --canary 10.0.0.5:7777 --stage 0.5:30000 --stage 1:0
```

```bash
rhp-cli revoke build --release <id> -i ops.rhpid -o revocations.rhprev
```

`release confirm <channel>` and `release deactivate <channel> [--hold]` act on a running candidate or release; `revoke sign` adds a signature to a `.rhprev` and `revoke apply` sends it; `rollout` also takes `--max-failures` and `--keep-on-failure`, and discovers hosts when no `--host` is given. `release build` also takes `--seq` (default `auto`: the current Unix time), `--label`, `--app`, `--build`, `--platform`, `--not-before`, `--not-after`, `--role`, `--lib`, `--fail-event`, `--max-handler-failures`; several `-i` sign with several keys (`release sign` adds one later). `headless_server --releases DIR --release-signers FILE` serves releases and keeps them in `DIR`.

## Rollout

```cpp
Rhp::fleet<> group{admin_identity, admin_signing_key};
group.discover();                                  // or group.add(record) per host
Rhp::rollout_plan plan;
plan.canaries = {"build-agent-7"};
plan.stages = {{0.1, std::chrono::seconds{60}}, {0.5, std::chrono::seconds{60}}, {1.0, std::chrono::seconds{0}}};
plan.max_failures = 0;
const Rhp::rollout_report report = group.rollout(envelope_bytes, plan);
```

Canaries go first, then the rest in an order fixed by the release (each stage's fraction is cumulative, in [0, 1]; an unknown canary or a fraction outside that range is refused before any host is touched). Each stage's hosts apply the release health-watched, are watched for the stage's `observe` time (a host whose release fails rolls it back on its own; one that stops answering counts as failed; hosts the release isn't meant for, or that run a newer release in the channel, are skipped; a host that refuses it as superseded otherwise rolled it back or quarantined it earlier and counts as failed), then confirmed (only if it is still this release's candidate). When more than `max_failures` hosts fail, the rollout stops and, unless `rollback_on_failure` is false, deactivates the release on the hosts this run applied it to where it still runs (bound to its id). The report has one entry per member: `confirmed`, `already`, `skipped`, `failed`, `rolled_back` or `pending` (its stage wasn't reached); `completed` needs every stage passed and at least one host running the release.

## Faster restarts: the compiled-chunk cache

A restore parses every module of every release it brings back. Give the manager a key and it keeps each release's Lua bytecode in the store next to its envelope (`bytecode/<id>`), so the next restart, restore or fallback loads that instead (a boot restoring eight 300-line modules went from about 6 ms to about 2 ms in `Tests/bench/bench_release.cpp`):

```cpp
// A secret of this install: made once (Rhp::security::key::generate()), kept where the store's
// writers can't read it (the OS keychain, a protected config file), never shared with clients.
options.bytecode_key = *Rhp::security::key::from_file("config/rhp_bytecode.key");
```

- Lua doesn't check bytecode, and bytecode crafted by someone else escapes the sandbox. So every entry carries a keyed BLAKE2b-256 MAC under that key, checked before anything in it is read; it is also bound to the release id, each module's source hash and the Lua build (`Rhp::release::compiled_build()`). Releases still pass every check before their bytecode is looked at.
- Anything wrong with an entry (another key, an edited or truncated file, another Lua build, bytecode Lua refuses) throws it away: the sources are parsed and a fresh entry is written. `releases.bytecode_cache_stats()` counts loads, compiles, writes and discards, with the reason for the latest discard.
- Without a key nothing is cached and nothing cached is read. Envelopes from clients are always parsed as text; bytecode never comes from the wire.
- Debug information is kept: tracebacks, the debugger, the profiler and coverage see the same lines as with the source.
- Whoever can read the key can make this host run anything: keep it out of the store's folder, or don't set one. Entries go away with their releases.

## What the store protects against

The state document is checksummed (BLAKE2b-256) and every write goes through a temporary file and a rename, so a torn or corrupted write is noticed instead of trusted. It is not authenticated: someone who can write the store can lower floors, point a channel at an older signed release or delete revocations. Signatures are still checked on every restore, so only signed releases ever run. Keep the store where only the program can write. A restore takes the stored state and lists as they are, even past the seq caps (an older build may have accepted them): lowering them would undo revocations, refusing them would leave the store unusable.

## Limits

- Release ops need an admin identity (`kReleaseApply`, `kReleaseConfirm`, `kReleaseDeactivate`); `kReleaseStatus` and `kRevoke` need observe. They are not on the HTTP gateway yet. They run on the pump thread inside `host.pump()`: a large release delays the other sessions' requests while it loads, and `kCancel` doesn't reach it.
- `--seq auto` is the Unix time in seconds: two builds of one channel in the same second share a seq (pass `--seq`). Counters (1, 2, 3) and Unix-time seqs pass the `max_seq_jump` caps; seqs that are neither (milliseconds, a date with the time) need a larger `max_seq_jump` for a channel's first release and a host's first revocation list. A host whose clock is far behind refuses a first Unix-time seq until its clock is right.
- A module's top level must finish while loading: a release whose module suspends (`rhp.wait`) is refused.
- `directory_store` syncs files and directories on POSIX and flushes with `_commit` on Windows; a store on a network share is only as durable as the share.
- `headless_server` takes a release-signers file, not a root of trust.
- Release state in the store is checksummed, not authenticated ([above](#what-the-store-protects-against)); MAC'd release state and pulling releases over HTTPS with a signed channel index are Stage 13c.
