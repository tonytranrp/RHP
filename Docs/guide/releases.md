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
| **revocation list** (`.rhprev`) | Release ids and signing keys to stop trusting and channel floors to raise. Cumulative: each list replaces the previous one (higher `seq`). |
| **trust** | The keys that may sign releases (separate from script signers), each limited to channel patterns (`game.*`, `*`), with a threshold of distinct signers. |
| **store** | Where a manager keeps its state, the revocation list and the envelopes it may run again: `memory_store` or `directory_store` (one file per key, written through a synced rename). Anything that models `Rhp::release::storage` works. |

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

Without a host, call `releases.pump()` every frame and `releases.apply(envelope)` yourself (a release file shipped with an update, downloaded at startup).

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
| `max_seq_jump` | 2^32 | how far `seq` may jump past the floor at once |
| `limits` | host-like (`wall_ms` 10 s) | the channels' sandboxes |
| `wall_clock`, `clock` | system / steady | injectable for tests |
| `output` | none | `print()` of the channels' scripts, with the channel |

## What a host checks

In order, before anything runs: the envelope decodes and its body is canonical; enough trusted, unrevoked keys signed it for its channel (`kBadSignature`); the release isn't revoked or quarantined here (`kRevoked`); it is meant for this app, build and platform (`kOutOfScope`); now is inside its validity window (`kExpired`); its `seq` is above the channel's floor (`kSuperseded`) and not too far above (`kOutOfRange`); its role is allowed (`kForbidden`); every lib it needs is installed (`kNotFound`); every source matches its hash (`kIntegrity`). The same checks run again on every release a restart brings back.

## Swapping without a gap

A new release's modules load into the channel's sandbox in manifest order: a module the old release had too is **reloaded** (its `on_save` / `on_restore` carry state across), a new one is loaded, and the old release's leftover modules are unloaded afterwards. If any module fails, what changed is undone and the old release keeps running. A release asking for a different role gets a fresh sandbox that replaces the old one once everything loaded.

## Confirming: now, health, manual

| `confirm` | The release... |
|---|---|
| `now` | becomes active at once; the previous one is kept to fall back to |
| `health` | runs as a **candidate** for `health_window`; a module fault, more handler failures than `health.max_handler_failures` or one of the manifest's `health.fail_events` (an `rhp.publish`) rolls it back; a quiet window confirms it |
| `manual` | runs as a candidate until `confirm(channel)`, or `deactivate(channel)` rolls it back |

`deactivate(channel)` falls back (candidate → active, active → previous); with `hold` the channel runs nothing until a new release arrives. The floor never goes down: a release that was rolled back can't be applied again (build a new one with a higher `seq`). A candidate that keeps crashing the program never gets confirmed: after `max_boot_attempts` restarts it is quarantined and the active release runs instead.

## Revocation

A revocation list (signed by keys trusted for `*`) stops what it names: revoked releases fall back like a deactivate, releases whose only valid signatures were by revoked keys stop too, and floors rise for the channels it lists (also channels that never ran anything). It reaches a host through `kRevoke` (any identity may send one: it is signed itself), inside a release envelope, or `manager.revoke(bytes)` locally, and it is stored with the state.

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

`release build` also takes `--seq` (default `auto`: the current Unix time), `--label`, `--app`, `--build`, `--platform`, `--not-before`, `--not-after`, `--role`, `--lib`, `--fail-event`, `--max-handler-failures`; several `-i` sign with several keys (`release sign` adds one later). `headless_server --releases DIR --release-signers FILE` serves releases and keeps them in `DIR`.

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

Canaries go first, then the rest in an order fixed by the release (each stage's fraction is cumulative). Each stage's hosts apply the release health-watched, are watched for the stage's `observe` time (a host whose release fails rolls it back on its own; one that stops answering counts as failed; hosts the release isn't meant for are skipped), then confirmed. When more than `max_failures` hosts fail, the rollout stops and, unless `rollback_on_failure` is false, deactivates the release on every host that still runs it. The report has one entry per member: `confirmed`, `already`, `skipped`, `failed`, `rolled_back` or `pending` (its stage wasn't reached).

## Limits

- Release ops need an admin identity (`kReleaseApply`, `kReleaseConfirm`, `kReleaseDeactivate`); `kReleaseStatus` and `kRevoke` need observe. They are not on the HTTP gateway yet.
- A module's top level must finish while loading: a release whose module suspends (`rhp.wait`) is refused.
- `directory_store` syncs files and directories on POSIX and flushes with `_commit` on Windows; a store on a network share is only as durable as the share.
- The Python client doesn't speak releases yet.
