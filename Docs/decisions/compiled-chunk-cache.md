# Compiled-chunk cache: release bytecode that survives a restart

Within one process a signed script is compiled once (`exec_cached`, the trusted-source cache), but a release's modules were parsed again at every boot, restore and fallback. The release manager can now keep the Lua bytecode of each release it runs in its store, next to the envelope, and load that instead of parsing.

## Decisions

- **Opt-in, keyed by a host-local secret.** `manager_options::bytecode_key` (a `security::key`, 16..64 bytes). Without a key nothing is written or read: every load parses, as before. The key is the application's: generated once per install and kept where the store's writers can't read it (the OS keychain, a protected config). It is never sent anywhere and never shared with clients.
- **Authenticated with keyed BLAKE2b-256.** Lua doesn't verify bytecode, and malicious bytecode escapes the sandbox (it can forge upvalues and read or write arbitrary memory). The envelope's Ed25519 signature covers the sources, not the bytecode, and the directory store is a plain folder. So each entry is `MAC || body` with `MAC = keyed BLAKE2b-256(key, "rhp/bytecode\0" || body)` (Monocypher, `security::keyed_blake2b_256`), compared in constant time (`security::digests_equal`). The MAC is checked before anything in the body is decoded, let alone handed to `lua_load`.
- **One entry per release, beside the manifest, not in it.** Key `bytecode/<hex release id>`; body = MessagePack `{rhp = "release-bytecode", revision, build, release, modules = [{name, hash, code}...]}` (`release/bytecode.hpp`: `seal_compiled`, `open_compiled`, `compiled_store_key`). The manifest's canonical encoding (and so every release id) is untouched. Garbage collection drops an entry with its release.
- **Keyed by the source's hash and the Lua build.** `hash` is each module's manifest hash (BLAKE2b-256 of its source, checked against the source when the envelope is decoded); `release` is the release id; `build` is `compiled_build()`, BLAKE2b-256 of `script::bytecode_build()`: `LUA_VERSION_RELEASE_NUM` plus the `lua_dump` of a probe chunk exercising constants of every type, nested functions, upvalues, varargs, gotos and line info. That dump starts with the header `lundump` checks (version, format, `LUAC_DATA`, sizes of `int`, `Instruction`, `lua_Integer`, `lua_Number`), and any change to the compiler or to the dump format changes it, even one that keeps Lua's version. Nothing RHP-specific is in the bytecode: the module environment (`_ENV`) is set after loading on both paths, and `RHP_ENABLE=0` builds have no Lua (`bytecode_build()` is empty, so nothing is cached).
- **Debug information kept.** `lua_dump(..., strip = 0)`: tracebacks, the debugger, the profiler and coverage see the same lines and chunk names (`@module.name`) as with the source. The sandbox also checks that the loaded chunk was compiled under that module's name and is a main chunk (one upvalue, vararg, no parameters).
- **Every failure falls back to the source, visibly.** No key: parse. No entry: compile here (`sandbox::compile_module`), load that bytecode, store the entry. An entry whose MAC doesn't match (another key, an edit), that is truncated or malformed, of another revision, made by another build, or for another release's modules is discarded (removed from the store) and the sources are parsed; `manager::bytecode_cache_stats()` counts it (`discarded`, `last_discarded` with the reason) and the entry is written again. Bytecode that passes the MAC but that Lua still refuses (a build change the probe missed) is set aside by the sandbox, which parses the source (`sandbox_stats::bytecode_rejected`); the manager discards that entry too and writes a new one. A cache write that fails costs the next load a parse, never the release.
- **Never from the wire.** Envelopes from clients are text: the sandbox loads every network source with mode `"t"`, a release whose source is bytecode fails with `kCompile`, and Lua's own `load` stays text-only. Only `sandbox::load(name, source, trusted_bytecode)` loads bytecode, and only the manager (from MAC'd entries) and the test runner (bytecode it compiled in-process) call it. Everything a manager runs still goes through `manager_impl::check` (signatures, revocations, scope, window) before its cached bytecode is looked at.
- **Unchanged modules reuse their bytecode.** A swap that keeps a module (same name and hash) takes its bytecode from the previous release's entry; only changed modules are compiled.
- **The test runner, in-process.** `--isolation test` creates a sandbox per test and loaded every module of the scripts folder into each from source. The runner now compiles each module once (`compile_module`, in the first sandbox) and loads that bytecode in every later sandbox. No MAC: the bytecode never leaves the process and was made from the files the runner read.

## Threat model

- Someone who can write the store but doesn't have the key can delete or edit entries (each is discarded and the sources parsed), copy one release's entry over another's (the `release` and module hashes don't match: discarded), or put back an older entry this host made (it holds bytecode this build compiled from exactly those sources: harmless; one from an older build is discarded by `build`). They can't make the host run bytecode it didn't compile.
- Someone who can read the key can make bytecode the host runs unchecked: keep the key out of the store's folder, or don't configure one. This is the only new trust the cache adds; without a key the store's threat model is unchanged (see the releases guide).
- MACs are compared in constant time; the key is wiped when the options die (`security::key`).

## Alternatives

- **Sign the bytecode with the release key (in the envelope).** Bytecode is specific to one Lua build; the signer would have to build per target, and a release id would change with the toolchain. Rejected.
- **Bytecode fields in the manifest.** Changes the canonical encoding, so every release id. Rejected (the manifest rule).
- **Trust the store as is.** The directory store is a plain folder, often under a save directory; loading unauthenticated bytecode from it turns write access into code execution. Rejected.
- **A bytecode verifier.** Lua has none (`luai_verifycode` is empty), and writing one for 5.5's format is a large attack surface of its own. Rejected.
- **Per-module entries keyed by source hash** (shared across releases). Garbage collection would have to decode every kept release to know which modules are referenced. Per-release entries go with their release; unchanged modules are copied from the previous release's entry instead.
- **Lua's fixed-buffer loading (`mode "B"`)**, which keeps strings in the caller's buffer: the buffer would have to outlive every function of the module. Rejected for plain `"b"`.

## Measurements

`Tests/bench/bench_release.cpp`, Release build, Windows MSVC, three runs on a machine busy with other builds (means; ranges across runs). Eight modules of about 300 lines (73.6 KB of source, 83.5 KB of bytecode with debug information):

| Benchmark | Sources parsed | Bytecode |
|---|---:|---:|
| `module-load raw`: a plain `lua_State` compiling the 8 modules | 3.8 - 5.1 ms | 0.50 - 0.56 ms |
| `module-load rhp`: a fresh sandbox loading the 8 modules (each `--isolation test` sandbox) | 4.3 - 4.7 ms | 0.69 - 1.05 ms |
| `restore rhp`: a boot restoring a release of the 8 modules (a manager over a memory store) | 5.6 - 7.3 ms | 2.1 - 4.7 ms (2.1 - 2.5 ms in two runs of three) |

What a cached restore still spends is the rest of a boot: the sandbox, the envelope's decode with its source hashes and Ed25519 signature, the entry's MAC and decode, undumping, the state written back.

## Consequences

- A boot or restore of a cached release parses nothing (measured in `Tests/bench/bench_release.cpp`, see Measurements). The first load of a release with the key on costs a parse, a dump, an undump and a store write.
- The store holds one more file per kept release (bytecode with debug information is a few times the source size).
- `manager::bytecode_cache_stats()` reports loads, compiles, writes, discards and why.
