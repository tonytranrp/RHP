# Benchmarks

What RHP costs on top of the Lua code it runs, measured by `rhp_bench` (`Tests/bench`). Every RHP benchmark that has a plain-Lua (or plain C++) equivalent sits next to a **raw twin** with the same name: `lua raw: fib(22)` runs on a bare `lua_State`, `lua rhp: fib(22)` runs the same Lua through a sandbox. The ratio between the two is RHP's overhead on that work, and it travels between machines far better than absolute times do.

Stage 8 wrote the suite first, measured, then removed what the numbers showed RHP wasting. The tables below are that before and after.

## Running it

```bash
cmake --preset windows-msvc -B build/bench -DRHP_BUILD_BENCH=ON
```

```bash
cmake --build build/bench --config Release --target rhp_bench
```

```bash
build/bench/Tests/bench/Release/rhp_bench "[bench]" --benchmark-samples 50 --benchmark-resamples 2000 --benchmark-warmup-time 200 --reporter xml::out=bench.xml
```

```bash
python Tools/bench/summarize.py bench.xml
```

`Tools/bench/compare.py before.xml after.xml` diffs two runs and reports a change only when the confidence intervals don't overlap and the means differ by more than 5% (`--threshold`). The `unchecked` side runs the same work with `limits.cancel_checks = kNone`. Groups can be run alone: `"[lua]"`, `"[bindings]"`, `"[patch]"`, `"[events]"`, `"[scheduler]"`, `"[requests]"`, `"[wire]"`, `"[security]"`, `"[e2e]"`, `"[tools]"`, `"[testing]"`.

Always benchmark a Release build (`RelWithDebInfo` on MSVC inlines less). On a laptop or a hybrid-core CPU, pin the process to one performance core and keep the machine idle; even then, treat differences under 10% as noise unless they repeat. ctest only runs a two-sample smoke pass (`bench.smoke`) so the suite keeps compiling and running.

## What each group measures

| Group | RHP side | Raw twin |
|---|---|---|
| `lua` | module functions called through `sandbox::call`: an arithmetic loop, recursion, tables, strings, closures, coroutines, `pcall` errors; `exec` of a one-liner | the same Lua on a `lua_State` with the standard libraries |
| `bindings` | `Rhp::lib` function calls (through the lib and held in a local), variable reads, journaled writes plus their revert, handle round trips | a hand-written `lua_CFunction` and a plain table field |
| `patch` | an unpatched patch point; patched by a Lua handler, with and without `original` | a direct call through a function pointer; `lua_pcall` of the handler |
| `events` | `lua_event::fire` with nobody listening and with 1 / 10 / 100 handlers; a `pump()` delivering an `rhp.publish` | calling the same number of Lua functions |
| `scheduler` | one `pump()` with N frame callbacks, idle timers, sleeping tasks or tasks resuming every frame (N = 0 ... 10000) | resuming N coroutines from Lua |
| `requests` | `call` with arguments, `reload`, `load` + `unload`, `checkpoint` + `revert_to` | |
| `wire` | MessagePack encode / decode, value copy, CRC32C, frame encode / decode at 64 B, 4 KiB, 64 KiB | `memcpy` of the same bytes |
| `security` | BLAKE2b-256, Ed25519 sign and verify of 4 KiB | |
| `e2e` | a signed `exec` and a `call` from a client to a host over loopback, both on one thread (`io<zero_threads>`) | the same `exec` on a sandbox directly (`e2e local`) |
| `testing` (Stage 12) | the same loop and `fib(22)` with the exact instruction meter, with line coverage, and both; the test runner over a file with no tests, 100 empty tests (measured and `--no-measure`), and one test doing 10k lib calls (plain and through `spy.on`), 10k plain checks, 10k `assert.equals`, 10k `expect().to.equal` | the same Lua on a plain `lua_State`; a state compiling the framework; 100 `pcall`s of empty functions |
| `tools` (Stage 11) | the same loop and `fib(22)` with no tool, with a breakpoint armed elsewhere / on a line number the loop runs / inside the module, and with the profiler sampling every 1000 and 100 instructions; a tunable read and a `tune` write | the same Lua on a plain `lua_State`; a plain global read and write |

## Results

Measured on 2026-10-24 on one laptop (Windows 11, MSVC 19.51 Release, process pinned to one core at high priority; WSL Ubuntu, Clang 21 Release, `taskset -c 2`), 40 samples each. "Before" is the suite at `201713b` (Stage 8 benchmarks, before any optimization); "after" is the Stage 8 branch with the review fixes. Changes under about 15% on a row are within this machine's run-to-run noise: the raw twins, whose code didn't change, move by that much between runs.

What changed and why:

- **Events** (-66…-84%): a delivery used to start a full request per handler (record, coroutine, error-location strings, clock reads). Records, map nodes and coroutines are now pooled, locations are formatted only when a handler fails, and clocks are read only with `limits.wall_ms`.
- **Scheduler** (-76…-99.9%): `pump()` remembers the next due frame and time, so idle timers and sleeping tasks cost nothing until one is due. Frame callbacks reuse pooled requests.
- **Coroutines on Linux** (about 20x): Lua compiled as C++ threw a C++ exception on every yield; yields now `_longjmp` (`RHP_LUA_JUMP_YIELDS`, errors still throw). The raw twin uses the same Lua build, so it got faster too. MSVC keeps exceptions (a `_longjmp` there unwinds), which is why Windows yields didn't move.
- **Patched calls** (-56…-65%): a Lua patch layer builds the `original` function once instead of per call.
- **Bindings** (up to -43%): lib functions resolve through a members table used directly as `__index`; journaled writes allocate less.
- **Wire** (-60…-81%): hardware CRC32C (SSE4.2 / ARMv8 CRC) and frames encoded into one allocation.
- **Security / end to end** (signing -39…-46%, end to end about -10%): the Ed25519 public key is derived once, and hosts check script signatures on the network thread while `pump()` keeps running scripts.

### Where the remaining cost is

- **The cancel hook.** By default (`limits.cancel_checks = kRequests`) every `exec` / `load` / `call` / task runs with Lua's count hook armed, so a client's cancel can stop a runaway loop. Stock Lua checks an armed hook on every instruction, which roughly doubled the time of loop-heavy code (`fib(22)`: about 2x raw); since the [overall optimization pass](#overall-optimization-pass) a count that isn't due is counted down inline, and the same code runs at about 1.2-1.5x raw. The `unchecked` rows run the same calls with `cancel_checks = kNone`: they run at raw-Lua speed. For trusted scripts that never need a remote cancel, set `kNone`; instruction, memory and wall-time limits still arm the hook when set.
- **A request per call.** `sandbox::call` starts a request (a pooled coroutine, a ledger owner, result conversion): about 0.4 µs over a raw `lua_pcall` of an empty function.
- **Binding calls** cost about 2-3.5x a hand-written `lua_CFunction` (arguments converted through `Rhp::result<T>`, the role check, the label). Fine for gameplay calls; a binding called millions of times per frame is better written to take a batch.
- **Variable reads** of small trivially copyable variables (numbers, bools, enums) take no lock since the overall optimization pass (an atomic read; RHP's own writes store atomically too); other types still read under the variable's lock. From Lua a read costs about 65-80 ns, most of it the binding. A value read every frame in a hot loop is cheaper to pass in as an argument.

Rows under a few nanoseconds (an unpatched point, an event fired with nobody listening) are at the timer's resolution: read them as "free", not as a ratio.

### Before and after Stage 8

| Benchmark | Windows before | Windows after | Windows change | Linux before | Linux after | Linux change |
|---|---:|---:|---:|---:|---:|---:|
| events rhp: deliver to 1 handlers | 932 ns | 315 ns | -66% | 677 ns | 213 ns | -69% |
| events rhp: deliver to 100 handlers | 78.4 us | 12.4 us | -84% | 66.9 us | 13.7 us | -80% |
| events rhp: pump delivering a publish to 100 handlers | 89.9 us | 14.9 us | -83% | 77.5 us | 13 us | -83% |
| scheduler rhp: pump with 1000 frame callbacks | 1.14 ms | 223 us | -81% | 773 us | 186 us | -76% |
| scheduler rhp: pump with 10000 idle timers | 82.7 us | 130 ns | -100% | 72.6 us | 107 ns | -100% |
| scheduler rhp: pump with 10000 sleeping tasks | 131 us | 157 ns | -100% | 197 us | 135 ns | -100% |
| scheduler rhp: resume 1000 tasks | 3.38 ms | 2.72 ms | -20% | 1.87 ms | 148 us | -92% |
| scheduler raw: resume 1000 tasks | 2.82 ms | 2.65 ms | -6% | 2.77 ms | 98.5 us | -96% |
| lua rhp: 1k coroutine yields | 2.86 ms | 2.59 ms | -9% | 2.2 ms | 85.5 us | -96% |
| lua raw: 1k coroutine yields | 2.93 ms | 2.55 ms | -13% | 2.04 ms | 109 us | -95% |
| patch rhp: call into a Lua handler | 228 ns | 81 ns | -65% | 165 ns | 72.2 ns | -56% |
| patch rhp: call into a Lua handler calling original | 383 ns | 163 ns | -58% | 239 ns | 103 ns | -57% |
| bindings rhp: 10k calls of bench.add | 1.26 ms | 724 us | -42% | 889 us | 831 us | -6% |
| bindings rhp: 10k journaled var writes then their revert | 13.8 ms | 7.81 ms | -43% | 29 ms | 18 ms | -38% |
| lua rhp: empty function call | 1.03 us | 507 ns | -51% | 893 ns | 747 ns | -16% |
| lua rhp: 1k pcall errors | 5.67 ms | 3.32 ms | -41% | 2.5 ms | 2.58 ms | +3% |
| requests rhp: call with two arguments | 959 ns | 420 ns | -56% | 720 ns | 550 ns | -24% |
| requests rhp: checkpoint and revert_to over 100 scratch effects | 50.2 us | 53 us | +5% | 37.8 us | 42.1 us | +11% |
| wire rhp: crc32c of 4096 bytes | 1.55 us | 291 ns | -81% | 1.69 us | 338 ns | -80% |
| wire rhp: encode a frame of 4096 bytes | 3.75 us | 1.51 us | -60% | 2.31 us | 516 ns | -78% |
| wire rhp: decode a frame of 4096 bytes | 1.7 us | 369 ns | -78% | 2.21 us | 436 ns | -80% |
| security rhp: ed25519 sign of 4 KiB | 85.1 us | 51.6 us | -39% | 98.8 us | 53 us | -46% |
| e2e rhp: signed exec of a one-line script | 217 us | 192 us | -12% | 190 us | 184 us | -3% |
| e2e rhp: call of a module function | 20.4 us | 18.4 us | -10% | 8.89 us | 7.92 us | -11% |

### What RHP costs on top of raw Lua (after)

| Work | Windows raw | Windows rhp | Windows rhp / raw | Windows unchecked / raw | Linux raw | Linux rhp | Linux rhp / raw | Linux unchecked / raw |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `lua`: empty function call | 93.6 ns | 507 ns | 5.41x | 5.24x | 89.2 ns | 747 ns | 8.37x | 5.25x |
| `lua`: 100k arithmetic loop | 729 us | 1.36 ms | 1.87x | 1.01x | 831 us | 1.4 ms | 1.68x | 1.09x |
| `lua`: fib(22) | 1.05 ms | 2.09 ms | 1.99x | 1.00x | 1.14 ms | 2.12 ms | 1.87x | 0.80x |
| `lua`: 10k table fill and ipairs | 289 us | 431 us | 1.49x | 0.98x | 253 us | 327 us | 1.29x | 1.13x |
| `lua`: 1k tostring and concat | 120 us | 156 us | 1.30x | - | 115 us | 122 us | 1.06x | - |
| `lua`: 10k closures | 1.05 ms | 1.35 ms | 1.29x | 1.34x | 745 us | 1.35 ms | 1.81x | 1.06x |
| `lua`: 1k coroutine yields | 2.55 ms | 2.59 ms | 1.02x | - | 109 us | 85.5 us | 0.78x | - |
| `lua`: 1k pcall errors | 2.6 ms | 3.32 ms | 1.28x | - | 1.72 ms | 2.58 ms | 1.50x | - |
| `bindings`: 10k calls of bench.add | 331 us | 724 us | 2.18x | - | 279 us | 831 us | 2.98x | - |
| `bindings`: 10k calls of bench.add held in a local | 272 us | 621 us | 2.28x | - | 177 us | 602 us | 3.40x | - |
| `bindings`: 10k reads of bench.speed | 99.6 us | 1.03 ms | 10.29x | - | 158 us | 682 us | 4.31x | - |
| `patch`: call of the C++ default | 0.862 ns | 1.08 ns | 1.26x | - | 1.81 ns | 0.503 ns | 0.28x | - |
| `patch`: call into a Lua handler | 21.1 ns | 81 ns | 3.84x | - | 29.5 ns | 72.2 ns | 2.45x | - |
| `events`: deliver to 1 handlers | 24.2 ns | 315 ns | 13.02x | - | 43.5 ns | 213 ns | 4.90x | - |
| `events`: deliver to 100 handlers | 2.18 us | 12.4 us | 5.67x | - | 1.29 us | 13.7 us | 10.57x | - |
| `scheduler`: resume 1000 tasks | 2.65 ms | 2.72 ms | 1.03x | - | 98.5 us | 148 us | 1.50x | - |

## Stage 11 tools

Measured on 2026-10-24 on the same laptop (Windows 11, MSVC Release, pinned to one core at high priority, 60 samples), after the Stage 11 review fixes. Each row is against its raw twin in the same run; `tools-off` is the sandbox with no tool (what the default cancel hook costs, about 2x on this loop-heavy code).

| Work | No tool | Breakpoint elsewhere | Breakpoint on a line number it runs | Breakpoint in the module | Profile every 1000 | Profile every 100 |
|---|---:|---:|---:|---:|---:|---:|
| 100k arithmetic loop | 1.91 ms (2.10x) | 5.02 ms (5.24x) | 7.05 ms (7.48x) | 4.66 ms (5.03x) | 1.93 ms (2.06x) | 2.54 ms (2.97x) |
| fib(22) | 2.66 ms (1.99x) | 5.51 ms (4.12x) | - | 5.39 ms (4.14x) | 3.00 ms (2.22x) | 6.24 ms (4.78x) |

| Work | Raw | RHP |
|---|---:|---:|
| read one tunable (`tunables("x.y")`) vs a global read | 13.5 ns | 418 ns |
| write one tunable (`tune`, journaled) vs a global write | 8.51 ns | 3.14 us (noisy: 0.75-12.5 us) |

What the numbers say:

- **No breakpoint, no cost.** Without breakpoints, a step or a pause, the line hook isn't armed; the `tools-off` rows are the plain sandbox.
- **An armed debugger costs about 2-2.5x on top of the sandbox** for line-dense code: every line runs the hook, and the line bitmap rejects it. A line number that has a breakpoint in any source adds a `lua_getinfo` and a source lookup (`debug-line`). (Stage 11 measurement. Since the overall optimization pass, line events are turned on per function, at its call or return, only where it holds a breakpoint, without re-arming the hook, so the instruction countdown is kept: a loop in a function without a breakpoint runs at about 1.2-1.3x raw Lua, as with no debugger (`debug-armed`, `debug-inside`). The first try at this, which re-armed the hook, starved instruction limits and cancels.) Clear breakpoints when you stop debugging (`set_breakpoints(source, {})`, `debug_reset()`, or end the debugging session).
- **The profiler at its default interval (1000) is close to free** on loops (2.06x vs 2.10x) and costs about 10% on call-heavy code. At 100 the stack walks show, most on deep recursion (`fib`: 4.8x). Sample at 1000 unless short scripts need more resolution.
- **Tunables are for tools, not hot paths.** Listing one tunable builds its description (tags, current value); a `tune` runs a journaled scratch request. Both are per command, not per frame.

## Stage 12 test engine

Measured on 2026-10-24 on the same laptop (Windows 11, MSVC Release, pinned to one core at high priority, 40 samples). `-off` rows are the same work without the feature (the plain sandbox, or the runner on a test without spies or assertions), so a feature's cost is the difference.

| Work | Raw | Off | Metered | Coverage | Coverage + metered |
|---|---:|---:|---:|---:|---:|
| 100k arithmetic loop | 965 us | 1.82 ms | 1.82 ms | 5.23 ms | 5.23 ms |
| fib(22) | 1.46 ms | 2.77 ms | 2.81 ms | 5.31 ms | 5.34 ms |

The runner, before and after the optimizations below (same machine, same settings):

| Work | Before | After |
|---|---:|---:|
| a test file with no tests (a sandbox, the framework, the file) | 3.97 ms | 1.39 ms |
| 100 empty tests, measured (one file) | 26.5 ms | 15.3 ms |
| 100 empty tests, `--no-measure` | 6.82 ms | 4.07 ms |
| 10k lib calls in one test (`spy-off`) | 5.19 ms | 2.52 ms |
| 10k lib calls through `spy.on` | 42.9 ms | 25.0 ms |
| 10k plain checks (`assert-off`) | 4.51 ms | 1.83 ms |
| 10k `assert.equals` | 35.7 ms | 14.7 ms |
| 10k `expect(x).to.equal(y)` | 62.4 ms | 21.5 ms |

For scale: a raw state compiling the framework takes 3.28 ms, and 100 `pcall`s of empty functions 54 us.

What the numbers say:

- **Exact metering is free.** The meter adds the count hook's ticks and reads each thread's countdown after a resume; the loop and `fib` cost the same with and without it.
- **Coverage costs about 2-3x on line-dense code**, the price of Lua's line hook (the same as an armed debugger, [Stage 11](#stage-11-tools)). The hook itself is a lookup of the running prototype and an array increment. Turn coverage on for coverage runs, not for every run.
- **A test file costs about 1.4 ms.** Most of the 4 ms before was parsing the framework's 100 KB of Lua in every new sandbox; now each process compiles it once and later sandboxes load its bytecode (`sandbox::exec_cached`, trusted sources only). Test files are cached the same way, which matters with `--isolation test`, where every test makes a sandbox.
- **A measured test costs about 150 us, an unmeasured one about 40 us.** The difference is the full garbage collection on each side of a measured test (the retained-memory figure); there was a second collection on each side before, needed only for objects with finalizers. `--no-measure` skips them for fast iteration.
- **Assertions and spies are cheap enough for hot loops.** An `assert.equals` costs about 1.3 us (word chains are made once per spelling and resolved once), an `expect(...).to.equal` about 2 us (one table per word, messages built only for a failure), a call through a spy about 2.3 us (arguments without tables aren't copied).


## Overall optimization pass

Measured on 2026-10-25 on the same laptop (MSVC Release, pinned to one core at high priority, 30 samples): the suite before this pass (`main` at Stage 12) and after it, each run twice in alternating order; each side's number is the lower of its two means. What changed and why is in [the decision](decisions/performance-and-build-speed.md).

| Benchmark | Before | After | Change |
|---|---:|---:|---:|
| e2e rhp: signed exec of a one-line script (the same script again) | 168 us | 18.3 us | -89% |
| e2e rhp: call of a module function (loopback, one thread) | 17.4 us | 12.4 us | -29% |
| lua rhp: 100k arithmetic loop (default cancel checks) | 1.85 ms | 1.01 ms | -45% |
| lua rhp: fib(22) | 2.86 ms | 1.71 ms | -40% |
| lua rhp: 10k closures | 1.64 ms | 1.31 ms | -20% |
| lua rhp: empty function call (`sandbox::call`) | 571 ns | 392 ns | -31% |
| requests rhp: call with two arguments | 478 ns | 306 ns | -36% |
| lua rhp: 1k coroutine yields (Windows) | 2.95 ms | 104 us | -96% |
| scheduler rhp: resume 1000 tasks (Windows) | 2.88 ms | 172 us | -94% |
| scheduler rhp: pump with 1000 frame callbacks | 245 us | 175 us | -29% |
| scheduler rhp: an idle pump | 137-156 ns | 79-90 ns | about -40% |
| bindings rhp: 10k journaled var writes then their revert | 7.3 ms | 1.87 ms | -74% |
| bindings rhp: 10k ready async calls | 3.65 ms | 1.93 ms | -47% |
| bindings rhp: 10k reads of a lib variable | 843 us | 667 us | -21% |
| bindings rhp: 10k calls held in a local | 742 us | 563 us | -24% |
| requests rhp: checkpoint and revert_to over 100 scratch effects | 53.8 us | 41.1 us | -24% |
| wire rhp: msgpack encode of a small reply | 368 ns | 202 ns | -45% |
| wire rhp: encode a frame of 4 KiB / 64 KiB | 1.38 us / 22.2 us | 317 ns / 4.79 us | -77% / -78% |
| wire rhp: decode a frame of 64 KiB | 8.52 us | 3.94 us | -54% |
| wire rhp: crc32c of 4 KiB / 64 KiB | 336 ns / 5.72 us | 185 ns / 2.84 us | -45% / -50% |
| testing: 10k `assert.equals` / `expect().to.equal` in one test | 12.9 / 18.8 ms | 10.6 / 16.2 ms | -18% / -14% |
| debug-armed rhp: 100k loop, a breakpoint in another module | 4.32 ms | 1.0 ms | -77% |
| debug-inside rhp: 100k loop, a breakpoint elsewhere in the same module | 4.62 ms | 1.01 ms | -78% |
| debug-armed / debug-inside rhp: fib(22) (a call and a return event per call) | 4.4 / 4.34 ms | 3.99 / 3.86 ms | ~ |
| e2e rhp: 32 pipelined module calls over TCP on 127.0.0.1 (gathered writes) | 632-635 us | 374-401 us | -39% |
| mDNS: Windows resolves a record RHP's responder publishes (`mdns: the native provider ...`, Debug) | 24-41 s | 2.7 s | -90% |

Rows not listed moved by less than about 10% (within this machine's noise), apart from three. Two raw twins moved, whose code didn't change: noise. `tunables rhp: write one variable` journals every write of the benchmark into one sandbox, so its mean measures the journal's reallocations (its standard deviation is larger than its mean on both sides; the lower bounds agree). Windows yields jump now (an x64 process without a CET shadow stack); on Linux they already did.

Ranked by the ratio to their raw twins after the pass, the largest left are by design rather than overhead to remove: `tunables rhp: read one variable` (370 ns, about 34x) builds a description of the variable with its tags for `rhp-cli tune`, where the raw twin reads a global; `events rhp: deliver to N handlers` (275 ns for one, then about 130 ns per handler; raw about 20 ns) runs every handler as a request of its own on a coroutine, so it can yield and a failing handler undoes only its own call; the write row is the journal described above.

The biggest remaining cost of loop-heavy scripts is gone: with the default `cancel_checks = kRequests`, a loop runs at about 1.2x raw Lua (it was 1.85-2x), so `kNone` is only worth it for the last few percent.

Builds (clean `windows-msvc` Debug, 16 threads, 16 GB):

| | Before | After |
|---|---:|---:|
| build wall time | 174-183 s | 111 s (106 s with `RHP_UNITY_BUILD`) |
| compile time summed over jobs | 2953-3097 s | 1765 s |
| Catch2 (108 sources) | about 450 s | about 110 s (unity) |
| linking, summed | 364-399 s | 110 s (job pool) |
| full ctest run (16 cores) | 77 s | 42-62 s |

## Follow-up pass: profiled hot paths

Measured on 2026-10-25, same laptop and method (MSVC Release, one core, high priority, 40 samples): `main` before the pass and the branch, each run twice in alternating order; each side's number is the lower of its two means. A profile (Visual Studio's sampling collector on a RelWithDebInfo build) showed where a remote call's time went: frame MACs about a quarter, then system calls and allocation; Lua itself a few percent. What changed is in [the decision](decisions/performance-and-build-speed.md).

| Benchmark | Before | After | Change |
|---|---:|---:|---:|
| e2e rhp: call of a module function | 12.4-12.9 us | 11.0-11.1 us | -11% to -14% |
| e2e rhp: signed exec of a one-line script | 17.8-17.9 us | 16.3-16.6 us | -7% to -9% |
| e2e rhp: 32 pipelined module calls over TCP on 127.0.0.1 | 377-378 us | 309-315 us | -16% to -18% |
| e2e rhp: 32 pipelined module calls over reliable UDP on 127.0.0.1 | 1.30-1.35 ms | 720-783 us | -42% to -45% |
| bindings rhp: 10k ready async calls | 2.09 ms | 1.28 ms | -39% |
| bindings rhp: 10k reads of bench.speed | 705-832 us | 627-664 us | -11% to -20% |
| bindings rhp: 10k calls of bench.add (held in a local) | 642-664 us | 564-574 us | -12% to -14% |
| bindings rhp: 10k method calls on a handle | 710-733 us | 647-649 us | -9% to -12% |
| events rhp: deliver to 1 / 10 / 100 handlers | 270 ns / 1.68 us / 13.4 us | 219 ns / 1.2 us / 10.5 us | -19% / -29% / -21% |
| events rhp: pump delivering a publish to 10 / 100 handlers | 2.6 / 17.4 us | 1.97 / 13.1 us | -24% / -25% |
| scheduler rhp: pump with 10000 frame callbacks | 2.58 ms | 2.19 ms | -15% |
| scheduler rhp: resume 10000 tasks | 2.33-2.81 ms | 2.26-2.29 ms | about -10% |

The raw twins of the bindings rows, whose code didn't change, moved by up to 15% between the two binaries (code layout), so changes under about 10% are within noise.

Builds (clean `windows-msvc` Debug, 16 threads, `main` and the branch alternating):

| | Before | After |
|---|---:|---:|
| build wall time | 98.6 / 100.1 s | 76.8 / 72.5 s |
| `compile_fail.fixtures_compile` (the as-is fixtures, now in the tests) | (in the build) | 17 s of the ctest run |
