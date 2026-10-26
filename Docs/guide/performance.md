# Performance

What RHP costs, which settings change it, and how to build it fast. All numbers come from `rhp_bench` and are listed in [benchmarks](../benchmarks.md); why the code is the way it is, in the [performance decision](../decisions/performance-and-build-speed.md).

## Ship a Release build

Debug builds of RHP and Lua are much slower than Release. Benchmarks and any timing you care about need `Release` (on MSVC, `RelWithDebInfo` inlines less):

```bash
cmake --build --preset windows-msvc --config Release
```

### Link-time optimization (`RHP_LTO`)

`-DRHP_LTO=ON` turns on link-time optimization for RHP's targets (and the dependencies built with them) in `Release`, `RelWithDebInfo` and `MinSizeRel`. It is off by default.

- Gain: 10-35% on binding calls, lib variable and property reads and handle methods; under 5% on pure Lua work.
- Cost: longer links, and LTO objects only link with the same compiler version. An installed RHP package built with LTO ties its consumers to that toolchain.
- A toolchain that can't do it gets a configure warning and a normal build.

## The cancel hook (`limits.cancel_checks`)

A client's `cancel()` stops a running script through Lua's count hook. Which runs have it armed is `limits.cancel_checks`:

| Value | Who checks for `cancel()` | Cost on loop-heavy Lua |
|---|---|---|
| `kRequests` (default) | `exec` / `load` / `call` / `reload` / `rollback`, `rhp.spawn` tasks, and code they call | about 1.2x raw Lua |
| `kEverything` | also timers, frame callbacks, event handlers and patch handlers hit from game code | about 1.2x raw Lua on every handler too |
| `kNone` | nothing: a cancel stops a request only before it starts or resumes | raw Lua |

A count that isn't due is counted down inline, so the default costs about 20%, not the 85-100% it cost before the [optimization pass](../benchmarks.md#overall-optimization-pass). `kNone` now buys only the last few percent; keep the default unless you have measured a need. Setting `limits.instructions`, `wall_ms` or `slice_us` arms the hook for every run whatever `cancel_checks` says.

```cpp
using trusted_cfg = Rhp::config<>::limits<Rhp::limits{.cancel_checks = Rhp::cancel_scope::kNone}>;
```

## Coroutine yields (`RHP_LUA_JUMP_YIELDS`)

Lua is compiled as C++, so a Lua error is a C++ exception. With `RHP_LUA_JUMP_YIELDS=ON` (the default) a yield (`rhp.wait`, `rhp.sleep`, `rhp.next_frame`, a task resuming, an asynchronous binding) is a `_longjmp` instead: tens of nanoseconds rather than microseconds. It applies on Linux, macOS, iOS, Android and x64 Windows. Yields still throw:

- with the MSVC ABI outside x64 (Windows on arm64),
- in a Windows process that runs with a CET shadow stack (detected once per process),
- under ThreadSanitizer.

On x64 Windows 1k yields went from 2.95 ms to 104 us. A C++ binding that yields must hold no object with a destructor at that point; ordinary bindings and `Rhp::async<T>` don't need to care.

## Bindings, events and requests

| Path | Cost (Windows Release, see [benchmarks](../benchmarks.md)) | What to do in a hot loop |
|---|---|---|
| binding call (`game.add(a, b)`) | about 2-3.5x a hand-written `lua_CFunction` | pass a batch to one call instead of many small calls |
| lib variable read (`game.speed`) | tens of nanoseconds (a layer stack under a lock; small trivially copyable types use an atomic load) | read it once into a local, or pass it as an argument |
| handle property (`e.hp`) | one C call per lookup on that handle type, methods included | prefer methods, or cache the value |
| unpatched patch point | one atomic load | nothing to do |
| event delivery | about 275 ns for one handler, then about 130 ns per handler (each handler is a request of its own) | publish less often, or with more data per event |
| `sandbox::call` | a few hundred nanoseconds over a raw `lua_pcall` (a pooled request, a ledger owner, result conversion) | call once per frame, not per object |
| idle `pump()` | under 100 ns; idle timers and sleeping tasks cost nothing until due | nothing to do |

## Signed scripts

Ed25519 signing and checking cost tens of microseconds each. A process-wide cache keeps the 64 most recent script signatures a client made and the 64 most recent ones a host found valid, keyed by public key, signature and the source's BLAKE2b-256. Sending the same source again signs and verifies once: a repeated signed `exec` of a one-line script went from 168 us to 18 us. A host still checks that it trusts the signer before it looks in the cache; a different key, signature or source misses.

## Network

- **Pipelining.** Many calls in flight cost far less than the same calls one after another. Start them with `client.async()` and collect the results afterwards ([host and client](host-and-client.md#async)).
- **Gathered writes.** TCP and IPC links send the frames queued behind a write in flight in one gathered write (up to 16 frames). WebSocket joins them into one message. 32 pipelined calls over TCP on `127.0.0.1` take 374-401 us instead of 632-635 us.
- **Delayed acks.** A standalone ack waits up to 5 ms for an outgoing frame to carry it, so a call and its reply are two frames instead of four. Acks still go at once for every 8th unacknowledged frame, a frame that asks for one, and a duplicate. This is `session::options::ack_delay_ms` in the session layer; hosts and clients use the default. The protocol is unchanged.
- **Reliable UDP** recovers loss by retransmission; on a clean link it is slower than TCP (32 pipelined calls: about 1.3 ms). Prefer TCP unless only UDP gets through.
- **DNS-SD.** RHP's own responder answers a query with the records it asked for and puts the rest in the additional section (RFC 6763 §12). Windows now resolves a record RHP publishes in about 2.7 s (it took 24-41 s before).

## Tools

- **Debugger.** With nothing set it costs nothing. With breakpoints only, line events run only in functions whose lines hold a breakpoint: a 100k loop with a breakpoint elsewhere takes 1.0 ms (4.3 ms before the optimization pass), about what it takes with no debugger. Call-heavy code still pays a call and a return event per call (`fib(22)` about 2x). A step or a pause watches every line until it ends; clear breakpoints when you stop debugging.
- **Profiler.** One stack walk per sample. At the default interval (1000 instructions) it is close to free on loops and about 10% on call-heavy code; at 100 the stack walks show (deep recursion about 2.4x).
- **Coverage** in the test runner costs about 2-3x on line-dense code; turn it on for coverage runs only.

## Build speed

| Option | Default | Effect |
|---|---|---|
| `RHP_PCH` | on for top-level desktop builds, off for cross builds and clang-cl | one shared precompiled header for the libraries above `core` and one for the test suites |
| `RHP_UNITY_BUILD` | off | unity files (16 sources each): about a third less wall time on clean builds, slower edits. CI's `linux-clang` and `windows-msvc` jobs use it |
| link job pool | top-level Ninja builds | links share a pool sized by memory; linking every test at once otherwise runs out of memory |

A clean `windows-msvc` Debug build of everything takes about 111 s on a 16-thread laptop (106 s with `RHP_UNITY_BUILD`). A source that forgets an `#include` may still compile under the shared PCH; CI's `linux-clang-asan` job builds without it.

## Measuring your own case

```bash
cmake --preset windows-msvc -B build/bench -DRHP_BUILD_BENCH=ON
cmake --build build/bench --config Release --target rhp_bench
build/bench/Tests/bench/Release/rhp_bench "[bench]" --reporter xml::out=bench.xml
python Tools/bench/summarize.py bench.xml
```

`Tools/bench/compare.py a.xml b.xml` diffs two runs. Pin the process to one core and treat differences under 10% as noise unless they repeat. For scripts, the test engine measures exact instruction counts and memory per test ([testing scripts](testing-scripts.md#measuring)); the [profiler](tools.md#profiler) shows where a running program's scripts spend their instructions.
