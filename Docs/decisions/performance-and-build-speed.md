# Performance and build speed

The overall optimization pass after Stage 12: everything was benchmarked (`rhp_bench`) and profiled
(VS diagnostics / Windows Performance Toolkit sampling, `-ftime-trace`, `/d1reportTime`, counted
allocations and locks per operation), then the largest costs were taken out. Numbers are in
[benchmarks.md](../benchmarks.md#overall-optimization-pass).

## Runtime

**The cancel hook's per-instruction cost.** With any count hook set, Lua 5.5's VM calls
`luaG_traceexec` before every instruction; for a count that isn't due it only decrements
`hookcount` (and stores the pc). That call was about half the time of loop-heavy code under the
default `cancel_checks = kRequests`. `cmake/lua/lua_cxx.cpp` now spells out onelua.c's include list
and puts an inline count-down in front of `luaG_traceexec` for `lvm.c` only: a count that isn't due
is a decrement; a due count, line events and a hook that yielded go through upstream's function, so
hook calls, the exact instruction meter and hook yields are unchanged. Loops: about 1.85x raw Lua ->
about 1.25x. *Alternatives:* polling a flag at loop back edges and calls (a patch to `lvm.c`,
near-zero cost; RHP doesn't patch upstream sources); arming the hook from the network thread on a
cancel (`lua_sethook` walks `L->ci` while the VM changes it: a data race, and TSan says so).
*Consequence:* the include list must follow onelua.c when Lua is updated (an `#error` on the
release number says so).

**Coroutine yields on x64 MSVC jump** (see [lua-runtime](lua-runtime.md)): the CRT's `longjmp`
skips unwinding when the jump buffer's frame is cleared after `setjmp`. A process with a CET shadow
stack can't take that jump (measured: it dies), so `RDSSP` decides once per process and yields
throw there; `rhp_script_cet_tests` runs the yield tests linked `/CETCOMPAT`. About 20x faster
yields, task resumes and asynchronous bindings on Windows.

**Per call / per event.** No `std::format` on the hot paths (a call's label is built in the pooled
request's string, timer labels with `to_chars`); `drain()` returns before taking its lock when
nothing is queued; timers and frame callbacks in an `unordered_map` (frame callbacks keep creation
order by sorting their keys); an event's handler keys in an inline array; an already-finished
asynchronous result is pushed without the shared call a suspension needs; lib variables of small
trivially copyable types are read with an atomic load (RHP's writes store atomically too; without
`std::atomic_ref` reads keep the lock); a reverted variable write finds its layer from the newest end
(reverts were O(n^2)). *Not done:* resetting `request_record` field by field (about 10% of a frame
callback, but it would break "reset() resets every field" with no portable compile-time guard); a
lock-free patch-point fast path. A layer found for a thread can only be removed by that thread, so
a per-thread cache of the top layer, checked against a version that every push and remove bumps, is
safe; measured, it made no difference to a call into a Lua handler (79-85 ns either way: the
uncontended lock is a small part of it, the handler's request and pcall the rest), so it isn't in.

**The debugger with breakpoints only** runs line events in the functions whose lines hold one
(`scope_lines`, debug.cpp): call and return events switch them, keeping the instruction countdown
(`internals::set_line_events`), and the last answer is cached by source and line range. A C function
runs no Lua lines; returning from one (pcall after a caught error, a coroutine's yield when it
resumes) is a return event, so the Lua function returned to gets its lines back; anything that
can't be told (a chunk named without '@' / '=') keeps them on. A step, a pause or coverage still
watch every line. A loop with a breakpoint elsewhere: 4.4 ms -> 1.0 ms (raw Lua 0.8 ms).

**Wire and session.** `byte_buffer::append` is one `memcpy` (a pmr vector's `insert` copied element
by element on MSVC) and small buffers start at 64 bytes; CRC32C with the CPU instruction runs three
streams over 8 KiB / 256 B blocks combined with compile-time shift tables (Mark Adler's method);
envelopes move their body in and out (`wire::envelope_value`, `wire::take_envelope`); standalone
acks wait `session::options::ack_delay_ms` (5 ms) for an outgoing frame to carry them, so a call
and its reply are two frames instead of four (still at once for every 8th frame, a requested ack and
a duplicate; the protocol is unchanged); the host's cancel-enforcement timer runs only while a cancel
is recorded. *Not done:* a local post queue in `io_context` (a threading review for a few
microseconds on zero-thread hosts), TCP gathered writes, reliable-UDP ack coalescing.

**Signatures.** Ed25519 is deterministic: a process-wide cache of recent script signatures, and of
signatures found valid, keyed by the public key, the signature and the source's BLAKE2b-256, makes a
repeated signed exec sign and verify once. Both are facts about bytes, so a verifier still checks
that it trusts the signer before it looks; a different key, signature or source misses.

## Build

Measured on a clean MSVC Debug build (16 threads, 16 GB): the time went to parsing standard headers
(every file: `<format>`, `<chrono>`, `<filesystem>`, ...), Catch2's own sources, and running out of
memory when every test executable linked at once.

- **One shared precompiled header per group** (`RHP_PCH`, `cmake/RhpPch.cmake`): the libraries above
  core and the test suites reuse one PCH each. A PCH per target cost more than it saved (31 PCH
  compiles, about 190 MB each); `<rhp/rhp.hpp>` stays out (it slowed every PCH). Headers come in
  force-included, so CI's `linux-clang-asan` job builds without it. `rhp_net` and the test suites
  that link Asio compile without it (Asio's macros and `_WIN32_WINNT` can change what the standard
  headers mean), and it is off for clang-cl (it refuses a PCH built with other `/D` macros) and for
  cross builds (not measured there).
- **Catch2 as unity files** (always: it is built once per tree).
- **Links share a Ninja job pool** sized by memory (top-level builds): a link takes 1-2 s alone and
  13-22 s when every core links at once.
- **`RHP_UNITY_BUILD`** (off; CI's `linux-clang` and `windows-msvc` jobs use it): sources whose
  file-local helpers collide keep their own translation unit (`SKIP_UNITY_BUILD_INCLUSION`); the script
  and integration test suites stay file by file (their fixture namespaces share names).
- Fewer standard headers in public headers where the API allows (`<iosfwd>` in `test/cli.hpp`); the
  host event tables are explicitly instantiated once (`event/hub.cpp`); rhp-cli's shell compiles in its
  own file; Catch2 with `CATCH_CONFIG_FAST_COMPILE`; MSVC `/Zc:inline /Gw`, Clang
  `-ffunction-sections -fdata-sections`; clang-cl gets the interpreter's computed-goto dispatch.

*Not done:* LTO by default (measured under 5% on script work, 10-35% on binding calls, variable and property reads
and handle methods, and it ties a static library's objects to one toolchain version: `RHP_LTO` turns it
on); Asio separate compilation (the eight Asio files save about 2 s together, and
an extra file compiles Asio's implementation); `/DEBUG:FASTLINK` (slower here); removing
`<chrono>`, `<filesystem>` and `<future>` from headers whose API uses them.
