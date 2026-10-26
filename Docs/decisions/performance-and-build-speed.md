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

**Safe points (the Lua speed pass, superseding the line above about patching).** Even counted down
inline, a count hook still made the VM trap before every instruction (and reload its base after
each), about 1.1-1.5x raw Lua on loops and calls. A cancel or a limit needs a bound, not an exact
count: straight-line code is bounded by its function's size, so only loops and calls can run long.
`cmake/RhpLua.cmake` now copies `lvm.c` into the build tree with four charges added (`dojump` with a
negative offset, `OP_FORLOOP`, `OP_TFORLOOP`, function entry), each replacement required to match
exactly once (configure fails on a Lua update that moves one). `internals::set_safepoint_hook` sets
the hook function and count with no mask, so the VM runs as without a hook; when a charge uses the
count up, the hook is armed for one instruction (`LUA_MASKCOUNT` plus a bit above lua_sethook's byte)
and fires through upstream's `luaG_traceexec`, so errors, yields and `CIST_HOOKYIELD` are unchanged;
`rhp_lua_traceexec` then returns to safe points. *Semantics:* `limits.instructions` charges a loop
iteration its body's length and a call 1 (forward branches inside a loop and the `MMBIN`
fallback after each arithmetic instruction, skipped when the operands are numbers, are over-counted:
an arithmetic loop is charged up to about 1.5-1.7x what it runs; straight-line code outside loops
isn't counted); the meter, the profiler and line events keep exact
per-instruction counting (`sandbox_impl::install_hook`). An unchecked run pays one subtraction per
loop iteration. *Alternatives:* keeping upstream untouched (the earlier choice: about 1.1-1.5x);
weighting calls by their function's size (over-counts functions that return early, and recursion is
already bounded by the call charge); arming from another thread on cancel (the data race above).

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
(reverts were O(n^2)). `request_record` is `request_state` plus its three pooled strings: `reset()`
assigns the state whole and clears the strings, and a `static_assert` on the sizes keeps every new
field inside `request_state` (the guard a field-by-field reset lacked). A binding call reads its label
and context only when an error, an undo record or an async call needs them (observe bindings skip the
role check); lib variable getters, C functions without upvalues, run in the proxy's frame instead of
a nested `lua_call`; `Rhp::async<T>::completed()` keeps its outcome inline (no shared state, mutex or
`std::function` for an operation that is already over); event delivery looks the subscription list
up again only after a subscription was added or removed. *Not done:* a lock-free patch-point fast path. A layer found for a thread can only be removed by that thread, so
a per-thread cache of the top layer, checked against a version that every push and remove bumps, is
safe; measured, it made no difference to a call into a Lua handler (79-85 ns either way: the
uncontended lock is a small part of it, the handler's request and pcall the rest), so it isn't in.

**Binding calls and lib members.** A *plain* binding (synchronous, no `undo<G>` / `irreversible`,
every parameter a bool, integer, floating point number, `std::string_view` / `std::string` or handle)
takes `call_plain`: one out-of-line `stack::read_args` reads every plain argument by type into an
`arg_slot` (no `Rhp::result<T>` per argument), handles are pulled as before, then the call,
exceptions and `push_return` as on the general path. An argument that doesn't fit falls back to the
general path, which raises the error it always did, so the two can't disagree (a test calls both
with every kind of bad argument). Properties are C functions without upvalues with a compile-time
label, run in their handle's `__index` frame instead of a nested `lua_call`; `lib_var_index` takes
the key where the VM left it. Measured in one binary (twins forced down the general path, so code
layout is the same): two `int` arguments -27%, a method with only its handle -6% to -13%, a handle
and an `int` -4% to -11%. Across binaries the call rows moved -20% to -30%, properties -8% to -10%;
variable reads did not move beyond noise. *Remaining cost:* a plain call of `add` is about 1.3-1.4x
a hand-written `lua_CFunction` without the cancel hook: the trampoline's frame, the out-of-line reader,
two API calls per argument (the type, then the value: `luaL_checkinteger` makes one and also takes
`"1"`), the push through `stack`. A function lookup through a lib is a table-valued metamethod (the
proxy is userdata); in a module, the lib's own name is a miss in the module's `_ENV` and a hit in its
`__index` (the sandbox's environment, not the binding layer). A variable read is a C call (about
100 cycles more than a table field): raw-Lua models of the proxy (the current shape; one C `__index` for everything; the current
shape without the getter check) put the floor there. *Rejected:* a table as the lib proxy, with
functions as its own fields (a lookup with no metamethod): Lua calls `__newindex` only for absent
keys, so `game.spawn = f` would replace a shared function without a journal entry. One C `__index`
on the proxy for variables and functions: no faster for reads, and every function lookup becomes a C
call. Calling any upvalue-free C getter in place without checking it (about 15% off a read in the
model): a test's swapped-in C closure would read `lib_var_index`'s upvalues (a crash for one like
`string.gmatch`'s iterator). Caching variable values in the lib: C++ writes them at any time,
including inside a binding the script just called. Copying `ro` members of `const` objects into the
lib: a `const T*` template argument can point at a mutable variable, so the copy could go stale (an
explicit constant entry would be sound; it would be new API, stubs, `api()` and test-bridge work).
Handle metatables looked up by the address of their static key (`lua_rawgetp` on the registry):
slower, since Lua hashes a light userdata with a modulo by the table size, more than its string cache
and a short-string lookup. Declaring Lua API functions in headers so templates call
`lua_tointegerx` directly: it breaks the `stack` wall and `RHP_ENABLE=OFF`. *Measuring:* wall-clock
runs on a busy machine moved by up to 30%; thread cycle counts (`QueryThreadCycleTime`, the lowest of
300 runs, binaries alternating) still moved unchanged raw rows by 10-15% between two builds (code
layout), hence the twins inside one binary.

**Lua's allocator.** Every Lua allocation went through `malloc` / `realloc` / `free` (or the pmr
resource) after walking the run stack for the innermost budget. The innermost budget is now cached
(`budget_`, kept by `active_scope`), and blocks up to 128 bytes come from `small_alloc`
(`puc_lua/small_alloc.{hpp,cpp}`): per-size-class slabs of 4 KiB, carved from 64 KiB regions aligned
to 4 KiB (from the pmr resource when one is given, else the aligned global `operator new`), so an
allocation pops a slab's free list or bumps its never-used part, and a free finds its slab by
masking its address. The classes were measured: a Lua 5.5 table is 48 bytes, a closure with one
upvalue 40, an upvalue 40, a short string 24 + length + 1, small array and node parts 13-48; every
8 bytes up to 64, then 80 / 96 / 112 / 128 (every 16 where blocks need 16-byte alignment). Where a
block lives follows from the size Lua passes back, so nothing is looked up; a small block shrinking
to another class moves when there is room and otherwise stays (a slab frees by address), so a
shrink never fails. Accounting, the limit, the sticky stop and the meter are in Lua's sizes,
unchanged. A slab that empties goes to a pool of empty slabs, which every class takes from first;
a region whose slabs are all empty is given back once the pool holds 8 spare slabs besides it (a
live set hovering at a region boundary doesn't get and free a region over and over). Keeping each
class's last slab instead (no pool round trip when a class's live count touches zero) was tried
and dropped: one kept slab per class could pin a region each after a peak. No pooling under AddressSanitizer
(`__SANITIZE_ADDRESS__` / `__has_feature`), so a use after free in a Lua object is still caught.
On a loaded machine, as the ratio to the raw twin (`luaL_newstate`'s `realloc`) within each of
four alternating runs: `10k closures` 1.16-1.32x -> 0.62-0.80x (unchecked 1.06-1.38x ->
0.42-0.68x), the new `10k small tables` 0.49-0.65x, `exec return 1` 1.24-1.48x -> 0.82-0.90x; table
fill (its arrays are large blocks), strings, calls, the scheduler and the requests moved within
noise. *Rejected:* free lists that never give
memory back (simpler, but a script's peak would stay with the sandbox until it closes); a header
word per block for its slab (8 bytes on 40-byte objects); slabs aligned to their own size through the
C heap (MSVC's aligned `malloc` costs a whole alignment per block: 2x for 4 KiB slabs); pooling under
ASan with poisoning (more code than the pass-through it replaces, for a build that measures nothing).

**Garbage collection.** A new `lua_State` collects incrementally (only the standalone `lua`
interpreter switches to generational), so sandboxes always have; `sandbox_options::gc` now picks
the mode at creation (default unchanged: incremental). `sandbox::collect_idle(budget)` gives the
collector slack time: in incremental mode `LUA_GCSTEP` steps until the budget is spent or the
cycle ends; in generational mode one step, since a step there is a whole minor collection and a
second one in a row finds nothing new. Measured with the hidden `[gc]` case (1000 frame callbacks
making garbage, 200k live tables, medians of 7 interleaved rounds, two runs on a loaded machine):
incremental p99 / max pump 9.4-16.7 / 34.7-44.5 ms, with `collect_idle(250us)` 5.8-6.6 / 8.6-9.4
ms for 0.44 ms of idle work and a higher median pump (cycles back to back keep the write barriers
on); generational 9.1-9.4 / 13.2-16.4 ms with the lowest mean (1.25-1.59 ms against 1.57-2.62),
and with idle steps 2.3-2.9 / 3.3-6.0 ms but 1.6-1.8 ms of idle work per frame (each minor
collection walks the 200k-entry table the scripts write to). With no live heap the modes are within
noise. So `collect_idle` is an explicit call (the application knows its frame's slack; `pump()`
doesn't), and the default mode stays incremental: generational won on this one workload, on a
noisy machine, by an amount that depends on how old data is written, and a mode change moves
every finalizer's timing and what the test engine measures; it is one option away. *Not done:* stepping inside `pump()` when it ran little (pump can't tell how
much of the frame is left); a host option (host_options would need to carry it to each identity's
sandbox).

**`sandbox::call` and event deliveries.** Profiled with `__rdtsc` marks along the path (an empty
call, two integer arguments, one result): about a fifth of a call converted its result (the vector's
allocation and a `result<value>` per value), a sixth each went to the `pcall` that protects the setup
and to looking the function up and pushing the arguments, an eighth to `lua_resume` with the
function itself, and about a quarter to the request record (pool, `reset()`, label, hook arming,
insertion into and removal from the scheduler's `std::map`, closing). A delivery's handler paid the
same record costs each. What changed: a request enters `requests_` only when it first suspends (its
map node waits in `unlisted_`; tasks are listed at once), so a call, exec, timer or handler that
finishes in its first step never touches the map, and a finished request no longer marks the
scheduler dirty; the handlers of one delivery run in one record and coroutine while they return
normally (`restart_request`: each its own request id, owner, budget and policy, so a `report` undoes
only that handler's effects through the ledger's per-request revert, as before); results that are
nil, booleans or numbers convert in place; and `call_unprotected` runs a call's setup without the
`pcall` when nothing in it can raise (an interned name pinned in the registry, exports without a
metatable, scalar arguments, a spare record and coroutine, capacity in every container), leaving
anything but a normal return with scalar results to a protected run as before. That last one means
the main state may have no protected run while a call's coroutine runs, so nothing may raise there
meanwhile: `rhp.spawn` now makes a new coroutine on the spawning one (a test aborted without it).
Measured on a loaded machine (other builds and benchmarks running; min to max of the means of four
alternating runs, main against this): a call with two arguments 402-883 ns -> 304-499 ns, an empty
call 435-686 ns -> 385-588 ns, a delivery to 100 handlers 12.8-17.2 us -> 9.7-13.5 us, a pump
delivering a publish to 100 handlers 17.1-21.6 us -> 11.3-15.6 us; a delivery to one handler showed
no clear change (235-345 ns -> 257-358 ns). *Not done:* running all of a delivery's handlers in one
`lua_resume` (a C function calling each through `lua_pcallk`): a handler may suspend, and a C frame
under every handler would show in tracebacks, the debugger's stacks and the profiler's samples; per
handler, the resume is a smaller part than the record. A ledger checkpoint per handler instead of a
request id: a deferred `report` would also undo what later handlers and nested deliveries recorded
after the mark. Skipping `arm_hook` for a reused coroutine whose hook is already off: it restarts the
countdown a budget is measured by, and the hook functions are being reworked separately. The
remaining costs per call are the result vector's allocation (the API returns a `value_list`),
`lua_resume`, the operation scope's two `lua_sethook` calls and the record's bookkeeping.

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
is recorded. The TCP and IPC links send the frames queued behind a write in flight in one gathered
write (up to 16; WebSocket already joins them into one message): 32 pipelined calls over TCP on
127.0.0.1 take 374-401 us instead of 632-635 us. *Measured and left out:* a local queue for posts made on the
running thread (one reactor post per batch instead of one each: module calls, signed execs and 32
pipelined calls over TCP and UDP all stayed within run-to-run noise), and posting each reliable-UDP
ACK to the end of the I/O round (1.33-1.35 ms against 1.27-1.28 ms: each datagram was its own
receive completion, so the posted ACK ran before the next one arrived). What works instead: a
receive drains the datagrams already waiting (up to 64) and then acknowledges once per peer, unless
a packet sent meanwhile carried the ACK; queued sends share packets (the payload is a byte stream);
an in-order packet with nothing buffered goes straight to the handler. 32 pipelined calls over
reliable UDP: 1.30-1.35 ms -> 0.72-0.78 ms. Sending each burst from a posted flush (frames sent in
one turn share datagrams) was left out: a reply would wait for the host's next pump. A sequenced
frame's payload moves into the session's resend window and is sent from there (one copy fewer).

**Frame MAC.** Keyed BLAKE2b hashes the padded key as its first block, and Monocypher compresses it
once message bytes follow. Every frame starts with the frame magic, so a sealer keeps the state
after the key and the magic and copies it per frame: identical MACs, one compression fewer of the
2-3 a call's frame takes (the MACs were about a quarter of a remote call). A module call over
loopback: 12.4-12.9 us -> 11.0-11.1 us together with the binding changes.

**Signatures.** Ed25519 is deterministic: a process-wide cache of recent script signatures, and of
signatures found valid, keyed by the public key, the signature and the source's BLAKE2b-256, makes a
repeated signed exec sign and verify once. Both are facts about bytes, so a verifier still checks
that it trusts the signer before it looks; a different key, signature or source misses.

**mDNS answers.** The wire responder answers a query with the records it asked for in the answer
section and the rest in the additional section (RFC 6763 §12), as Windows' own responder does;
announcements keep every record in the answer section. Windows' `DnsServiceResolve` did not take an
SRV or TXT that arrived among unasked answers: it re-asked about 40 times a second and the responder
answered each (1,667 responses in one run), so resolving a record published by RHP took 24-41 s.
Now it takes 2.7 s, with 42 responses. Ruled out on the way, each measured: legacy unicast and QU
queries, the `127.0.0.1` address, answering on every IPv4 interface, a single-label host name, NSEC
records, and moving every non-PTR record to the additional section (Windows then never resolved).

## Build

Measured on a clean MSVC Debug build (16 threads, 16 GB): the time went to parsing standard headers
(every file: `<format>`, `<chrono>`, `<filesystem>`, ...), Catch2's own sources, and running out of
memory when every test executable linked at once.

- **One shared precompiled header per group** (`RHP_PCH`, `cmake/RhpPch.cmake`): the libraries above
  core, the test suites, and the apps (examples, rhp-cli, the fuzz replay drivers) reuse one PCH each,
  with the standard headers and RHP's core and utils headers (those alone: -27% over 24 sources). A
  PCH per target cost more than it saved (31 PCH compiles, about 190 MB each); `<rhp/rhp.hpp>` stays
  out (it slowed every PCH). Headers come in
  force-included, so CI's `linux-clang-asan` job builds without it. The translation units that include
  Asio compile apart from it (Asio's macros and `_WIN32_WINNT` can change what the standard headers
  mean): `rhp_net_asio`, an OBJECT library folded into `rhp_net`, with an Asio precompiled header of
  its own (not `mdns/native.cpp`, which defines `UNICODE` before `<windows.h>`), and the net tests'
  relay; the rest of `rhp_net` and `rhp_net_tests` share the library and test headers (a clean MSVC
  Debug build: 72.5-74.6 s -> 69.7-69.8 s), and it is off for clang-cl (it refuses a PCH built with other `/D` macros) and for
  cross builds (not measured there).
- **Catch2 as unity files** (always: it is built once per tree).
- **The compile-fail fixtures build in their tests**: one test (`compile_fail.fixtures_compile`)
  builds every as-is fixture in one build run, and the failing builds wait for it; in the default
  build the 34 objects were 13% of the work. The fuzz replay main compiles once.
- **Links share a Ninja job pool** sized by memory (top-level builds): a link takes 1-2 s alone and
  13-22 s when every core links at once.
- **`RHP_UNITY_BUILD`** (off; CI's `linux-clang` and `windows-msvc` jobs use it): sources whose
  file-local helpers collide keep their own translation unit (`SKIP_UNITY_BUILD_INCLUSION`); the script
  and integration test suites stay file by file (their fixture namespaces share names).
- Fewer standard headers in public headers where the API allows (`<iosfwd>` in `test/cli.hpp`); the
  host event tables are explicitly instantiated once (`event/hub.cpp`); rhp-cli's shell compiles in its
  own file; Catch2 with `CATCH_CONFIG_FAST_COMPILE`; MSVC `/Zc:inline /Gw`, Clang
  `-ffunction-sections -fdata-sections`; clang-cl gets the interpreter's computed-goto dispatch.

*Not done:* `lld-link` (about 40% faster links, but not part of a default Visual Studio install:
`-DCMAKE_LINKER_TYPE=LLD` with CMake 3.29+ where it is); making rhp-cli's `extern template` of its
shell effective (every member is defined in the class, so the explicit instantiation saves nothing;
moving about 900 lines out of the class would save about 1 s of the critical path); LTO by default (measured under 5% on script work, 10-35% on binding calls, variable and property reads
and handle methods, and it ties a static library's objects to one toolchain version: `RHP_LTO` turns it
on); Asio separate compilation (the eight Asio files save about 2 s together, and
an extra file compiles Asio's implementation); `/DEBUG:FASTLINK` (slower here); removing
`<chrono>`, `<filesystem>` and `<future>` from headers whose API uses them.
