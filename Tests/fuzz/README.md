# fuzz

| Target | Input | Checks |
|---|---|---|
| `frame` | a byte stream, cut into pieces by its first byte | every frame the decoder reports is in bounds and decodes again identically once re-encoded; oversized lengths stop the stream |
| `msgpack` | MessagePack bytes | decoding fails cleanly or the value's encoding round-trips byte for byte (depth and element limits hold) |
| `envelope` | MessagePack bytes | every wire message type that accepts the value gives back one it accepts again, unchanged |
| `sandbox_escape` | Lua source, run as an observe identity (instruction, memory, wall limits) | the host's variable is untouched; `io`, `debug`, `package`, `dofile`, `loadfile`, `string.dump` stay hidden from a fresh module; no crash |
| `network` | HTTP heads, multicast DNS packets, WebSocket frame headers, reliable-UDP packets | each parser refuses or bounds what it accepts (header / body lengths, field and record counts, decoded names); malformed input fails cleanly |
| `release` | release envelopes, revocation lists, manifest bodies | whatever decodes encodes back to bytes that decode to the same thing; a manifest body that decodes is canonical (it encodes to exactly the bytes it came from) |

Every build with `RHP_ENABLE=ON` has replay drivers (`rhp_fuzz_<target>_replay`, `replay_main.cpp`) that ctest runs as `fuzz.<target>` (label `fuzz`): the seeds, every file named on the command line, then `--iterations` deterministic mutations (3000 under ctest: byte flips, inserts, deletes, duplicated ranges, splices, boundary bytes).

```bash
ctest --preset windows-msvc -L fuzz
build/windows-msvc/Tests/fuzz/Debug/rhp_fuzz_frame_replay crash-file      # replay one input
```

Long runs need Clang's libFuzzer (`RHP_FUZZ=ON`, Linux): it adds `rhp_fuzz_<target>` executables built with `-fsanitize=fuzzer` (the preset adds ASan and UBSan). `--write-corpus <dir>` writes a replay driver's seeds out as the starting corpus.

```bash
cmake --preset linux-clang-fuzz
cmake --build --preset linux-clang-fuzz
build/linux-clang-fuzz/Tests/fuzz/RelWithDebInfo/rhp_fuzz_frame_replay --write-corpus corpus/frame
build/linux-clang-fuzz/Tests/fuzz/RelWithDebInfo/rhp_fuzz_frame -max_total_time=300 corpus/frame
```

A new target: a `<name>_fuzz.cpp` with `LLVMFuzzerTestOneInput`, `rhp_fuzz_seeds()` and its invariants as `RHP_FUZZ_CHECK` (`fuzz_support.hpp`), one `rhp_add_fuzz(<name> SOURCE ... LINKS ...)` line in `CMakeLists.txt`, and a row here.

Found so far: `sandbox_escape` — returning a deeply nested table overran the Lua C stack (fixed; regression test `sandbox: returning deeply nested tables never overruns the Lua stack` in `unit/script/sandbox_tests.cpp`).
