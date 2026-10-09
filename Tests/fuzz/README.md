# fuzz

| Target | Input | Checks |
|---|---|---|
| `frame` | a byte stream, cut into pieces by its first byte | every frame the decoder reports is in bounds and decodes again identically once re-encoded; oversized lengths stop the stream |
| `msgpack` | MessagePack bytes | decoding fails cleanly or the value's encoding round-trips byte for byte (depth and element limits hold) |
| `envelope` | MessagePack bytes | every wire message type that accepts the value gives back one it accepts again, unchanged |
| `sandbox_escape` | Lua source, run as an observe identity (instruction, memory, wall limits) | the host's variable is untouched; `io`, `debug`, `package`, `dofile`, `loadfile`, `string.dump` stay hidden from a fresh module; no crash |

Every build has replay drivers (`rhp_fuzz_<target>_replay`) that ctest runs as `fuzz.<target>`: the seeds, then 3000 deterministic mutations. Replay a crash file with `rhp_fuzz_<target>_replay crash-file`.

Long runs need Clang's libFuzzer (Linux):

```bash
cmake --preset linux-clang-fuzz
```

```bash
cmake --build --preset linux-clang-fuzz
```

```bash
build/linux-clang-fuzz/Tests/fuzz/RelWithDebInfo/rhp_fuzz_frame_replay --write-corpus corpus/frame
```

```bash
build/linux-clang-fuzz/Tests/fuzz/RelWithDebInfo/rhp_fuzz_frame -max_total_time=300 corpus/frame
```

Found so far: `sandbox_escape` — returning a deeply nested table overran the Lua C stack (fixed with `lua_checkstack`, regression test in `unit/script/sandbox_tests.cpp`).
