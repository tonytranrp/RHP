#pragma once

// What every fuzz target provides. The same source builds two ways:
//   RHP_FUZZ=ON (Clang)  a libFuzzer executable: `rhp_fuzz_frame -max_total_time=60 corpus/`
//   otherwise            a replay driver (replay_main.cpp) that ctest runs: the seeds, then a few
//                        thousand deterministic mutations of them
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

// Well-formed (and some deliberately odd) inputs the mutations start from.
std::vector<std::string> rhp_fuzz_seeds();

// An invariant the target checks; a violation aborts, which both drivers report as a crash.
#define RHP_FUZZ_CHECK(cond)                                                                       \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            std::fprintf(stderr, "fuzz invariant failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            std::abort();                                                                          \
        }                                                                                          \
    } while (false)
