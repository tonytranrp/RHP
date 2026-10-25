#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/value.hpp>
#include <rhp/script/debug.hpp>
#include <rhp/script/testing.hpp>

namespace Rhp::test {

enum class status : std::uint8_t {
    kPassed,
    kFailed,  // an assertion failed
    kError,   // anything else went wrong (an error, a limit, a leak, a setup that failed)
    kPending, // pending(), or a test without a body
    kSkipped  // it.skip / describe.skip, or left out by .only
};

[[nodiscard]] constexpr std::string_view to_string(status s) noexcept {
    switch (s) {
    case status::kPassed: return "passed";
    case status::kFailed: return "failed";
    case status::kError: return "error";
    case status::kPending: return "pending";
    case status::kSkipped: return "skipped";
    }
    return "unknown";
}

// What one test's Lua cost, from the request that ran it (hooks included). Memory figures are
// bytes; `peak` is above what was in use when the test started, `retained` what stays after a full
// collection (0 with --no-measure).
struct metrics {
    std::uint64_t instructions = 0;
    double time_ms = 0; // time Lua ran
    double wall_ms = 0; // real time the runner spent on the test (pumps and clock steps included)
    std::uint64_t allocations = 0;
    std::uint64_t bytes = 0;
    std::uint64_t peak = 0;
    std::int64_t retained = 0;
    std::array<std::uint64_t, script::kAllocKinds> objects{};
    std::uint64_t frames = 0; // pump() calls the test needed
};

// test.measure(fn) inside a test.
struct measure {
    std::string name;
    std::uint64_t instructions = 0;
    std::uint64_t allocations = 0;
    std::uint64_t bytes = 0;
    std::int64_t peak = 0;
    std::int64_t retained = 0;
    double time_ms = 0;
};

struct stats_line {
    double min = 0;
    double max = 0;
    double mean = 0;
    double median = 0;
    double stddev = 0;
};

// test.bench(name, fn) inside a test.
struct bench {
    std::string name;
    std::uint32_t runs = 0;
    stats_line instructions;
    stats_line time_ms;
    stats_line bytes;
    stats_line allocations;
};

struct test_result {
    std::uint64_t id = 0;   // within its file
    std::string name;       // the full name ("combat spawns a boss")
    std::string file;       // the test file, relative to the run's root
    std::uint32_t line = 0; // where it is declared
    std::vector<std::string> tags;
    status outcome = status::kPassed;
    std::string message; // why it failed, errored or is pending
    std::string where;   // "tests/x_spec.lua:12": where it failed
    std::string fail_file;
    std::uint32_t fail_line = 0;
    std::string traceback;
    std::optional<std::string> expected; // for editors' diff views
    std::optional<std::string> actual;
    std::uint64_t assertions = 0;
    metrics cost;
    std::vector<measure> measures;
    std::vector<bench> benches;
    std::vector<std::string> output;            // what the scripts printed during the test
    std::vector<std::string> notes;             // warnings: irreversible effects, slow budget, ...
    std::vector<script::profile_stack> profile; // with --profile
    std::uint32_t repeat = 0;                   // which run of --repeat (0: the first)
};

// An error outside any test: a test file that doesn't compile, a describe body or a teardown that
// failed, a module that didn't load.
struct file_error {
    std::string message;
    std::string file;
    std::uint32_t line = 0;
    std::string traceback;
};

struct file_result {
    std::string file;
    std::vector<test_result> tests;
    std::vector<file_error> errors;
    double ms = 0;
};

struct counts {
    std::size_t passed = 0;
    std::size_t failed = 0;
    std::size_t errors = 0;
    std::size_t pending = 0;
    std::size_t skipped = 0;
    std::size_t file_errors = 0;

    [[nodiscard]] std::size_t total() const noexcept { return passed + failed + errors + pending + skipped; }
    [[nodiscard]] bool ok() const noexcept { return failed == 0 && errors == 0 && file_errors == 0; }
};

// Line coverage of one source file.
struct file_coverage {
    std::string file;                 // relative to the run's root
    std::vector<std::uint32_t> lines; // executable lines (exclusions removed)
    std::vector<std::uint64_t> hits;
    [[nodiscard]] std::size_t covered() const noexcept {
        std::size_t n = 0;
        for (const std::uint64_t h : hits) {
            n += h != 0 ? 1 : 0;
        }
        return n;
    }
};

struct run_result {
    std::vector<file_result> files;
    counts totals;
    std::uint64_t seed = 0;
    double ms = 0;
    std::vector<file_coverage> coverage;        // with --coverage
    std::vector<script::profile_stack> profile; // every test's samples together, with --profile
    std::vector<std::string> notes;             // obsolete snapshots, ...
};

} // namespace Rhp::test
