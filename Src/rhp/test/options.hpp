#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::test {

// How much each test shares with the others of its file.
enum class isolation : std::uint8_t {
    kFile, // one sandbox per test file; each test's effects are undone after it (module globals stay)
    kTest  // a fresh sandbox per test (the modules and the file loaded again for each)
};

enum class report_kind : std::uint8_t {
    kText,  // for people (the default)
    kTap,   // TAP version 14
    kJunit, // JUnit XML (GitLab, Jenkins, GitHub report actions)
    kJson,  // one JSON event per line (editors: the VS Code extension)
    kGithub // GitHub Actions annotations (::error file=...)
};

enum class coverage_kind : std::uint8_t {
    kSummary,  // a table in the text report
    kLcov,     // lcov.info
    kCobertura // Cobertura XML
};

// A report and where it goes (empty path: standard output).
struct report_spec {
    report_kind kind = report_kind::kText;
    std::filesystem::path path{};
};

struct coverage_spec {
    coverage_kind kind = coverage_kind::kSummary;
    std::filesystem::path path{};
};

struct run_options {
    // Test files, or folders searched for *_spec.lua, *.spec.lua, *_test.lua and test_*.lua.
    std::vector<std::filesystem::path> tests{};
    // Folders of modules loaded into every test sandbox (scripts/game/combat.lua -> game.combat;
    // scripts/game/init.lua -> game), in the order their require()s need.
    std::vector<std::filesystem::path> scripts{};
    // Paths in reports are relative to this folder (default: the current one).
    std::filesystem::path root{};

    // Selection: full names containing a filter (a /regex/ between slashes), tags (#name in names).
    std::vector<std::string> filters{};
    std::vector<std::string> filters_out{};
    std::vector<std::string> tags{};
    std::vector<std::string> exclude_tags{};
    std::optional<std::uint64_t> seed{}; // random order, property and fuzz inputs (default: from the clock, printed)
    bool shuffle = false;
    std::uint32_t repeat = 1;
    bool fail_fast = false;

    isolation share = isolation::kFile;
    role caller = role::kPatch;                // the role the scripts get (what the real program gives them)
    Rhp::limits limits{};                      // per test request (instructions, memory, wall_ms ...)
    std::chrono::milliseconds timeout{10'000}; // real time per test before it is cancelled
    std::uint64_t max_frames = 10'000;         // pump() calls one test may take
    std::int64_t epoch = 1'700'000'000;        // os.time() when a test file starts (the clock is fake)

    bool measure = true;      // full collections around each test (retained memory)
    bool strict_undo = false; // irreversible effects fail tests
    bool profile = false;
    std::uint32_t profile_interval = 1000;
    std::filesystem::path profile_out{}; // folded stacks of every test together
    std::vector<coverage_spec> coverage{};
    bool coverage_tests = false; // the test files' own lines in coverage too

    bool ci = false; // new snapshots fail instead of being stored
    bool update_snapshots = false;
    std::optional<std::uint64_t> fuzz_ms{}; // test.fuzz runs for this long instead of a number of inputs
    std::uint32_t property_runs = 100;

    std::optional<value> api{}; // fake the libs of this description (rhp-cli test --api)
    bool strict_fakes = false;

    std::vector<report_spec> reports{};
    bool list_only = false;
    std::optional<bool> color{}; // default: when standard output is a terminal
    bool verbose = false;        // every test's line and costs in the text report
};

// Parsed command line of a test executable or `rhp-cli test`.
struct cli_options {
    run_options run;
    std::filesystem::path dump_api{}; // write the installed API description and exit
    std::filesystem::path api_file{}; // --api
    bool help = false;
};

// Parses arguments (without the program name). kInvalidArgument names the bad one.
[[nodiscard]] result<cli_options> parse_args(std::span<const std::string_view> args);

// The --help text.
[[nodiscard]] std::string usage(std::string_view program);

} // namespace Rhp::test
