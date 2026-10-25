#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/test/options.hpp>

namespace Rhp::test {

namespace {

std::vector<std::string> split_list(std::string_view text) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = std::min(text.find(',', start), text.size());
        if (end > start) {
            out.emplace_back(text.substr(start, end - start));
        }
        if (end >= text.size()) {
            break;
        }
        start = end + 1;
    }
    return out;
}

template <class T>
std::optional<T> number(std::string_view text) {
    T v{};
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
    if (ec != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return v;
}

// "kind" or "kind:path".
std::pair<std::string, std::string> kind_and_path(std::string_view text) {
    // A Windows drive ("c:\...") belongs to the path: only a colon after two characters splits.
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos || colon < 2) {
        return {std::string{text}, {}};
    }
    return {std::string{text.substr(0, colon)}, std::string{text.substr(colon + 1)}};
}

} // namespace

std::string usage(std::string_view program) {
    return std::format(R"(usage: {} [options] [test files or folders...]

Runs Lua test files (describe / it / assert / expect, busted style) against this program's API,
offline. Folders are searched for *_spec.lua, *.spec.lua, *_test.lua and test_*.lua.

  -s, --scripts DIR          modules to load (DIR/game/combat.lua is module game.combat); repeatable
  -f, --filter TEXT          run tests whose full name contains TEXT (/regex/ for a regex); repeatable
      --filter-out TEXT      leave out tests whose full name contains TEXT
  -t, --tags A,B             only tests tagged #A or #B
      --exclude-tags A,B     leave out tests tagged #A or #B
      --seed N               order (with --shuffle), property and fuzz inputs; printed every run
      --shuffle              random test order within each file
      --repeat N             run every test N times
      --fail-fast            stop at the first failure
      --isolation file|test  one sandbox per file (default) or per test
      --role observe|patch|admin   the role scripts run with (default patch)
      --timeout MS           real time one test may take (default 10000)
      --max-frames N         pump() calls one test may take (default 10000)
      --instructions N       instruction limit of each test request
      --memory BYTES         memory limit of each test sandbox
  -r, --reporter KIND[:FILE] text, tap, junit, json, github; repeatable (stdout gets text unless one has no FILE)
  -v, --verbose              every test's line with its costs
      --coverage KIND[:FILE] summary, lcov, cobertura; repeatable
      --coverage-tests       count the test files' own lines too
      --profile[=N]          sample every N instructions (default 1000); costs per test in reports
      --profile-out FILE     every test's samples as folded stacks (flamegraph.pl, speedscope)
      --no-measure           skip the collections around each test (faster; no retained memory)
      --strict-undo          irreversible effects fail tests
      --ci                   never store new snapshots: a missing one fails
  -u, --update-snapshots     store every snapshot as it is now
      --fuzz MS              each test.fuzz runs for MS milliseconds of Lua time
      --property-runs N      cases per test.property (default 100)
      --api FILE.json        fake the libs this description lists (rhp-cli test, --dump-api)
      --strict-fakes         fakes raise for calls nothing configured
      --dump-api FILE.json   write this program's API description and exit
      --list                 list the selected tests instead of running them
      --color / --no-color   ANSI colors in the text report (default: on a terminal)
      --root DIR             paths in reports are relative to DIR (default: the current folder)
  -h, --help
)",
                       program);
}

result<cli_options> parse_args(std::span<const std::string_view> args) {
    cli_options out;
    run_options& o = out.run;
    const auto bad = [](std::string_view what) { return fail(errc::kInvalidArgument, std::string{what}, "arguments"); };
    for (std::size_t i = 0; i < args.size(); ++i) {
        std::string_view a = args[i];
        std::string_view inline_value;
        bool has_inline = false;
        if (a.starts_with("--")) {
            if (const std::size_t eq = a.find('='); eq != std::string_view::npos) {
                inline_value = a.substr(eq + 1);
                a = a.substr(0, eq);
                has_inline = true;
            }
        }
        const auto next = [&](std::string_view name) -> result<std::string_view> {
            if (has_inline) {
                return inline_value;
            }
            if (i + 1 >= args.size()) {
                return fail(errc::kInvalidArgument, std::format("{} needs a value", name), "arguments");
            }
            return args[++i];
        };
#define RHP_VALUE(name)                               \
    auto v = next(name);                              \
    if (!v) {                                         \
        return std::unexpected{std::move(v).error()}; \
    }
        if (a == "-h" || a == "--help") {
            out.help = true;
        } else if (a == "-s" || a == "--scripts") {
            RHP_VALUE("--scripts")
            o.scripts.emplace_back(std::string{*v});
        } else if (a == "-f" || a == "--filter") {
            RHP_VALUE("--filter")
            o.filters.emplace_back(*v);
        } else if (a == "--filter-out") {
            RHP_VALUE("--filter-out")
            o.filters_out.emplace_back(*v);
        } else if (a == "-t" || a == "--tags") {
            RHP_VALUE("--tags")
            for (std::string& t : split_list(*v)) {
                o.tags.push_back(std::move(t));
            }
        } else if (a == "--exclude-tags") {
            RHP_VALUE("--exclude-tags")
            for (std::string& t : split_list(*v)) {
                o.exclude_tags.push_back(std::move(t));
            }
        } else if (a == "--seed") {
            RHP_VALUE("--seed")
            const auto n = number<std::uint64_t>(*v);
            if (!n) {
                return bad(std::format("--seed expects a number, got '{}'", *v));
            }
            o.seed = *n;
        } else if (a == "--shuffle") {
            o.shuffle = true;
        } else if (a == "--repeat") {
            RHP_VALUE("--repeat")
            const auto n = number<std::uint32_t>(*v);
            if (!n || *n == 0) {
                return bad(std::format("--repeat expects a number > 0, got '{}'", *v));
            }
            o.repeat = *n;
        } else if (a == "--fail-fast") {
            o.fail_fast = true;
        } else if (a == "--isolation") {
            RHP_VALUE("--isolation")
            if (*v == "file") {
                o.share = isolation::kFile;
            } else if (*v == "test") {
                o.share = isolation::kTest;
            } else {
                return bad(std::format("--isolation is 'file' or 'test', got '{}'", *v));
            }
        } else if (a == "--role") {
            RHP_VALUE("--role")
            if (*v == "observe") {
                o.caller = role::kObserve;
            } else if (*v == "patch") {
                o.caller = role::kPatch;
            } else if (*v == "admin") {
                o.caller = role::kAdmin;
            } else {
                return bad(std::format("--role is observe, patch or admin, got '{}'", *v));
            }
        } else if (a == "--timeout") {
            RHP_VALUE("--timeout")
            const auto n = number<std::uint64_t>(*v);
            if (!n || *n == 0) {
                return bad(std::format("--timeout expects milliseconds > 0, got '{}'", *v));
            }
            o.timeout = std::chrono::milliseconds{static_cast<std::int64_t>(*n)};
        } else if (a == "--max-frames") {
            RHP_VALUE("--max-frames")
            const auto n = number<std::uint64_t>(*v);
            if (!n || *n == 0) {
                return bad(std::format("--max-frames expects a number > 0, got '{}'", *v));
            }
            o.max_frames = *n;
        } else if (a == "--instructions") {
            RHP_VALUE("--instructions")
            const auto n = number<std::uint64_t>(*v);
            if (!n) {
                return bad(std::format("--instructions expects a number, got '{}'", *v));
            }
            o.limits.instructions = *n;
        } else if (a == "--memory") {
            RHP_VALUE("--memory")
            const auto n = number<std::uint64_t>(*v);
            if (!n) {
                return bad(std::format("--memory expects bytes, got '{}'", *v));
            }
            o.limits.memory = *n;
        } else if (a == "-r" || a == "--reporter") {
            RHP_VALUE("--reporter")
            auto [kind, path] = kind_and_path(*v);
            report_spec spec{report_kind::kText, path};
            if (kind == "text") {
                spec.kind = report_kind::kText;
            } else if (kind == "tap") {
                spec.kind = report_kind::kTap;
            } else if (kind == "junit") {
                spec.kind = report_kind::kJunit;
            } else if (kind == "json") {
                spec.kind = report_kind::kJson;
            } else if (kind == "github") {
                spec.kind = report_kind::kGithub;
            } else {
                return bad(std::format("unknown reporter '{}' (text, tap, junit, json, github)", kind));
            }
            o.reports.push_back(std::move(spec));
        } else if (a == "-v" || a == "--verbose") {
            o.verbose = true;
        } else if (a == "--coverage") {
            RHP_VALUE("--coverage")
            auto [kind, path] = kind_and_path(*v);
            coverage_spec spec{coverage_kind::kSummary, path};
            if (kind == "summary") {
                spec.kind = coverage_kind::kSummary;
            } else if (kind == "lcov") {
                spec.kind = coverage_kind::kLcov;
                if (spec.path.empty()) {
                    spec.path = "lcov.info";
                }
            } else if (kind == "cobertura") {
                spec.kind = coverage_kind::kCobertura;
                if (spec.path.empty()) {
                    spec.path = "coverage.xml";
                }
            } else {
                return bad(std::format("unknown coverage format '{}' (summary, lcov, cobertura)", kind));
            }
            o.coverage.push_back(std::move(spec));
        } else if (a == "--coverage-tests") {
            o.coverage_tests = true;
        } else if (a == "--profile") {
            o.profile = true;
            if (has_inline) {
                const auto n = number<std::uint32_t>(inline_value);
                if (!n) {
                    return bad(std::format("--profile=N expects a number, got '{}'", inline_value));
                }
                o.profile_interval = *n;
            }
        } else if (a == "--profile-out") {
            RHP_VALUE("--profile-out")
            o.profile = true;
            o.profile_out = std::string{*v};
        } else if (a == "--no-measure") {
            o.measure = false;
        } else if (a == "--strict-undo") {
            o.strict_undo = true;
        } else if (a == "--ci") {
            o.ci = true;
        } else if (a == "-u" || a == "--update-snapshots") {
            o.update_snapshots = true;
        } else if (a == "--fuzz") {
            RHP_VALUE("--fuzz")
            const auto n = number<std::uint64_t>(*v);
            if (!n) {
                return bad(std::format("--fuzz expects milliseconds, got '{}'", *v));
            }
            o.fuzz_ms = *n;
        } else if (a == "--property-runs") {
            RHP_VALUE("--property-runs")
            const auto n = number<std::uint32_t>(*v);
            if (!n || *n == 0) {
                return bad(std::format("--property-runs expects a number > 0, got '{}'", *v));
            }
            o.property_runs = *n;
        } else if (a == "--api") {
            RHP_VALUE("--api")
            out.api_file = std::string{*v};
        } else if (a == "--strict-fakes") {
            o.strict_fakes = true;
        } else if (a == "--dump-api") {
            RHP_VALUE("--dump-api")
            out.dump_api = std::string{*v};
        } else if (a == "--list") {
            o.list_only = true;
        } else if (a == "--color") {
            o.color = true;
        } else if (a == "--no-color") {
            o.color = false;
        } else if (a == "--root") {
            RHP_VALUE("--root")
            o.root = std::string{*v};
        } else if (a.starts_with("-") && a.size() > 1) {
            return bad(std::format("unknown option '{}' (--help lists them)", a));
        } else {
            o.tests.emplace_back(std::string{a});
        }
#undef RHP_VALUE
    }
    return out;
}

} // namespace Rhp::test
