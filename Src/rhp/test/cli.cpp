#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/json.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/test/cli.hpp>
#include <rhp/test/detail/support.hpp>
#include <rhp/test/reporter.hpp>
#include <rhp/test/runner.hpp>

namespace Rhp::test {

namespace {

namespace fs = std::filesystem;
using detail::write_text;

} // namespace

int run_cli(std::span<const std::string_view> args, const install_fn& install, std::string_view program, std::ostream& out, std::ostream& err, const value* given_api) {
    auto parsed = parse_args(args);
    if (!parsed) {
        err << std::format("{}: {}\n", program, parsed.error().message);
        return 2;
    }
    cli_options& cli = *parsed;
    if (cli.help) {
        out << usage(program);
        return 0;
    }
    run_options& o = cli.run;
    if (!cli.dump_api.empty()) {
        auto api = describe_api(install, o.caller);
        if (!api) {
            err << std::format("{}: describing the API failed: {}\n", program, api.error());
            return 1;
        }
        if (auto written = write_text(cli.dump_api, json::to_text(*api, 2) + "\n"); !written) {
            err << std::format("{}: can't write {}: {}\n", program, cli.dump_api.generic_string(), written.error());
            return 1;
        }
        out << std::format("wrote the API description to {}\n", cli.dump_api.generic_string());
        return 0;
    }
    if (!cli.api_file.empty()) {
        auto bytes = platform::read_file(cli.api_file);
        if (!bytes) {
            err << std::format("{}: can't read {}: {}\n", program, cli.api_file.generic_string(), bytes.error());
            return 2;
        }
        auto api = json::parse(std::string_view{reinterpret_cast<const char*>(bytes->data()), bytes->size()});
        if (!api || api->find("libs") == nullptr) {
            err << std::format("{}: {} isn't an API description (--dump-api writes one)\n", program, cli.api_file.generic_string());
            return 2;
        }
        o.api = std::move(*api);
    }
    if (given_api != nullptr) {
        if (given_api->find("libs") == nullptr) {
            err << std::format("{}: the API description has no libs\n", program);
            return 2;
        }
        o.api = *given_api;
    }
    if (o.tests.empty()) {
        err << std::format("{}: no test files or folders given (--help for usage)\n", program);
        return 2;
    }
    const bool color = o.color.value_or(platform::stdout_is_terminal()) && platform::enable_ansi_colors();

    runner r{o, install};
    if (o.list_only) {
        const bool as_json = std::ranges::any_of(o.reports, [](const report_spec& s) { return s.kind == report_kind::kJson; });
        bool ok = true;
        for (const auto& [file, tests] : r.list()) {
            ok = ok && file.errors.empty();
            if (as_json) {
                value::array list;
                for (const test_info& t : tests) {
                    value::map m;
                    m.emplace_back(value{"id"}, value{detail::test_id(t.file, t.name)});
                    m.emplace_back(value{"name"}, value{t.name});
                    m.emplace_back(value{"line"}, value{static_cast<std::int64_t>(t.line)});
                    m.emplace_back(value{"tags"}, Rhp::to_value(t.tags));
                    m.emplace_back(value{"skipped"}, value{t.skipped});
                    list.emplace_back(std::move(m));
                }
                value::array errors;
                for (const file_error& e : file.errors) {
                    errors.emplace_back(e.message);
                }
                value::map event;
                event.emplace_back(value{"event"}, value{"list"});
                event.emplace_back(value{"file"}, value{file.file});
                event.emplace_back(value{"tests"}, value{std::move(list)});
                event.emplace_back(value{"errors"}, value{std::move(errors)});
                out << json::to_text(value{std::move(event)}) << '\n';
            } else {
                out << file.file << '\n';
                for (const file_error& e : file.errors) {
                    out << "  error: " << e.message << '\n';
                }
                for (const test_info& t : tests) {
                    out << std::format("  {}:{}  {}{}\n", t.file, t.line, t.name, t.skipped ? "  (skipped)" : "");
                }
            }
        }
        return ok ? 0 : 1;
    }

    reporter_list reports;
    std::vector<std::unique_ptr<std::ofstream>> files;
    const auto stream_for = [&](const fs::path& path) -> std::ostream* {
        if (path.empty()) {
            return &out;
        }
        std::error_code ec;
        if (path.has_parent_path()) {
            fs::create_directories(path.parent_path(), ec);
        }
        auto f = std::make_unique<std::ofstream>(path, std::ios::binary);
        if (!*f) {
            err << std::format("{}: can't write {}\n", program, path.generic_string());
            return nullptr;
        }
        files.push_back(std::move(f));
        return files.back().get();
    };
    // Standard output gets the text report unless a reporter was given for it (reports written to
    // files come on top).
    if (std::ranges::none_of(o.reports, [](const report_spec& s) { return s.path.empty(); })) {
        o.reports.insert(o.reports.begin(), report_spec{});
    }
    for (const report_spec& spec : o.reports) {
        std::ostream* s = stream_for(spec.path);
        if (s == nullptr) {
            return 2;
        }
        switch (spec.kind) {
        case report_kind::kText: reports.add(make_text_reporter(*s, color && spec.path.empty(), o.verbose, o.coverage)); break;
        case report_kind::kTap: reports.add(make_tap_reporter(*s)); break;
        case report_kind::kJunit: reports.add(make_junit_reporter(*s)); break;
        case report_kind::kJson: reports.add(make_json_reporter(*s)); break;
        case report_kind::kGithub: reports.add(make_github_reporter(*s)); break;
        }
    }
    const run_result result = r.run(reports);
    for (const coverage_spec& spec : o.coverage) {
        std::string text;
        if (spec.kind == coverage_kind::kLcov) {
            text = lcov_text(result.coverage);
        } else if (spec.kind == coverage_kind::kCobertura) {
            text = cobertura_text(result.coverage, o.root.empty() ? std::string{"."} : o.root.generic_string());
        } else {
            continue;
        }
        if (auto written = write_text(spec.path, text); !written) {
            err << std::format("{}: can't write {}: {}\n", program, spec.path.generic_string(), written.error());
        }
    }
    if (!o.profile_out.empty()) {
        if (auto written = write_text(o.profile_out, folded_text(result.profile)); !written) {
            err << std::format("{}: can't write {}: {}\n", program, o.profile_out.generic_string(), written.error());
        }
    }
    return result.totals.ok() ? 0 : 1;
}

int run_cli(std::span<const std::string_view> args, const install_fn& install, std::string_view program) {
    return run_cli(args, install, program, std::cout, std::cerr);
}

} // namespace Rhp::test
