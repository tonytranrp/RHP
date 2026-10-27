#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/json.hpp>
#include <rhp/core/value.hpp>
#include <rhp/test/detail/support.hpp>
#include <rhp/test/reporter.hpp>
#include <rhp/utils/utf8.hpp>

namespace Rhp::test {

namespace {

// ---- text helpers ----------------------------------------------------------------------------------------

std::string human_count(std::uint64_t n) {
    if (n >= 10'000'000) {
        return std::format("{:.1f}M", static_cast<double>(n) / 1e6);
    }
    if (n >= 10'000) {
        return std::format("{:.1f}k", static_cast<double>(n) / 1e3);
    }
    return std::format("{}", n);
}

std::string human_bytes(std::int64_t n) {
    const double v = static_cast<double>(n < 0 ? -n : n);
    const std::string sign = n < 0 ? "-" : "";
    if (v >= 1024.0 * 1024.0) {
        return std::format("{}{:.1f} MiB", sign, v / (1024.0 * 1024.0));
    }
    if (v >= 1024.0) {
        return std::format("{}{:.1f} KiB", sign, v / 1024.0);
    }
    return std::format("{}{} B", sign, n < 0 ? -n : n);
}

std::string ms_text(double ms) {
    if (ms >= 1000.0) {
        return std::format("{:.2f} s", ms / 1000.0);
    }
    if (ms >= 10.0) {
        return std::format("{:.0f} ms", ms);
    }
    return std::format("{:.2f} ms", ms);
}

std::string_view first_line(std::string_view text) {
    return text.substr(0, text.find('\n'));
}

std::string indent(std::string_view text, std::string_view prefix) {
    std::string out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = std::min(text.find('\n', start), text.size());
        out += prefix;
        out += text.substr(start, end - start);
        out += '\n';
        if (end >= text.size()) {
            break;
        }
        start = end + 1;
    }
    return out;
}

const char* kReset = "\x1b[0m";
const char* kGreen = "\x1b[32m";
const char* kRed = "\x1b[31m";
const char* kYellow = "\x1b[33m";
const char* kDim = "\x1b[2m";
const char* kBold = "\x1b[1m";

// ---- text --------------------------------------------------------------------------------------------------

class text_reporter final : public reporter {
public:
    text_reporter(std::ostream& out, bool color, bool verbose, std::vector<coverage_spec> coverage)
        : out_(out), color_(color), verbose_(verbose), coverage_(std::move(coverage)) {}

    void run_started(std::uint64_t seed, std::size_t files) override {
        out_ << std::format("RHP Lua tests: {} file(s), seed {}\n", files, seed);
    }

    void file_started(const std::string& file, const std::vector<test_info>&) override { out_ << paint(kBold, file) << '\n'; }

    void test_finished(const test_result& r) override {
        const bool bad = r.outcome == status::kFailed || r.outcome == status::kError;
        if (!verbose_ && !bad && r.outcome != status::kPending) {
            return;
        }
        std::string costs;
        if (verbose_ && r.outcome != status::kSkipped) {
            costs = paint(kDim, std::format("  ({}, {} instr, peak {}, {} alloc)", ms_text(r.cost.time_ms), human_count(r.cost.instructions), human_bytes(static_cast<std::int64_t>(r.cost.peak)),
                                            human_count(r.cost.allocations)));
        }
        out_ << "  " << badge(r.outcome) << ' ' << r.name << costs << '\n';
        if (bad || r.outcome == status::kPending) {
            if (!r.message.empty()) {
                out_ << indent(r.message, "      ");
            }
        }
        if (bad) {
            out_ << paint(kDim, std::format("      at {}\n", r.where));
            if (!r.traceback.empty()) {
                out_ << paint(kDim, indent(r.traceback, "        "));
            }
            if (!r.output.empty()) {
                out_ << paint(kDim, "      output:\n");
                for (const std::string& line : r.output) {
                    out_ << paint(kDim, "        " + line + "\n");
                }
            }
        }
        for (const std::string& note : r.notes) {
            out_ << paint(kYellow, "      note: " + note + "\n");
        }
        if (verbose_) {
            for (const measure& m : r.measures) {
                out_ << paint(kDim, std::format("      measure {}: {} instr, {} bytes, peak {}, retained {}, {}\n", m.name, human_count(m.instructions), human_bytes(static_cast<std::int64_t>(m.bytes)),
                                                human_bytes(m.peak), human_bytes(m.retained), ms_text(m.time_ms)));
            }
        }
        for (const bench& b : r.benches) {
            out_ << paint(kDim, std::format("      bench {}: median {} instr, {} (mean {}, stddev {}), {} per run, {} runs\n", b.name, human_count(static_cast<std::uint64_t>(b.instructions.median)),
                                            ms_text(b.time_ms.median), ms_text(b.time_ms.mean), ms_text(b.time_ms.stddev),
                                            human_bytes(static_cast<std::int64_t>(b.bytes.median)), b.runs));
        }
    }

    void file_finished(const file_result& r) override {
        for (const file_error& e : r.errors) {
            out_ << "  " << paint(kRed, "ERROR") << ' ' << e.message << '\n';
            if (!e.file.empty()) {
                out_ << paint(kDim, std::format("      at {}:{}\n", e.file, e.line));
            }
            if (!e.traceback.empty()) {
                out_ << paint(kDim, indent(e.traceback, "        "));
            }
        }
        if (!verbose_) {
            std::size_t passed = 0;
            for (const test_result& t : r.tests) {
                passed += t.outcome == status::kPassed ? 1 : 0;
            }
            out_ << paint(kDim, std::format("  {} of {} passed ({})\n", passed, r.tests.size(), ms_text(r.ms)));
        }
    }

    void run_finished(const run_result& r) override {
        const counts& c = r.totals;
        out_ << '\n';
        for (const std::string& note : r.notes) {
            out_ << paint(kYellow, "note: " + note) << '\n';
        }
        // The slowest and the hungriest tests: what to look at first.
        std::vector<const test_result*> all;
        for (const file_result& f : r.files) {
            for (const test_result& t : f.tests) {
                if (t.outcome != status::kSkipped) {
                    all.push_back(&t);
                }
            }
        }
        if (all.size() > 3) {
            std::ranges::sort(all, [](const test_result* a, const test_result* b) { return a->cost.instructions > b->cost.instructions; });
            out_ << "most instructions:\n";
            for (std::size_t i = 0; i < std::min<std::size_t>(3, all.size()); ++i) {
                out_ << std::format("  {:>8}  {} ({})\n", human_count(all[i]->cost.instructions), all[i]->name, all[i]->file);
            }
            std::ranges::sort(all, [](const test_result* a, const test_result* b) { return a->cost.peak > b->cost.peak; });
            out_ << "most memory (peak):\n";
            for (std::size_t i = 0; i < std::min<std::size_t>(3, all.size()); ++i) {
                out_ << std::format("  {:>10}  {} ({})\n", human_bytes(static_cast<std::int64_t>(all[i]->cost.peak)), all[i]->name, all[i]->file);
            }
        }
        if (std::ranges::any_of(coverage_, [](const coverage_spec& s) { return s.kind == coverage_kind::kSummary; }) && !r.coverage.empty()) {
            std::size_t total = 0;
            std::size_t covered = 0;
            out_ << "coverage:\n";
            for (const file_coverage& f : r.coverage) {
                total += f.lines.size();
                covered += f.covered();
                const double pct = f.lines.empty() ? 100.0 : 100.0 * static_cast<double>(f.covered()) / static_cast<double>(f.lines.size());
                out_ << std::format("  {:>6.1f}%  {:>5}/{:<5} {}\n", pct, f.covered(), f.lines.size(), f.file);
            }
            out_ << std::format("  {:>6.1f}%  {:>5}/{:<5} total\n", total == 0 ? 100.0 : 100.0 * static_cast<double>(covered) / static_cast<double>(total), covered, total);
        }
        std::string line = std::format("{} passed", c.passed);
        if (c.failed != 0) {
            line += std::format(", {} failed", c.failed);
        }
        if (c.errors != 0) {
            line += std::format(", {} error{}", c.errors, c.errors == 1 ? "" : "s");
        }
        if (c.pending != 0) {
            line += std::format(", {} pending", c.pending);
        }
        if (c.skipped != 0) {
            line += std::format(", {} skipped", c.skipped);
        }
        if (c.file_errors != 0) {
            line += std::format(", {} file error{}", c.file_errors, c.file_errors == 1 ? "" : "s");
        }
        out_ << paint(c.ok() ? kGreen : kRed, line) << std::format(" in {} (seed {})\n", ms_text(r.ms), r.seed);
        out_.flush();
    }

private:
    std::string paint(const char* code, std::string_view text) const {
        if (!color_) {
            return std::string{text};
        }
        return std::format("{}{}{}", code, text, kReset);
    }

    std::string badge(status s) const {
        switch (s) {
        case status::kPassed: return paint(kGreen, "PASS");
        case status::kFailed: return paint(kRed, "FAIL");
        case status::kError: return paint(kRed, "ERR ");
        case status::kPending: return paint(kYellow, "TODO");
        case status::kSkipped: return paint(kDim, "SKIP");
        }
        return "????";
    }

    std::ostream& out_;
    bool color_;
    bool verbose_;
    std::vector<coverage_spec> coverage_;
};

// ---- TAP 14 ----------------------------------------------------------------------------------------------

std::string tap_escape(std::string_view text) {
    std::string out;
    for (const char c : text) {
        if (c == '#' || c == '\\') {
            out += '\\';
        }
        out += c == '\n' || c == '\r' ? ' ' : c;
    }
    return out;
}

std::string yaml_quote(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                out += std::format("\\x{:02x}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    return out + "\"";
}

class tap_reporter final : public reporter {
public:
    explicit tap_reporter(std::ostream& out) : out_(out) {}

    void run_started(std::uint64_t seed, std::size_t) override { out_ << "TAP version 14\n"
                                                                      << std::format("# seed {}\n", seed); }

    void test_finished(const test_result& r) override {
        ++n_;
        const bool ok = r.outcome == status::kPassed || r.outcome == status::kSkipped || r.outcome == status::kPending;
        std::string line = std::format("{} {} - {}", ok ? "ok" : "not ok", n_, tap_escape(std::format("{}: {}", r.file, r.name)));
        if (r.outcome == status::kSkipped) {
            line += " # SKIP";
        } else if (r.outcome == status::kPending) {
            line += " # TODO " + tap_escape(r.message);
        }
        out_ << line << '\n';
        if (!ok) {
            out_ << "  ---\n";
            out_ << "  message: " << yaml_quote(r.message) << '\n';
            out_ << "  severity: " << (r.outcome == status::kFailed ? "fail" : "error") << '\n';
            out_ << "  at: " << yaml_quote(r.where) << '\n';
            if (r.expected) {
                out_ << "  expected: " << yaml_quote(*r.expected) << '\n';
            }
            if (r.actual) {
                out_ << "  actual: " << yaml_quote(*r.actual) << '\n';
            }
            if (!r.traceback.empty()) {
                out_ << "  stack: " << yaml_quote(r.traceback) << '\n';
            }
            out_ << "  ...\n";
        }
    }

    void file_finished(const file_result& r) override {
        for (const file_error& e : r.errors) {
            ++n_;
            out_ << std::format("not ok {} - {}\n", n_, tap_escape(std::format("{}: {}", r.file, e.message)));
            out_ << "  ---\n  message: " << yaml_quote(e.message) << "\n  at: " << yaml_quote(std::format("{}:{}", e.file, e.line)) << "\n  ...\n";
        }
    }

    void run_finished(const run_result& r) override {
        out_ << std::format("1..{}\n", n_);
        out_ << std::format("# {} passed, {} failed, {} errors, {} pending, {} skipped\n", r.totals.passed, r.totals.failed, r.totals.errors + r.totals.file_errors, r.totals.pending,
                            r.totals.skipped);
        out_.flush();
    }

private:
    std::ostream& out_;
    std::size_t n_ = 0;
};

// ---- JUnit XML -------------------------------------------------------------------------------------------

std::string class_name(std::string_view file) {
    std::string out{file};
    if (out.ends_with(".lua")) {
        out.resize(out.size() - 4);
    }
    std::ranges::replace(out, '/', '.');
    return out;
}

class junit_reporter final : public reporter {
public:
    explicit junit_reporter(std::ostream& out) : out_(out) {}

    void run_finished(const run_result& r) override {
        const auto now = std::chrono::system_clock::now();
        const std::string stamp = std::format("{:%Y-%m-%dT%H:%M:%S}", std::chrono::floor<std::chrono::seconds>(now));
        out_ << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
        out_ << std::format("<testsuites name=\"rhp-lua-tests\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{:.3f}\">\n", r.totals.total(), r.totals.failed,
                            r.totals.errors + r.totals.file_errors, r.totals.skipped + r.totals.pending, r.ms / 1000.0);
        for (const file_result& f : r.files) {
            std::size_t failed = 0;
            std::size_t errored = f.errors.size();
            std::size_t skipped = 0;
            for (const test_result& t : f.tests) {
                failed += t.outcome == status::kFailed ? 1 : 0;
                errored += t.outcome == status::kError ? 1 : 0;
                skipped += (t.outcome == status::kSkipped || t.outcome == status::kPending) ? 1 : 0;
            }
            out_ << std::format("  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{:.3f}\" timestamp=\"{}\">\n", xml_escape(f.file),
                                f.tests.size() + f.errors.size(), failed, errored, skipped, f.ms / 1000.0, stamp);
            out_ << std::format("    <properties><property name=\"seed\" value=\"{}\"/></properties>\n", r.seed);
            const std::string cls = xml_escape(class_name(f.file));
            for (const test_result& t : f.tests) {
                out_ << std::format("    <testcase classname=\"{}\" name=\"{}\" file=\"{}\" line=\"{}\" time=\"{:.4f}\"", cls, xml_escape(t.name), xml_escape(t.file), t.line,
                                    t.cost.wall_ms / 1000.0);
                const bool has_body = t.outcome != status::kPassed || !t.output.empty();
                if (!has_body) {
                    out_ << "/>\n";
                    continue;
                }
                out_ << ">\n";
                if (t.outcome == status::kFailed || t.outcome == status::kError) {
                    const char* tag = t.outcome == status::kFailed ? "failure" : "error";
                    // " at (file:line:1)" lets reporters that read stack lines annotate the source.
                    std::string body = std::format("{}\n    at test ({}:1)\n{}", t.message, t.where, t.traceback);
                    out_ << std::format("      <{} message=\"{}\" type=\"{}\">{}</{}>\n", tag, xml_escape(first_line(t.message)), t.outcome == status::kFailed ? "assertion" : "error",
                                        xml_escape(body), tag);
                } else if (t.outcome == status::kSkipped || t.outcome == status::kPending) {
                    out_ << std::format("      <skipped message=\"{}\"/>\n", xml_escape(t.outcome == status::kPending ? t.message : "skipped"));
                }
                if (!t.output.empty()) {
                    std::string text;
                    for (const std::string& line : t.output) {
                        text += line + "\n";
                    }
                    out_ << std::format("      <system-out>{}</system-out>\n", xml_escape(text));
                }
                out_ << "    </testcase>\n";
            }
            for (const file_error& e : f.errors) {
                out_ << std::format("    <testcase classname=\"{}\" name=\"{}\" file=\"{}\" line=\"{}\" time=\"0\">\n", cls, xml_escape(std::format("(file) {}", first_line(e.message))),
                                    xml_escape(e.file.empty() ? f.file : e.file), e.line);
                out_ << std::format("      <error message=\"{}\" type=\"error\">{}</error>\n    </testcase>\n", xml_escape(first_line(e.message)),
                                    xml_escape(e.message + "\n" + e.traceback));
            }
            out_ << "  </testsuite>\n";
        }
        out_ << "</testsuites>\n";
        out_.flush();
    }

private:
    std::ostream& out_;
};

// ---- JSON events ------------------------------------------------------------------------------------------

using detail::object;
using detail::test_id;

value test_value(const test_result& t) {
    object o;
    o.set("event", value{"test_end"})
        .set("id", value{test_id(t.file, t.name)})
        .set("file", value{t.file})
        .set("name", value{t.name})
        .set("line", value{static_cast<std::int64_t>(t.line)})
        .set("status", value{std::string{to_string(t.outcome)}})
        .set("message", value{t.message})
        .set("where", value{t.where})
        .set("fail_file", value{t.fail_file})
        .set("fail_line", value{static_cast<std::int64_t>(t.fail_line)})
        .set("traceback", value{t.traceback})
        .set("ms", value{t.cost.wall_ms})
        .set("tags", Rhp::to_value(t.tags))
        .set("assertions", value{static_cast<std::int64_t>(t.assertions)})
        .set("output", Rhp::to_value(t.output))
        .set("notes", Rhp::to_value(t.notes));
    if (t.expected) {
        o.set("expected", value{*t.expected});
    }
    if (t.actual) {
        o.set("actual", value{*t.actual});
    }
    o.set("cost", object{}
                      .set("instructions", value{static_cast<std::int64_t>(t.cost.instructions)})
                      .set("time_ms", value{t.cost.time_ms})
                      .set("allocations", value{static_cast<std::int64_t>(t.cost.allocations)})
                      .set("bytes", value{static_cast<std::int64_t>(t.cost.bytes)})
                      .set("peak", value{static_cast<std::int64_t>(t.cost.peak)})
                      .set("retained", value{t.cost.retained})
                      .set("frames", value{static_cast<std::int64_t>(t.cost.frames)})
                      .done());
    value::array measures;
    for (const measure& m : t.measures) {
        measures.push_back(object{}
                               .set("name", value{m.name})
                               .set("instructions", value{static_cast<std::int64_t>(m.instructions)})
                               .set("bytes", value{static_cast<std::int64_t>(m.bytes)})
                               .set("peak", value{m.peak})
                               .set("retained", value{m.retained})
                               .set("time_ms", value{m.time_ms})
                               .done());
    }
    o.set("measures", value{std::move(measures)});
    value::array benches;
    for (const bench& b : t.benches) {
        const auto line = [](const stats_line& s) {
            return object{}.set("min", value{s.min}).set("max", value{s.max}).set("mean", value{s.mean}).set("median", value{s.median}).set("stddev", value{s.stddev}).done();
        };
        benches.push_back(object{}
                              .set("name", value{b.name})
                              .set("runs", value{static_cast<std::int64_t>(b.runs)})
                              .set("instructions", line(b.instructions))
                              .set("time_ms", line(b.time_ms))
                              .set("bytes", line(b.bytes))
                              .set("allocations", line(b.allocations))
                              .done());
    }
    o.set("benches", value{std::move(benches)});
    return o.done();
}

class json_reporter final : public reporter {
public:
    explicit json_reporter(std::ostream& out) : out_(out) {}

    void run_started(std::uint64_t seed, std::size_t files) override {
        emit(object{}.set("event", value{"run_start"}).set("seed", value{static_cast<std::int64_t>(seed)}).set("files", value{static_cast<std::int64_t>(files)}).done());
    }

    void file_started(const std::string& file, const std::vector<test_info>& tests) override {
        value::array list;
        for (const test_info& t : tests) {
            list.push_back(object{}
                               .set("id", value{test_id(t.file, t.name)})
                               .set("name", value{t.name})
                               .set("line", value{static_cast<std::int64_t>(t.line)})
                               .set("tags", Rhp::to_value(t.tags))
                               .set("skipped", value{t.skipped})
                               .set("pending", value{t.pending})
                               .done());
        }
        emit(object{}.set("event", value{"file_start"}).set("file", value{file}).set("tests", value{std::move(list)}).done());
    }

    void test_started(const test_info& t) override {
        emit(object{}.set("event", value{"test_start"}).set("id", value{test_id(t.file, t.name)}).set("file", value{t.file}).set("name", value{t.name}).done());
    }

    void test_finished(const test_result& t) override { emit(test_value(t)); }

    void file_finished(const file_result& f) override {
        value::array errors;
        for (const file_error& e : f.errors) {
            errors.push_back(object{}
                                 .set("message", value{e.message})
                                 .set("file", value{e.file})
                                 .set("line", value{static_cast<std::int64_t>(e.line)})
                                 .set("traceback", value{e.traceback})
                                 .done());
        }
        emit(object{}.set("event", value{"file_end"}).set("file", value{f.file}).set("ms", value{f.ms}).set("errors", value{std::move(errors)}).done());
    }

    void run_finished(const run_result& r) override {
        object o;
        o.set("event", value{"run_end"})
            .set("passed", value{static_cast<std::int64_t>(r.totals.passed)})
            .set("failed", value{static_cast<std::int64_t>(r.totals.failed)})
            .set("errors", value{static_cast<std::int64_t>(r.totals.errors)})
            .set("pending", value{static_cast<std::int64_t>(r.totals.pending)})
            .set("skipped", value{static_cast<std::int64_t>(r.totals.skipped)})
            .set("file_errors", value{static_cast<std::int64_t>(r.totals.file_errors)})
            .set("ms", value{r.ms})
            .set("seed", value{static_cast<std::int64_t>(r.seed)})
            .set("notes", Rhp::to_value(r.notes));
        value::array coverage;
        for (const file_coverage& f : r.coverage) {
            value::array lines;
            for (std::size_t i = 0; i < f.lines.size(); ++i) {
                lines.emplace_back(value::array{value{static_cast<std::int64_t>(f.lines[i])}, value{static_cast<std::int64_t>(f.hits[i])}});
            }
            coverage.push_back(object{}.set("file", value{f.file}).set("lines", value{std::move(lines)}).done());
        }
        o.set("coverage", value{std::move(coverage)});
        emit(o.done());
        out_.flush();
    }

private:
    void emit(const value& v) { out_ << json::to_text(v) << '\n'; }

    std::ostream& out_;
};

// ---- GitHub annotations ----------------------------------------------------------------------------------

std::string gh_escape(std::string_view text, bool property) {
    std::string out;
    for (const char c : text) {
        switch (c) {
        case '%': out += "%25"; break;
        case '\r': out += "%0D"; break;
        case '\n': out += "%0A"; break;
        case ':':
            out += property ? "%3A" : ":";
            break;
        case ',':
            out += property ? "%2C" : ",";
            break;
        default: out += c;
        }
    }
    return out;
}

class github_reporter final : public reporter {
public:
    explicit github_reporter(std::ostream& out) : out_(out) {}

    void test_finished(const test_result& t) override {
        if (t.outcome != status::kFailed && t.outcome != status::kError) {
            return;
        }
        const detail::place at = detail::failure_place(t);
        out_ << std::format("::error file={},line={},title={}::{}\n", gh_escape(at.file, true), at.line, gh_escape(t.name, true), gh_escape(t.message, false));
    }

    void file_finished(const file_result& f) override {
        for (const file_error& e : f.errors) {
            out_ << std::format("::error file={},line={},title={}::{}\n", gh_escape(e.file.empty() ? f.file : e.file, true), e.line, gh_escape("Lua test file", true), gh_escape(e.message, false));
        }
    }

    void run_finished(const run_result&) override { out_.flush(); }

private:
    std::ostream& out_;
};

} // namespace

std::unique_ptr<reporter> make_text_reporter(std::ostream& out, bool color, bool verbose, std::vector<coverage_spec> coverage) {
    return std::make_unique<text_reporter>(out, color, verbose, std::move(coverage));
}

std::unique_ptr<reporter> make_tap_reporter(std::ostream& out) {
    return std::make_unique<tap_reporter>(out);
}

std::unique_ptr<reporter> make_junit_reporter(std::ostream& out) {
    return std::make_unique<junit_reporter>(out);
}

std::unique_ptr<reporter> make_json_reporter(std::ostream& out) {
    return std::make_unique<json_reporter>(out);
}

std::unique_ptr<reporter> make_github_reporter(std::ostream& out) {
    return std::make_unique<github_reporter>(out);
}

std::string lcov_text(const std::vector<file_coverage>& files) {
    std::string out;
    for (const file_coverage& f : files) {
        out += "TN:\n";
        out += std::format("SF:{}\n", f.file);
        for (std::size_t i = 0; i < f.lines.size(); ++i) {
            out += std::format("DA:{},{}\n", f.lines[i], f.hits[i]);
        }
        out += std::format("LF:{}\nLH:{}\nend_of_record\n", f.lines.size(), f.covered());
    }
    return out;
}

std::string cobertura_text(const std::vector<file_coverage>& files, std::string_view root) {
    std::size_t total = 0;
    std::size_t covered = 0;
    for (const file_coverage& f : files) {
        total += f.lines.size();
        covered += f.covered();
    }
    const auto rate = [](std::size_t c, std::size_t t) { return t == 0 ? 1.0 : static_cast<double>(c) / static_cast<double>(t); };
    const auto stamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out += "<!DOCTYPE coverage SYSTEM \"http://cobertura.sourceforge.net/xml/coverage-04.dtd\">\n";
    out += std::format("<coverage line-rate=\"{:.4f}\" branch-rate=\"0\" lines-covered=\"{}\" lines-valid=\"{}\" branches-covered=\"0\" branches-valid=\"0\" complexity=\"0\" version=\"rhp\" timestamp=\"{}\">\n",
                       rate(covered, total), covered, total, stamp);
    out += std::format("  <sources><source>{}</source></sources>\n", xml_escape(root.empty() ? "." : root));
    // One package per folder.
    std::map<std::string, std::vector<const file_coverage*>> packages;
    for (const file_coverage& f : files) {
        const std::size_t slash = f.file.rfind('/');
        packages[slash == std::string::npos ? std::string{"."} : f.file.substr(0, slash)].push_back(&f);
    }
    out += "  <packages>\n";
    for (const auto& [name, list] : packages) {
        std::size_t pt = 0;
        std::size_t pc = 0;
        for (const file_coverage* f : list) {
            pt += f->lines.size();
            pc += f->covered();
        }
        std::string package_name = name;
        std::ranges::replace(package_name, '/', '.');
        out += std::format("    <package name=\"{}\" line-rate=\"{:.4f}\" branch-rate=\"0\" complexity=\"0\">\n      <classes>\n", xml_escape(package_name), rate(pc, pt));
        for (const file_coverage* f : list) {
            out += std::format("        <class name=\"{}\" filename=\"{}\" line-rate=\"{:.4f}\" branch-rate=\"0\" complexity=\"0\">\n          <methods/>\n          <lines>\n",
                               xml_escape(class_name(f->file)), xml_escape(f->file), rate(f->covered(), f->lines.size()));
            for (std::size_t i = 0; i < f->lines.size(); ++i) {
                out += std::format("            <line number=\"{}\" hits=\"{}\" branch=\"false\"/>\n", f->lines[i], f->hits[i]);
            }
            out += "          </lines>\n        </class>\n";
        }
        out += "      </classes>\n    </package>\n";
    }
    out += "  </packages>\n</coverage>\n";
    return out;
}

std::string folded_text(const std::vector<script::profile_stack>& stacks) {
    std::string out;
    for (const script::profile_stack& s : stacks) {
        out += std::format("{} {}\n", s.stack, s.samples);
    }
    return out;
}

std::string xml_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size();) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c < 0x80) {
            switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            case '\n': out += "&#10;"; break;
            case '\r': out += "&#13;"; break;
            case '\t': out += "&#9;"; break;
            default:
                if (c < 0x20) {
                    out += "\xEF\xBF\xBD"; // not allowed in XML 1.0 at all
                } else {
                    out += static_cast<char>(c);
                }
            }
            ++i;
            continue;
        }
        // A UTF-8 sequence: copied when well-formed, else U+FFFD.
        const std::size_t len = utils::utf8_sequence_length(text, i);
        // U+FFFE and U+FFFF aren't XML characters.
        const bool not_xml = len == 3 && c == 0xEF && static_cast<unsigned char>(text[i + 1]) == 0xBF &&
                             (static_cast<unsigned char>(text[i + 2]) == 0xBE || static_cast<unsigned char>(text[i + 2]) == 0xBF);
        if (len != 0 && !not_xml) {
            out.append(text.substr(i, len));
            i += len;
        } else {
            out += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return out;
}

} // namespace Rhp::test
