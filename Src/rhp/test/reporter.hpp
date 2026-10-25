#pragma once

#include <cstddef>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include <rhp/test/options.hpp>
#include <rhp/test/report.hpp>

namespace Rhp::test {

// A test declared in a file, before it runs.
struct test_info {
    std::uint64_t id = 0;
    std::string name;
    std::string file;
    std::uint32_t line = 0;
    std::vector<std::string> tags;
    bool skipped = false;
    bool pending = false;
};

// Receives a run as it happens (the runner's thread). Every callback has a default that does nothing.
class reporter {
public:
    virtual ~reporter() = default;

    virtual void run_started(std::uint64_t /*seed*/, std::size_t /*files*/) {}
    virtual void file_started(const std::string& /*file*/, const std::vector<test_info>& /*tests*/) {}
    virtual void test_started(const test_info& /*test*/) {}
    virtual void test_finished(const test_result& /*result*/) {}
    virtual void file_finished(const file_result& /*result*/) {}
    virtual void run_finished(const run_result& /*result*/) {}

protected:
    reporter() = default;
    reporter(const reporter&) = default;
    reporter& operator=(const reporter&) = default;
};

// Several reporters as one.
class reporter_list final : public reporter {
public:
    void add(std::unique_ptr<reporter> r) { list_.push_back(std::move(r)); }
    [[nodiscard]] bool empty() const noexcept { return list_.empty(); }

    void run_started(std::uint64_t seed, std::size_t files) override;
    void file_started(const std::string& file, const std::vector<test_info>& tests) override;
    void test_started(const test_info& test) override;
    void test_finished(const test_result& result) override;
    void file_finished(const file_result& result) override;
    void run_finished(const run_result& result) override;

private:
    std::vector<std::unique_ptr<reporter>> list_;
};

// The built-in reports, writing to `out` (which must outlive them).
[[nodiscard]] std::unique_ptr<reporter> make_text_reporter(std::ostream& out, bool color, bool verbose, std::vector<coverage_spec> coverage = {});
[[nodiscard]] std::unique_ptr<reporter> make_tap_reporter(std::ostream& out);
[[nodiscard]] std::unique_ptr<reporter> make_junit_reporter(std::ostream& out);
[[nodiscard]] std::unique_ptr<reporter> make_json_reporter(std::ostream& out);
[[nodiscard]] std::unique_ptr<reporter> make_github_reporter(std::ostream& out);

// Coverage files.
[[nodiscard]] std::string lcov_text(const std::vector<file_coverage>& files);
[[nodiscard]] std::string cobertura_text(const std::vector<file_coverage>& files, std::string_view root);
// Folded stacks ("frame;frame count" lines) for flame graph tools.
[[nodiscard]] std::string folded_text(const std::vector<script::profile_stack>& stacks);

// XML 1.0 text: & < > " ' escaped, characters XML can't carry (and invalid UTF-8) replaced by U+FFFD.
[[nodiscard]] std::string xml_escape(std::string_view text);

} // namespace Rhp::test
