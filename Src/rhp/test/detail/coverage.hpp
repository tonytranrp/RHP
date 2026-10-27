#pragma once

// Private to Src/rhp/test: the coverage of a run, merged from every test sandbox.

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <rhp/script/sandbox.hpp>
#include <rhp/test/report.hpp>

namespace Rhp::test::detail {

class coverage_totals {
public:
    // Adds a sandbox's report: the chunks of the scripts folder's modules (`chunk_files`: chunk name ->
    // file, relative), and the test file's own (`test_file`) when `with_tests` (--coverage-tests).
    void merge(const script::coverage_report& report, const std::map<std::string, std::string>& chunk_files, bool with_tests, const std::string& test_file);

    // Every file's executable lines and their hits, without the lines its source excludes ("rhp:
    // coverage off" / "on", luacov's disable / enable). Files are read under `root`.
    [[nodiscard]] std::vector<file_coverage> result(const std::filesystem::path& root) const;

private:
    std::map<std::string, std::map<std::uint32_t, std::uint64_t>> hits_; // file -> line -> hits
    std::map<std::string, std::set<std::uint32_t>> lines_;               // file -> executable lines
};

} // namespace Rhp::test::detail
