#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/test/detail/coverage.hpp>
#include <rhp/test/detail/support.hpp>
#include <rhp/test/report.hpp>

namespace Rhp::test::detail {

namespace {

namespace fs = std::filesystem;

// Lines between "-- rhp: coverage off" and "-- rhp: coverage on" (also luacov's disable / enable).
std::set<std::uint32_t> excluded_lines(std::string_view source) {
    std::set<std::uint32_t> out;
    bool off = false;
    std::uint32_t line = 1;
    std::size_t start = 0;
    while (start <= source.size()) {
        const std::size_t end = std::min(source.find('\n', start), source.size());
        const std::string_view text = source.substr(start, end - start);
        if (text.find("rhp: coverage off") != std::string_view::npos || text.find("luacov: disable") != std::string_view::npos) {
            off = true;
        }
        if (off) {
            out.insert(line);
        }
        if (text.find("rhp: coverage on") != std::string_view::npos || text.find("luacov: enable") != std::string_view::npos) {
            off = false;
        }
        if (end >= source.size()) {
            break;
        }
        start = end + 1;
        ++line;
    }
    return out;
}

} // namespace

void coverage_totals::merge(const script::coverage_report& report, const std::map<std::string, std::string>& chunk_files, bool with_tests,
                            const std::string& test_file) {
    for (const script::coverage_chunk& c : report.chunks) {
        std::string file;
        if (const auto it = chunk_files.find(c.chunk); it != chunk_files.end()) {
            file = it->second;
        } else if (with_tests && c.chunk == test_file) {
            file = test_file;
        } else {
            continue; // the framework, exec chunks
        }
        auto& lines = lines_[file];
        auto& hits = hits_[file];
        for (std::size_t i = 0; i < c.lines.size(); ++i) {
            lines.insert(c.lines[i]);
            hits[c.lines[i]] += c.hits[i];
        }
    }
}

std::vector<file_coverage> coverage_totals::result(const fs::path& root) const {
    std::vector<file_coverage> out;
    for (const auto& [file, lines] : lines_) {
        std::set<std::uint32_t> skip;
        std::optional<error> failure;
        const std::string source = read_text(root / file, failure);
        if (!failure) {
            skip = excluded_lines(source);
        }
        file_coverage fc;
        fc.file = file;
        const auto& hits = hits_.at(file);
        for (const std::uint32_t line : lines) {
            if (skip.contains(line)) {
                continue;
            }
            fc.lines.push_back(line);
            const auto h = hits.find(line);
            fc.hits.push_back(h != hits.end() ? h->second : 0);
        }
        out.push_back(std::move(fc));
    }
    return out;
}

} // namespace Rhp::test::detail
