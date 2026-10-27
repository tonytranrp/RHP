#pragma once

// Private to Src/rhp/test (not installed): helpers the runner, the reporters and the command line share.

#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/test/report.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::test::detail {

// A value map built field by field, in order: object{}.set("a", value{1}).set("b", value{2}).done().
class object {
public:
    object& set(std::string_view key, value v) {
        fields_.emplace_back(value{std::string{key}}, std::move(v));
        return *this;
    }
    [[nodiscard]] value done() { return value{std::move(fields_)}; }

private:
    value::map fields_;
};

// A file's text; empty, with `failure` set, when it can't be read.
[[nodiscard]] inline std::string read_text(const std::filesystem::path& path, std::optional<error>& failure) {
    auto bytes = platform::read_file(path);
    if (!bytes) {
        failure = std::move(bytes).error();
        return {};
    }
    return std::string{reinterpret_cast<const char*>(bytes->data()), bytes->size()};
}

// A path with '/' separators, as reports show it.
[[nodiscard]] inline std::string generic(const std::filesystem::path& p) {
    return p.generic_string();
}

// Writes `text` to `path` as a whole (platform::replace_file), creating its folder first.
[[nodiscard]] inline result<void> write_text(const std::filesystem::path& path, std::string_view text) {
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    return platform::replace_file(path, utils::as_bytes(text));
}

// "file::name": a test's id in the JSON report and in `--list` output.
[[nodiscard]] inline std::string test_id(std::string_view file, std::string_view name) {
    return std::format("{}::{}", file, name);
}

// Where a test failed: its failure's file and line, else the test's own.
struct place {
    std::string_view file;
    std::uint32_t line = 0;
};

[[nodiscard]] inline place failure_place(const test_result& r) noexcept {
    return place{r.fail_file.empty() ? std::string_view{r.file} : std::string_view{r.fail_file}, r.fail_line == 0 ? r.line : r.fail_line};
}

} // namespace Rhp::test::detail
