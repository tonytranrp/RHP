#pragma once

// Private to Src/rhp/test (not installed): helpers the runner, the reporters and the command line share.

#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/files.hpp>
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

// Writes `text` to `path` as a whole (platform::replace_file), creating its folder first.
[[nodiscard]] inline result<void> write_text(const std::filesystem::path& path, std::string_view text) {
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }
    return platform::replace_file(path, utils::as_bytes(text));
}

} // namespace Rhp::test::detail
