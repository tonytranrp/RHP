#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/test/detail/fuzz_corpus.hpp>
#include <rhp/test/detail/support.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>

namespace Rhp::test::detail {

namespace {

namespace fs = std::filesystem;

} // namespace

fs::path corpus_dir(const fs::path& root, const std::string& test_file, const std::string& name) {
    std::string safe;
    for (const char c : name) {
        safe += (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_') ? c : '_';
    }
    if (safe.size() > 70) {
        safe.resize(70);
    }
    // The hash of the exact name: "a+b" and "a b", or names differing only in case, don't share inputs.
    safe = std::format("{}_{:08x}", safe, utils::crc32c(utils::as_bytes(name)));
    const fs::path file{test_file};
    return root / file.parent_path() / "__fuzz__" / file.stem() / safe;
}

value corpus_load(const fs::path& dir) {
    value::array out;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) {
        return value{std::move(out)};
    }
    std::vector<fs::path> files;
    for (fs::directory_iterator it{dir, ec}, end; !ec && it != end; it.increment(ec)) {
        if (it->is_regular_file() && it->path().extension() == ".lua") {
            files.push_back(it->path());
        }
    }
    std::ranges::sort(files);
    for (const fs::path& p : files) {
        std::optional<error> failure;
        std::string text = read_text(p, failure);
        if (!failure) {
            out.emplace_back(std::move(text));
        }
    }
    return value{std::move(out)};
}

value corpus_save(const fs::path& dir, const std::string& text, const std::string& kind, std::vector<std::string>& notes) {
    const std::uint32_t hash = utils::crc32c(utils::as_bytes(text));
    const std::string_view what = kind == "crash" || kind == "cov" ? std::string_view{kind} : std::string_view{"input"};
    const fs::path path = dir / std::format("{}-{:08x}.lua", what, hash);
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        if (auto written = write_text(path, text); !written) {
            notes.push_back(std::format("can't save a fuzz input to {}: {}", generic(path), written.error()));
        }
    }
    return value{generic(path)};
}

} // namespace Rhp::test::detail
