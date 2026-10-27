#pragma once

// Private to Src/rhp/test: the fuzz corpus, inputs test.fuzz saved as Lua text under
// <test file's folder>/__fuzz__/<test file's stem>/<target>/.

#include <filesystem>
#include <string>
#include <vector>

#include <rhp/core/value.hpp>

namespace Rhp::test::detail {

// The folder of a fuzz target's inputs (`test_file` relative to `root`).
[[nodiscard]] std::filesystem::path corpus_dir(const std::filesystem::path& root, const std::string& test_file, const std::string& name);

// The inputs saved in `dir`, by file name.
[[nodiscard]] value corpus_load(const std::filesystem::path& dir);

// Saves an input in `dir` ("crash-", "cov-" or "input-<crc32c>.lua", unless it is there); its path. A
// failed write is noted.
value corpus_save(const std::filesystem::path& dir, const std::string& text, const std::string& kind, std::vector<std::string>& notes);

} // namespace Rhp::test::detail
