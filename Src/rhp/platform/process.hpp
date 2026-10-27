#pragma once

#include <filesystem>
#include <span>
#include <string>

#include <rhp/core/result.hpp>

namespace Rhp::platform {

// Runs `program` with `args` (not including the program itself), sharing this process's standard
// input, output and error, and waits for it. Returns its exit status (128 + the signal number when
// a signal ended it). A program without a folder is looked up on PATH. kDisabled on iOS.
[[nodiscard]] result<int> run_process(const std::filesystem::path& program, std::span<const std::string> args);

// The value of this process's environment variable `name` ("" when it isn't set).
[[nodiscard]] std::string environment_variable(const std::string& name);

} // namespace Rhp::platform
