#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <vector>

#include <rhp/core/result.hpp>

namespace Rhp::platform {

// The whole file (kNotFound when it doesn't exist, kRuntime when it can't be read).
[[nodiscard]] result<std::vector<std::byte>> read_file(const std::filesystem::path& path);

// Replaces `path` with `bytes` so that a crash or power loss leaves either the old file or the
// new one, never a mix: the bytes go to a temporary file next to it, are flushed to the device,
// and the temporary file is renamed over `path` (the directory is synced too where the OS allows).
[[nodiscard]] result<void> replace_file(const std::filesystem::path& path, std::span<const std::byte> bytes);

// Creates `path` (and its parents) if missing; on POSIX the new directory is readable by its
// owner only.
[[nodiscard]] result<void> make_private_directory(const std::filesystem::path& path);

} // namespace Rhp::platform
