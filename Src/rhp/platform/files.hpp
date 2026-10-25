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
// new one, never a mix: the bytes go to a temporary file next to it (with a name of its own; on POSIX
// readable by its owner only, on Windows with the folder's permissions), are flushed to the device,
// and the temporary file is renamed over `path` (written through on Windows; the directory is synced
// on POSIX). A crash between the two can leave a "*.tmp" file behind.
[[nodiscard]] result<void> replace_file(const std::filesystem::path& path, std::span<const std::byte> bytes);

// Creates `path` (and its parents) if missing; on POSIX every directory it creates is its owner's only.
[[nodiscard]] result<void> make_private_directory(const std::filesystem::path& path);

} // namespace Rhp::platform
