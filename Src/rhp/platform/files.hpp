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

// replace_file for secrets (keys and the files holding them): the file is its owner's alone on
// every OS. The temporary is created that way before any byte goes in (POSIX: O_EXCL, mode 0600;
// Windows: an explicit DACL that grants the process token's user full access and nobody else, with
// the folder's inherited permissions blocked), and the rename keeps it, so an existing file loses
// wider permissions too.
[[nodiscard]] result<void> write_private_file(const std::filesystem::path& path, std::span<const std::byte> bytes);

// Whether users other than the file's owner may read `path`. POSIX: the group or other read bit;
// Windows: no DACL, or an allow ACE granting read to anyone but the owner, this process's user,
// SYSTEM and the Administrators group. False when it can't tell (no such file).
[[nodiscard]] bool readable_by_others(const std::filesystem::path& path) noexcept;

// Creates `path` (and its parents) if missing; on POSIX every directory it creates is its owner's only.
[[nodiscard]] result<void> make_private_directory(const std::filesystem::path& path);

// This user's folder for application settings: %APPDATA% (Windows), ~/Library/Application Support
// (macOS), $XDG_CONFIG_HOME or else ~/.config (Linux). kNotFound when the variable it comes from isn't
// set; kDisabled on iOS and Android, where apps have no user folder to share.
[[nodiscard]] result<std::filesystem::path> user_config_dir();

// Standard output is a terminal (not a file or a pipe).
[[nodiscard]] bool stdout_is_terminal() noexcept;

// Standard input is a terminal (not a file or a pipe).
[[nodiscard]] bool stdin_is_terminal() noexcept;

// Lets the terminal on standard output show ANSI colors (turns them on in a Windows console); false
// when it can't.
[[nodiscard]] bool enable_ansi_colors() noexcept;

// Makes standard input and output binary (no newline translation on Windows; nothing elsewhere):
// for byte-counted protocols over stdio (rhp-cli dap).
void binary_stdio() noexcept;

} // namespace Rhp::platform
