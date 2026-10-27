#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/security/identity_file.hpp>

namespace Rhp::security {

// A dev session's connect file (decision AL7): a dev build's host listening on loopback or local IPC
// generates an identity for the run, trusts its signing key and writes this file owner-only to
// dev_session_path(app); `rhp-cli connect --dev [app]` reads it and connects with no key files. The
// host removes it when it stops. Any process of the same user can read it: dev machines only.
//
// The identity file's text with two more lines:
//
//   app         = "my_game"
//   endpoint    = "tcp://127.0.0.1:7777"     # or "local_ipc://my_game"; [::1] in brackets
//   name        = "dev"
//   psk         = "base64..."
//   signing_key = "base64..."
//
// Reading doesn't check where the endpoint points (security doesn't know the transports): whoever
// connects refuses anything but a loopback address or local IPC.
struct dev_session {
    std::string app;
    std::string transport;  // a transport's `name`: "tcp", "local_ipc", ...
    std::string host;       // the address, or for local_ipc the endpoint name
    std::uint16_t port = 0; // 0 for local_ipc
    identity_file identity; // name, psk, signing key

    [[nodiscard]] static result<dev_session> parse(std::string_view text);
    // The text of the file (it holds the secrets: wipe it when done).
    [[nodiscard]] std::string to_text() const;
    // "tcp://127.0.0.1:7777", "tcp://[::1]:7777", "local_ipc://my_game".
    [[nodiscard]] std::string endpoint() const;
};

inline constexpr std::string_view kDevSessionExtension = ".rhpdev";

// Writes `session` to `path` atomically and owner-only (platform::write_private_file), making its
// folder (owner-only on POSIX) when missing.
[[nodiscard]] result<void> write_dev_session(const std::filesystem::path& path, const dev_session& session);

// Reads a dev session file; its identity's warnings say what's unsafe (readable by other users).
// kNotFound when there is no file.
[[nodiscard]] result<dev_session> read_dev_session(const std::filesystem::path& path);

// Where dev session files go: <platform::user_config_dir()>/rhp/dev (kDisabled on iOS and Android).
[[nodiscard]] result<std::filesystem::path> dev_session_directory();

// <dir>/<app>.rhpdev, by default in dev_session_directory(). kInvalidArgument unless `app` is 1..64
// letters, digits, '.', '_' or '-' starting with a letter or digit, so it can't leave the folder.
[[nodiscard]] result<std::filesystem::path> dev_session_path(std::string_view app, const std::filesystem::path& dir);
[[nodiscard]] result<std::filesystem::path> dev_session_path(std::string_view app);

} // namespace Rhp::security
