#pragma once

// rhp-cli connect --dev [app]: which dev session file to read, and where it may point.

#include <filesystem>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/security/dev_session.hpp>

namespace rhp_cli {

// The dev session file to read in `dir` (security::dev_session_directory()): <dir>/<app>.rhpdev, or
// with no app the only *.rhpdev there. kNotFound when there is none (or none for `app`);
// kInvalidArgument for a bad app name, or for several files and no app (the message lists them).
[[nodiscard]] Rhp::result<std::filesystem::path> pick_dev_session(const std::filesystem::path& dir, std::string_view app);

// What to dial for a dev session: a loopback TCP address, or a local IPC name (`ipc`).
struct dev_target {
    Rhp::endpoint ep;
    bool ipc = false;
};

// kForbidden for any other endpoint: a dev session file that points elsewhere is refused.
[[nodiscard]] Rhp::result<dev_target> dev_endpoint(const Rhp::security::dev_session& session);

} // namespace rhp_cli
