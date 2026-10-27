#include "dev.hpp"

#include <algorithm>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/net/local/local.hpp>
#include <rhp/net/tcp/tcp.hpp>

namespace rhp_cli {

namespace {

// A path as UTF-8 text (path::string() throws on Windows for names outside the code page).
std::string text_of(const std::filesystem::path& path) {
    const std::u8string text = path.u8string();
    return {reinterpret_cast<const char*>(text.data()), text.size()};
}

} // namespace

Rhp::result<std::filesystem::path> pick_dev_session(const std::filesystem::path& dir, std::string_view app) {
    std::error_code ec;
    if (!app.empty()) {
        auto path = Rhp::security::dev_session_path(app, dir);
        if (path && !std::filesystem::is_regular_file(*path, ec)) {
            return Rhp::fail(Rhp::errc::kNotFound, std::format("no dev session of {} in {}: is it running with one?", app, text_of(dir)), "rhp-cli");
        }
        return path;
    }
    std::vector<std::string> apps;
    std::filesystem::path only;
    for (const auto& entry : std::filesystem::directory_iterator{dir, ec}) {
        if (entry.path().extension() == std::filesystem::path{Rhp::security::kDevSessionExtension} && entry.is_regular_file(ec)) {
            apps.push_back(text_of(entry.path().stem()));
            only = entry.path();
        }
    }
    if (apps.empty()) {
        return Rhp::fail(Rhp::errc::kNotFound, std::format("no dev sessions in {}: start the program with a dev session", text_of(dir)), "rhp-cli");
    }
    if (apps.size() > 1) {
        std::ranges::sort(apps);
        std::string names;
        for (const std::string& a : apps) {
            names += names.empty() ? a : ", " + a;
        }
        return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("{} dev sessions ({}): name one, rhp-cli connect --dev <app>", apps.size(), names), "rhp-cli");
    }
    return only;
}

Rhp::result<dev_target> dev_endpoint(const Rhp::security::dev_session& session) {
    if (session.transport == Rhp::net::local_ipc::name) {
        return dev_target{Rhp::endpoint::dial(session.host, 0), true};
    }
    if (session.transport == Rhp::net::tcp::name && Rhp::net::is_loopback_host(session.host)) {
        return dev_target{Rhp::endpoint::dial(session.host, session.port), false};
    }
    return Rhp::fail(Rhp::errc::kForbidden, std::format("the dev session of {} is at {}: rhp-cli connects to dev sessions on a loopback address or local IPC only", session.app, session.endpoint()), "rhp-cli");
}

} // namespace rhp_cli
