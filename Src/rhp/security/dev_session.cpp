#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/dev_session.hpp>
#include <rhp/security/identity_file.hpp>
#include <rhp/security/key.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

namespace {

constexpr std::string_view kSessionWhere = "security.dev_session";
// Rhp::net::local_ipc::name (security sits beside net, not above it): its address is a name, not host:port.
constexpr std::string_view kLocalIpc = "local_ipc";

[[nodiscard]] result<void> check_app(std::string_view app) {
    constexpr std::string_view kAllowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
    if (app.empty() || app.size() > 64 || app.find_first_not_of(kAllowed) != std::string_view::npos || kAllowed.find(app.front()) >= 62) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not an app name (1..64 letters, digits, '.', '_' or '-', starting with a letter or digit)", app), std::string{kSessionWhere});
    }
    return {};
}

// "transport://host:port" ("[v6]:port"), or "local_ipc://name".
[[nodiscard]] result<void> read_endpoint(dev_session& s, std::string_view text) {
    const auto scheme = text.find("://");
    if (scheme == std::string_view::npos || scheme == 0 || scheme + 3 == text.size()) {
        return fail(errc::kInvalidArgument, "the endpoint must be transport://address", std::string{kSessionWhere});
    }
    s.transport = text.substr(0, scheme);
    std::string_view address = text.substr(scheme + 3);
    if (s.transport == kLocalIpc) {
        s.host = address;
        s.port = 0;
        return {};
    }
    const auto colon = address.rfind(':');
    std::string_view host = colon == std::string_view::npos ? std::string_view{} : address.substr(0, colon);
    const std::string_view port = colon == std::string_view::npos ? std::string_view{} : address.substr(colon + 1);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    } else if (host.find(':') != std::string_view::npos) {
        return fail(errc::kInvalidArgument, "write IPv6 addresses in brackets: tcp://[::1]:7777", std::string{kSessionWhere});
    }
    const auto [end, ec] = std::from_chars(port.data(), port.data() + port.size(), s.port);
    if (host.empty() || ec != std::errc{} || end != port.data() + port.size() || s.port == 0) {
        return fail(errc::kInvalidArgument, std::format("the endpoint '{}' needs host:port", address), std::string{kSessionWhere});
    }
    s.host = host;
    return {};
}

} // namespace

result<dev_session> dev_session::parse(std::string_view text) {
    dev_session out;
    bool has_endpoint = false;
    auto id = identity_file::parse(text, [&](std::string_view field, std::string_view v) -> result<bool> {
        if (field == "app") {
            out.app = v;
            return true;
        }
        if (field == "endpoint") {
            if (auto read = read_endpoint(out, v); !read) {
                return std::unexpected{std::move(read).error()};
            }
            has_endpoint = true;
            return true;
        }
        return false;
    });
    if (!id) {
        return std::unexpected{std::move(id).error()};
    }
    if (!has_endpoint) {
        return fail(errc::kInvalidArgument, "a dev session file needs an endpoint", std::string{kSessionWhere});
    }
    if (auto app = check_app(out.app); !app) {
        return std::unexpected{std::move(app).error()};
    }
    out.identity = std::move(*id);
    return out;
}

std::string dev_session::endpoint() const {
    if (transport == kLocalIpc) {
        return std::format("{}://{}", transport, host);
    }
    if (host.find(':') != std::string::npos) {
        return std::format("{}://[{}]:{}", transport, host, port);
    }
    return std::format("{}://{}:{}", transport, host, port);
}

std::string dev_session::to_text() const {
    // As identity_file::to_text: the secrets' text is wiped and the whole text reserved up front.
    std::string id = identity.to_text();
    const utils::scope_guard wipe{[&id]() noexcept { secure_wipe(id.data(), id.size()); }};
    const std::string head = std::format("# RHP dev session of {0}: written while it runs, removed when it stops (rhp-cli connect --dev {0})\n"
                                         "app         = \"{0}\"\n"
                                         "endpoint    = \"{1}\"\n",
                                         app, endpoint());
    std::string text;
    text.reserve(head.size() + id.size());
    text += head;
    text += id;
    return text;
}

result<void> write_dev_session(const std::filesystem::path& path, const dev_session& session) {
    if (auto app = check_app(session.app); !app) {
        return app;
    }
    if (session.transport.empty() || session.host.empty() || session.identity.name.empty() || session.identity.psk.empty()) {
        return fail(errc::kInvalidArgument, "a dev session needs an endpoint and an identity", std::string{kSessionWhere});
    }
    if (path.has_parent_path()) {
        if (auto made = platform::make_private_directory(path.parent_path()); !made) {
            return made;
        }
    }
    std::string text = session.to_text();
    auto written = platform::write_private_file(path, std::as_bytes(std::span{text}));
    secure_wipe(text.data(), text.size());
    return written;
}

result<dev_session> read_dev_session(const std::filesystem::path& path) {
    auto text = detail::read_file(path);
    if (!text) {
        const std::u8string name = path.u8string();
        return fail(errc::kNotFound, std::format("can't read dev session file {}", std::string_view{reinterpret_cast<const char*>(name.data()), name.size()}), std::string{kSessionWhere});
    }
    auto session = dev_session::parse(*text);
    secure_wipe(text->data(), text->size());
    if (auto warning = session ? detail::exposure_warning(path) : std::nullopt) {
        session->identity.warnings.push_back(std::move(*warning));
    }
    return session;
}

result<std::filesystem::path> dev_session_directory() {
    auto config = platform::user_config_dir();
    if (!config) {
        return std::unexpected{std::move(config).error()};
    }
    return *config / "rhp" / "dev";
}

result<std::filesystem::path> dev_session_path(std::string_view app, const std::filesystem::path& dir) {
    if (auto valid = check_app(app); !valid) {
        return std::unexpected{std::move(valid).error()};
    }
    std::string file{app};
    file += kDevSessionExtension;
    return dir / file;
}

result<std::filesystem::path> dev_session_path(std::string_view app) {
    auto dir = dev_session_directory();
    if (!dir) {
        return std::unexpected{std::move(dir).error()};
    }
    return dev_session_path(app, *dir);
}

} // namespace Rhp::security
