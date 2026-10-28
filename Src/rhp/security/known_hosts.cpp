// Pinned host keys: text and files only (built with RHP_ENABLE=OFF too).
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <format>
#include <iterator>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/security/detail/text.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/known_hosts.hpp>

namespace Rhp::security {

struct known_hosts::state {
    mutable std::mutex mutex;
    std::vector<known_host> hosts;
    std::filesystem::path file; // empty: in memory only
};

namespace {

constexpr const char* kWhere = "security.known_hosts";

[[nodiscard]] result<void> check_entry(const known_host& h) {
    const bool bad_endpoint = h.endpoint.empty() || std::ranges::any_of(h.endpoint, [](char c) { return c == '#' || c == ' ' || c == '\t' || c == '\r' || c == '\n'; });
    if (bad_endpoint) {
        return fail(errc::kInvalidArgument, std::format("'{}' is no endpoint name (not empty, no spaces or '#')", h.endpoint), kWhere);
    }
    if (h.public_key.size() != key_handle::public_key_size(h.alg)) {
        return fail(errc::kInvalidArgument, std::format("a {} public key is {} bytes, got {}", to_string(h.alg), key_handle::public_key_size(h.alg), h.public_key.size()), kWhere);
    }
    return {};
}

[[nodiscard]] std::string text_of(const std::vector<known_host>& hosts) {
    std::string out;
    for (const known_host& h : hosts) {
        out += std::format("{} {} {}\n", h.endpoint, to_string(h.alg), base64_encode(h.public_key));
    }
    return out;
}

} // namespace

known_hosts::known_hosts() : state_(std::make_shared<state>()) {}

result<known_hosts> known_hosts::parse(std::string_view text) {
    known_hosts out;
    for (const detail::text_line& line : detail::content_lines(text)) {
        const auto f = detail::fields(line.text);
        if (f.size() != 3) {
            return fail(errc::kInvalidArgument, std::format("line {}: expected `endpoint alg base64-public-key`", line.number), kWhere);
        }
        const auto alg = parse_key_algorithm(f[1]);
        if (!alg) {
            return fail(errc::kInvalidArgument, std::format("line {}: unknown algorithm '{}' (ed25519 or p256)", line.number, f[1]), kWhere);
        }
        auto pub = base64_decode(f[2]);
        if (!pub) {
            return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, pub.error().message), kWhere);
        }
        known_host h{std::string{f[0]}, *alg, std::move(*pub)};
        if (auto ok = check_entry(h); !ok) {
            return fail(errc::kInvalidArgument, std::format("line {}: {}", line.number, ok.error().message), kWhere);
        }
        if (std::ranges::find(out.state_->hosts, h) == out.state_->hosts.end()) {
            out.state_->hosts.push_back(std::move(h));
        }
    }
    return out;
}

result<known_hosts> known_hosts::load(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        known_hosts out;
        out.state_->file = path;
        return out;
    }
    const auto text = detail::read_file(path);
    if (!text) {
        return fail(errc::kNotFound, std::format("can't read known hosts file {}", path.string()), kWhere);
    }
    auto out = parse(*text);
    if (out) {
        out->state_->file = path;
    }
    return out;
}

known_hosts::match known_hosts::check(std::string_view endpoint, key_algorithm alg, std::span<const std::byte> public_key) const {
    const std::scoped_lock lock{state_->mutex};
    bool any = false;
    for (const known_host& h : state_->hosts) {
        if (h.endpoint != endpoint) {
            continue;
        }
        if (h.alg == alg && std::ranges::equal(h.public_key, public_key)) {
            return match::kPinned;
        }
        any = true;
    }
    return any ? match::kChanged : match::kUnknown;
}

std::vector<known_host> known_hosts::find(std::string_view endpoint) const {
    const std::scoped_lock lock{state_->mutex};
    std::vector<known_host> out;
    std::ranges::copy_if(state_->hosts, std::back_inserter(out), [&](const known_host& h) { return h.endpoint == endpoint; });
    return out;
}

result<void> known_hosts::add(known_host entry) {
    if (auto ok = check_entry(entry); !ok) {
        return ok;
    }
    const std::scoped_lock lock{state_->mutex};
    if (std::ranges::find(state_->hosts, entry) != state_->hosts.end()) {
        return {};
    }
    state_->hosts.push_back(std::move(entry));
    if (state_->file.empty()) {
        return {};
    }
    const std::string text = text_of(state_->hosts);
    return platform::write_private_file(state_->file, std::as_bytes(std::span{text}));
}

std::vector<known_host> known_hosts::entries() const {
    const std::scoped_lock lock{state_->mutex};
    return state_->hosts;
}

std::string known_hosts::to_text() const {
    const std::scoped_lock lock{state_->mutex};
    return text_of(state_->hosts);
}

result<void> known_hosts::save(const std::filesystem::path& path) const {
    const std::string text = to_text();
    return platform::write_private_file(path, std::as_bytes(std::span{text}));
}

} // namespace Rhp::security
