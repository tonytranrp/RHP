#include "release_files.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "text.hpp"

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>

namespace rhp_cli {

namespace {

Rhp::error usage(std::string message) {
    return Rhp::make_error(Rhp::errc::kInvalidArgument, std::move(message), "rhp-cli");
}

Rhp::result<std::uint64_t> parse_seq(const std::string& text, std::chrono::system_clock::time_point now) {
    if (text == "auto") {
        const auto s = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        return static_cast<std::uint64_t>(std::max<std::int64_t>(s, 1));
    }
    std::uint64_t n = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), n);
    if (ec != std::errc{} || end != text.data() + text.size() || n == 0) {
        return std::unexpected{usage(std::format("--seq is a number from 1, or auto (got '{}')", text))};
    }
    return n;
}

std::string id_text(const Rhp::value::bytes& id) {
    if (id.size() != Rhp::release::release_id{}.size()) {
        return id.empty() ? "-" : "?";
    }
    Rhp::release::release_id out{};
    std::ranges::copy(id, out.begin());
    return Rhp::release::short_id(out);
}

std::string list_text(const std::vector<std::string>& items) {
    if (items.empty()) {
        return "any";
    }
    std::string out;
    for (const auto& item : items) {
        out += (out.empty() ? "" : ", ") + item;
    }
    return out;
}

} // namespace

Rhp::result<Rhp::release::release> build_release(const release_spec& spec, std::chrono::system_clock::time_point now) {
    Rhp::release::manifest m;
    m.channel = spec.channel;
    auto seq = parse_seq(spec.seq, now);
    if (!seq) {
        return std::unexpected{std::move(seq).error()};
    }
    m.seq = *seq;
    m.label = spec.label;
    m.app = spec.app;
    m.builds = spec.builds;
    m.platforms = spec.platforms;
    m.not_before = spec.not_before;
    m.not_after = spec.not_after;
    const auto role = Rhp::parse_role(spec.role);
    if (!role) {
        return std::unexpected{usage(std::format("--role is patch or admin (got '{}')", spec.role))};
    }
    m.run_as = *role;
    m.libs = spec.libs;
    m.health.fail_events = spec.fail_events;
    m.health.max_handler_failures = spec.max_handler_failures;
    std::vector<std::string> sources;
    for (const std::string& item : spec.modules) {
        const auto eq = item.find('=');
        const std::string path = eq == std::string::npos ? item : item.substr(eq + 1);
        const std::string name = eq == std::string::npos ? module_name_for(path) : item.substr(0, eq);
        auto bytes = Rhp::platform::read_file(path);
        if (!bytes) {
            return std::unexpected{usage(std::format("can't read module source {}", path))};
        }
        std::string source(bytes->size(), '\0');
        std::ranges::transform(*bytes, source.begin(), [](std::byte b) { return static_cast<char>(b); });
        m.modules.push_back(Rhp::release::module_entry{name, {}});
        sources.push_back(std::move(source));
    }
    return Rhp::release::make_release(std::move(m), std::move(sources));
}

Rhp::result<Rhp::release::signed_revocations> build_revocations(const revocation_spec& spec, std::chrono::system_clock::time_point now) {
    Rhp::release::revocation_list list;
    auto seq = parse_seq(spec.seq, now);
    if (!seq) {
        return std::unexpected{std::move(seq).error()};
    }
    list.seq = *seq;
    list.issued_at = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
    for (const std::string& hex : spec.releases) {
        auto id = Rhp::release::id_from_hex(hex);
        if (!id) {
            return std::unexpected{usage(std::format("--release '{}': {}", hex, id.error().message))};
        }
        list.releases.push_back(*id);
    }
    for (const std::string& text : spec.keys) {
        auto key = Rhp::security::ed25519_public_key::from_base64(text);
        if (!key) {
            return std::unexpected{usage(std::format("--key '{}': {}", text, key.error().message))};
        }
        list.keys.push_back(*key);
    }
    for (const std::string& floor : spec.floors) {
        const auto eq = floor.find('=');
        std::uint64_t n = 0;
        const std::string_view digits = eq == std::string::npos ? std::string_view{} : std::string_view{floor}.substr(eq + 1);
        const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
        if (eq == std::string::npos || ec != std::errc{} || end != digits.data() + digits.size()) {
            return std::unexpected{usage(std::format("--floor is channel=seq (got '{}')", floor))};
        }
        list.floors.push_back(Rhp::release::seq_floor{floor.substr(0, eq), n});
    }
    return Rhp::release::make_revocations(std::move(list));
}

Rhp::result<std::vector<std::byte>> read_binary_file(const std::filesystem::path& path) {
    return Rhp::platform::read_file(path);
}

Rhp::result<void> write_binary_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    return Rhp::platform::replace_file(path, bytes);
}

std::string describe(const Rhp::release::release& r) {
    const Rhp::release::manifest& m = r.body;
    std::string out = std::format("release {}\n", Rhp::release::to_hex(r.id));
    out += std::format("  channel    {}\n  seq        {}\n", m.channel, m.seq);
    if (!m.label.empty()) {
        out += std::format("  label      {}\n", m.label);
    }
    out += std::format("  app        {}\n  builds     {}\n  platforms  {}\n", m.app.empty() ? "any" : m.app, list_text(m.builds), list_text(m.platforms));
    out += std::format("  valid      {} .. {}\n", m.not_before == 0 ? std::string{"-"} : std::to_string(m.not_before),
                       m.not_after == 0 ? std::string{"-"} : std::to_string(m.not_after));
    out += std::format("  runs as    {}\n  needs libs {}\n", m.run_as, m.libs.empty() ? std::string{"-"} : list_text(m.libs));
    if (!m.health.fail_events.empty() || m.health.max_handler_failures != 0) {
        out += std::format("  health     fail on {}; {} handler failures allowed\n", list_text(m.health.fail_events), m.health.max_handler_failures);
    }
    for (std::size_t i = 0; i < m.modules.size(); ++i) {
        out += std::format("  module     {} ({} bytes, {})\n", m.modules[i].name, i < r.sources.size() ? r.sources[i].size() : 0,
                           Rhp::release::short_id(m.modules[i].hash));
    }
    if (r.signatures.empty()) {
        out += "  unsigned\n";
    }
    for (const auto& s : r.signatures) {
        out += std::format("  signed by  {}\n", s.signer);
    }
    if (!r.revocations.empty()) {
        out += "  carries a revocation list\n";
    }
    return out;
}

std::string describe(const Rhp::release::signed_revocations& r) {
    std::string out = std::format("revocation list {} (issued {})\n", r.body.seq, r.body.issued_at);
    for (const auto& id : r.body.releases) {
        out += std::format("  release  {}\n", Rhp::release::to_hex(id));
    }
    for (const auto& key : r.body.keys) {
        out += std::format("  key      {}\n", key.to_base64());
    }
    for (const auto& f : r.body.floors) {
        out += std::format("  floor    {} > {}\n", f.channel, f.seq);
    }
    for (const auto& s : r.signatures) {
        out += std::format("  signed by {}\n", s.signer);
    }
    return out;
}

std::string describe(const Rhp::wire::release_status_reply& status) {
    std::string out = std::format("app {} build {} on {}; revocation list {}\n", status.app.empty() ? "-" : status.app,
                                  status.build.empty() ? "-" : status.build, status.platform, status.revocation_seq);
    if (status.channels.empty()) {
        out += "  no channels\n";
    }
    for (const auto& c : status.channels) {
        out += std::format("  {:<24} {:<9}", c.channel, c.running);
        if (c.active) {
            out += std::format(" active {} seq {}", id_text(c.active->id), c.active->seq);
        }
        if (c.candidate) {
            out += std::format(" candidate {} seq {} ({}, {} restarts)", id_text(c.candidate->id), c.candidate->seq, c.confirm, c.attempts);
        }
        out += std::format(" floor {}{}\n", c.floor, c.held ? " held" : "");
    }
    return out;
}

} // namespace rhp_cli
