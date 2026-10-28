#include "release_files.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cmath>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <locale>
#include <optional>
#include <span>
#include <sstream>
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
#include <rhp/release/identity_revocations.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/security/identity_file.hpp>

namespace rhp_cli {

namespace {

Rhp::error usage(std::string message) {
    return Rhp::make_error(Rhp::errc::kInvalidArgument, std::move(message), "rhp-cli");
}

Rhp::result<std::uint64_t> parse_seq(const std::string& text, std::chrono::system_clock::time_point now) {
    if (text == "auto") { // Unix seconds: two builds in one second share a seq
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

// A key on the command line: "id=base64", "id=alg:base64" or an identity file (its signer name and
// public key); `channels` after a last '@' when allowed.
struct cli_key {
    std::string id;
    Rhp::security::public_key_ref key;
    std::vector<std::string> channels;
};

Rhp::result<Rhp::security::public_key_ref> key_text(std::string_view text) {
    std::string alg = "ed25519";
    if (const auto colon = text.find(':'); colon != std::string_view::npos) {
        alg = std::string{text.substr(0, colon)};
        text.remove_prefix(colon + 1);
    }
    auto bytes = Rhp::security::base64_decode(text);
    if (!bytes) {
        return std::unexpected{usage(std::format("'{}' is not a base64 public key", text))};
    }
    return Rhp::security::public_key_ref{std::move(alg), std::vector<std::byte>(bytes->begin(), bytes->end())};
}

Rhp::result<cli_key> key_from_file(const std::string& path) {
    auto id = Rhp::security::identity_file::load(path);
    if (!id) {
        return std::unexpected{std::move(id).error()};
    }
    if (!id->signing) {
        return std::unexpected{usage(std::format("{} has no signing key", path))};
    }
    return cli_key{id->signer.empty() ? id->name : id->signer, Rhp::security::key_ref(id->signing->public_key()), {}};
}

Rhp::result<cli_key> parse_cli_key(std::string_view text, bool with_id, bool channels_allowed) {
    std::vector<std::string> channels;
    if (const auto at = text.rfind('@'); channels_allowed && at != std::string_view::npos) {
        for (std::string_view rest = text.substr(at + 1); !rest.empty();) {
            const auto comma = rest.find(',');
            channels.emplace_back(rest.substr(0, comma));
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
        }
        text = text.substr(0, at);
    }
    std::error_code ec;
    if (std::filesystem::is_regular_file(std::filesystem::path{std::string{text}}, ec)) {
        auto k = key_from_file(std::string{text});
        if (k) {
            k->channels = std::move(channels);
        }
        return k;
    }
    std::string id;
    if (with_id) {
        const auto eq = text.find('=');
        if (eq == std::string_view::npos || eq == 0) {
            return std::unexpected{usage(std::format("a key is id=base64, id=alg:base64 or an identity file (got '{}')", text))};
        }
        id = std::string{text.substr(0, eq)};
        text.remove_prefix(eq + 1);
    }
    auto key = key_text(text);
    if (!key) {
        return std::unexpected{std::move(key).error()};
    }
    return cli_key{std::move(id), std::move(*key), std::move(channels)};
}

// Gives `role` the spec's keys (adding them to the root) when it names any, and its threshold.
Rhp::result<void> apply_role(Rhp::release::root_document& d, Rhp::release::root_role role, const root_role_spec& spec) {
    using Rhp::release::root_role;
    Rhp::release::role_keys& keys = d.role(role);
    if (!spec.keys.empty()) {
        keys.keys.clear();
        for (const std::string& text : spec.keys) {
            auto k = parse_cli_key(text, true, role == root_role::kRelease);
            if (!k) {
                return std::unexpected{std::move(k).error()};
            }
            Rhp::release::root_key entry{k->key.alg, k->key.pub, std::move(k->channels)};
            if (const auto it = d.keys.find(k->id); it != d.keys.end() && (it->second.alg != entry.alg || it->second.pub != entry.pub)) {
                return std::unexpected{usage(std::format("key id '{}' already names another key", k->id))};
            }
            if (role == root_role::kRelease || !d.keys.contains(k->id)) {
                d.keys[k->id] = std::move(entry);
            }
            keys.keys.push_back(k->id);
        }
    }
    std::vector<std::string> ids = keys.keys;
    std::ranges::sort(ids);
    const std::size_t distinct = static_cast<std::size_t>(std::ranges::distance(ids.begin(), std::ranges::unique(ids).begin()));
    if (spec.threshold != 0) {
        keys.threshold = spec.threshold;
    } else if (keys.threshold == 0 || keys.threshold > distinct) {
        keys.threshold = 1;
    }
    return {};
}

} // namespace

Rhp::result<Rhp::release::root_document> build_root(const root_spec& spec, const Rhp::release::root_document* base, std::chrono::system_clock::time_point now) {
    using Rhp::release::root_role;
    Rhp::release::root_document d = base != nullptr ? *base : Rhp::release::root_document{};
    d.version = base != nullptr ? base->version + 1 : 1;
    const auto now_s = static_cast<std::uint64_t>(std::max<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count(), 0));
    if (spec.expires_in != 0) {
        d.expires = now_s + spec.expires_in * 86'400;
    } else if (spec.expires != 0 || base == nullptr) {
        d.expires = spec.expires;
    }
    const auto drop_from_roles = [&d](const std::string& id) {
        for (const root_role r : Rhp::release::kRootRoles) {
            std::erase(d.role(r).keys, id);
        }
    };
    for (const std::string& id : spec.retire) {
        if (!d.keys.contains(id)) {
            return std::unexpected{usage(std::format("--retire: the root has no key '{}'", id))};
        }
        d.keys.erase(id);
        drop_from_roles(id);
        std::erase(d.compromised, id);
    }
    for (const std::string& id : spec.compromise) {
        if (!d.keys.contains(id)) {
            return std::unexpected{usage(std::format("--compromise: the root has no key '{}'", id))};
        }
        drop_from_roles(id);
        if (std::ranges::find(d.compromised, id) == d.compromised.end()) {
            d.compromised.push_back(id);
        }
    }
    const std::pair<root_role, const root_role_spec*> roles[] = {
        {root_role::kRoot, &spec.root}, {root_role::kRelease, &spec.release}, {root_role::kRevocation, &spec.revocation}, {root_role::kOperatorCa, &spec.operator_ca}};
    for (const auto& [role, role_spec] : roles) {
        if (auto ok = apply_role(d, role, *role_spec); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
    }
    // Keys no role names any more (and not compromised) leave the root: retired.
    std::erase_if(d.keys, [&d](const auto& entry) {
        const bool used = std::ranges::any_of(Rhp::release::kRootRoles, [&](root_role r) { return std::ranges::find(d.role(r).keys, entry.first) != d.role(r).keys.end(); });
        return !used && std::ranges::find(d.compromised, entry.first) == d.compromised.end();
    });
    if (auto ok = Rhp::release::validate(d); !ok) {
        return std::unexpected{usage(ok.error().message)};
    }
    return d;
}

Rhp::result<Rhp::release::signed_identity_revocations> build_identity_revocations(const identity_revocation_spec& spec, std::chrono::system_clock::time_point now) {
    Rhp::security::identity_revocation_list list;
    auto seq = parse_seq(spec.seq, now);
    if (!seq) {
        return std::unexpected{std::move(seq).error()};
    }
    list.seq = *seq;
    list.issued_at = static_cast<std::uint64_t>(std::max<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count(), 0));
    list.cert_serials = spec.serials;
    for (const auto& [from, into] : {std::pair{&spec.signers, &list.signer_keys}, std::pair{&spec.devices, &list.device_keys}}) {
        for (const std::string& text : *from) {
            auto k = parse_cli_key(text, false, false);
            if (!k) {
                return std::unexpected{std::move(k).error()};
            }
            into->push_back(std::move(k->key));
        }
    }
    return Rhp::release::make_identity_revocations(std::move(list));
}

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
        auto source = read_text_file(path);
        if (!source) {
            return std::unexpected{usage(std::format("can't read module source {}", path))};
        }
        m.modules.push_back(Rhp::release::module_entry{name, {}});
        sources.push_back(std::move(*source));
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

std::string document_tag(std::span<const std::byte> bytes) {
    auto v = Rhp::wire::msgpack::decode(Rhp::utils::bytes_view{bytes.data(), bytes.size()});
    const Rhp::value* tag = v ? v->find("rhp") : nullptr;
    return tag != nullptr && tag->get_if<std::string>() != nullptr ? *tag->get_if<std::string>() : std::string{};
}

std::optional<Rhp::rollout_stage> parse_stage(std::string_view text) {
    const auto colon = text.find(':');
    const std::string_view fraction_text = text.substr(0, colon);
    const std::string_view ms_text = colon == std::string_view::npos ? std::string_view{} : text.substr(colon + 1);
    // Not std::from_chars: Apple's libc++ only has the floating-point overload from macOS 26.
    double fraction = 0;
    std::istringstream number{std::string{fraction_text}};
    number.imbue(std::locale::classic());
    if (fraction_text.empty() || std::isspace(static_cast<unsigned char>(fraction_text.front())) != 0 || !(number >> std::noskipws >> fraction) || number.peek() != std::char_traits<char>::eof() || !std::isfinite(fraction) || fraction < 0.0 ||
        fraction > 1.0) {
        return std::nullopt;
    }
    std::uint64_t ms = 0;
    if (colon != std::string_view::npos) {
        const auto [mend, mec] = std::from_chars(ms_text.data(), ms_text.data() + ms_text.size(), ms);
        if (ms_text.empty() || mec != std::errc{} || mend != ms_text.data() + ms_text.size() || ms > 86'400'000ull * 30) {
            return std::nullopt;
        }
    }
    return Rhp::rollout_stage{fraction, std::chrono::milliseconds{static_cast<std::int64_t>(ms)}};
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

std::string describe(const Rhp::release::signed_root& r, const Rhp::release::signed_root* previous) {
    using Rhp::release::root_role;
    const Rhp::release::root_document& d = r.body;
    std::string out = std::format("root version {} (expires {})\n", d.version, d.expires == 0 ? std::string{"never"} : std::to_string(d.expires));
    for (const auto& [id, k] : d.keys) {
        const bool bad = std::ranges::find(d.compromised, id) != d.compromised.end();
        out += std::format("  key {:<20} {} {}{}{}\n", id, k.alg, Rhp::security::base64_encode(k.pub), k.channels.empty() ? "" : " @" + list_text(k.channels),
                           bad ? "  COMPROMISED" : "");
    }
    for (const root_role role : Rhp::release::kRootRoles) {
        const Rhp::release::role_keys& keys = d.role(role);
        out += std::format("  role {:<12} {} of [{}]\n", Rhp::release::to_string(role), keys.threshold, keys.keys.empty() ? std::string{"-"} : list_text(keys.keys));
    }
    for (const auto& s : r.signatures) {
        out += std::format("  signed by {}\n", s.signer);
    }
    const auto own = Rhp::release::verify_root(r);
    out += own ? "  its own root keys' threshold holds\n" : std::format("  not yet valid alone: {}\n", own.error().message);
    if (previous != nullptr) {
        const auto follows = Rhp::release::verify_next_root(*previous, r);
        out += follows ? std::format("  follows version {}\n", previous->body.version) : std::format("  doesn't follow version {}: {}\n", previous->body.version, follows.error().message);
    }
    return out;
}

std::string describe(const Rhp::release::signed_identity_revocations& r) {
    std::string out = std::format("identity revocations {} (issued {})\n", r.body.seq, r.body.issued_at);
    for (const auto& s : r.body.cert_serials) {
        out += std::format("  certificate serial {}\n", s);
    }
    for (const auto& k : r.body.signer_keys) {
        out += std::format("  signer key  {}:{}\n", k.alg, Rhp::security::base64_encode(k.pub));
    }
    for (const auto& k : r.body.device_keys) {
        out += std::format("  device key  {}:{}\n", k.alg, Rhp::security::base64_encode(k.pub));
    }
    for (const auto& s : r.signatures) {
        out += std::format("  signed by {}\n", s.signer);
    }
    return out;
}

std::string describe(const Rhp::wire::release_status_reply& status) {
    std::string out = std::format("app {} build {} on {}; revocation list {}\n", status.app.empty() ? "-" : status.app,
                                  status.build.empty() ? "-" : status.build, status.platform, status.revocation_seq);
    if (status.root_version != 0 || status.identity_seq != 0) {
        out += std::format("root of trust version {}; identity revocations {}\n", status.root_version, status.identity_seq);
    }
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
