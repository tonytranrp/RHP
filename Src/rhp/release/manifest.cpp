#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/bytecode.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>

namespace Rhp::release {

namespace detail {

error bad_body(std::string message) {
    return make_error(errc::kProtocol, std::move(message), "release.manifest");
}

std::vector<std::byte> signed_message(std::string_view domain, std::span<const std::byte> body) {
    std::vector<std::byte> out(domain.size() + body.size());
    std::memcpy(out.data(), domain.data(), domain.size());
    if (!body.empty()) {
        std::memcpy(out.data() + domain.size(), body.data(), body.size());
    }
    return out;
}

std::vector<std::string> canonical_set(std::vector<std::string> items) {
    std::ranges::sort(items);
    const auto dup = std::ranges::unique(items);
    items.erase(dup.begin(), dup.end());
    return items;
}

value string_array(const std::vector<std::string>& items) {
    value::array out;
    out.reserve(items.size());
    for (const std::string& s : items) {
        out.emplace_back(s);
    }
    return value{std::move(out)};
}

result<std::vector<std::byte>> encode(const value& v) {
    utils::byte_buffer out;
    if (auto ok = wire::msgpack::encode(v, out); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const auto bytes = out.view();
    return std::vector<std::byte>(bytes.begin(), bytes.end());
}

result<value> decode(std::span<const std::byte> bytes) {
    return wire::msgpack::decode(utils::bytes_view{bytes.data(), bytes.size()});
}

// ---- strict readers --------------------------------------------------------------------------

result<const value::map*> fields(const value& v, std::string_view what) {
    const auto* m = v.get_if<value::map>();
    if (m == nullptr) {
        return std::unexpected{bad_body(std::format("{} is not a map", what))};
    }
    return m;
}

result<const value*> field(const value::map& m, std::size_t index, std::string_view key) {
    if (index >= m.size()) {
        return std::unexpected{bad_body(std::format("field '{}' is missing", key))};
    }
    const auto* name = m[index].first.get_if<std::string>();
    if (name == nullptr || *name != key) {
        return std::unexpected{bad_body(std::format("expected field '{}' at position {}", key, index + 1))};
    }
    return &m[index].second;
}

result<std::string> text(const value& v, std::string_view key) {
    const auto* s = v.get_if<std::string>();
    if (s == nullptr) {
        return std::unexpected{bad_body(std::format("'{}' must be a string", key))};
    }
    return *s;
}

result<std::uint64_t> count(const value& v, std::string_view key) {
    const auto* i = v.get_if<std::int64_t>();
    if (i == nullptr || *i < 0) {
        return std::unexpected{bad_body(std::format("'{}' must be a non-negative integer", key))};
    }
    return static_cast<std::uint64_t>(*i);
}

result<std::vector<std::string>> texts(const value& v, std::string_view key) {
    const auto* a = v.get_if<value::array>();
    if (a == nullptr || a->size() > kMaxListEntries) {
        return std::unexpected{bad_body(std::format("'{}' must be an array of at most {} strings", key, kMaxListEntries))};
    }
    std::vector<std::string> out;
    out.reserve(a->size());
    for (const value& item : *a) {
        const auto* s = item.get_if<std::string>();
        if (s == nullptr) {
            return std::unexpected{bad_body(std::format("'{}' must hold strings", key))};
        }
        out.push_back(*s);
    }
    return out;
}

result<security::digest256> digest(const value& v, std::string_view key) {
    const auto* b = v.get_if<value::bytes>();
    if (b == nullptr || b->size() != security::digest256{}.size()) {
        return std::unexpected{bad_body(std::format("'{}' must be 32 bytes", key))};
    }
    security::digest256 out{};
    std::ranges::copy(*b, out.begin());
    return out;
}

value digest_value(const security::digest256& d) {
    return value{value::bytes(d.begin(), d.end())};
}

result<void> exact_size(const value::map& m, std::size_t n, std::string_view what) {
    if (m.size() != n) {
        return std::unexpected{bad_body(std::format("{} must have exactly {} fields", what, n))};
    }
    return {};
}

bool fits(std::uint64_t n) {
    return n <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
}

bool valid_channel(std::string_view name) {
    if (name.empty() || name.size() > kMaxChannelName || name.front() == '.' || name.back() == '.') {
        return false;
    }
    char previous = '.';
    for (const char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok || (c == '.' && previous == '.')) {
            return false;
        }
        previous = c;
    }
    return true;
}

} // namespace detail

namespace {

using detail::bad_body;

constexpr std::string_view kDigits = "0123456789abcdef";

value manifest_value(const manifest& m) {
    value::array modules;
    modules.reserve(m.modules.size());
    for (const module_entry& mod : m.modules) {
        value::map entry;
        entry.emplace_back(value{"name"}, value{mod.name});
        entry.emplace_back(value{"hash"}, detail::digest_value(mod.hash));
        modules.emplace_back(std::move(entry));
    }
    value::map health;
    health.emplace_back(value{"fail_events"}, detail::string_array(detail::canonical_set(m.health.fail_events)));
    health.emplace_back(value{"max_handler_failures"}, value{m.health.max_handler_failures});

    value::map out;
    out.emplace_back(value{"rhp"}, value{"release"});
    out.emplace_back(value{"channel"}, value{m.channel});
    out.emplace_back(value{"seq"}, value{m.seq});
    out.emplace_back(value{"label"}, value{m.label});
    out.emplace_back(value{"app"}, value{m.app});
    out.emplace_back(value{"builds"}, detail::string_array(detail::canonical_set(m.builds)));
    out.emplace_back(value{"platforms"}, detail::string_array(detail::canonical_set(m.platforms)));
    out.emplace_back(value{"not_before"}, value{m.not_before});
    out.emplace_back(value{"not_after"}, value{m.not_after});
    out.emplace_back(value{"role"}, value{to_string(m.run_as)});
    out.emplace_back(value{"libs"}, detail::string_array(detail::canonical_set(m.libs)));
    out.emplace_back(value{"modules"}, value{std::move(modules)});
    out.emplace_back(value{"health"}, value{std::move(health)});
    return value{std::move(out)};
}

#define RHP_TRY(var, expr)                                  \
    auto var##_r = (expr);                                  \
    if (!var##_r) {                                         \
        return std::unexpected{std::move(var##_r).error()}; \
    }                                                       \
    auto var = std::move(*var##_r)

result<manifest> manifest_from(const value& v) {
    RHP_TRY(m, detail::fields(v, "a release body"));
    if (auto ok = detail::exact_size(*m, 13, "a release body"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    manifest out;
    RHP_TRY(tag, detail::field(*m, 0, "rhp"));
    RHP_TRY(tag_text, detail::text(*tag, "rhp"));
    if (tag_text != "release") {
        return std::unexpected{bad_body(std::format("this is a '{}' document, not a release", tag_text))};
    }
    RHP_TRY(channel, detail::field(*m, 1, "channel"));
    RHP_TRY(channel_text, detail::text(*channel, "channel"));
    out.channel = std::move(channel_text);
    RHP_TRY(seq, detail::field(*m, 2, "seq"));
    RHP_TRY(seq_n, detail::count(*seq, "seq"));
    out.seq = seq_n;
    RHP_TRY(label, detail::field(*m, 3, "label"));
    RHP_TRY(label_text, detail::text(*label, "label"));
    out.label = std::move(label_text);
    RHP_TRY(app, detail::field(*m, 4, "app"));
    RHP_TRY(app_text, detail::text(*app, "app"));
    out.app = std::move(app_text);
    RHP_TRY(builds, detail::field(*m, 5, "builds"));
    RHP_TRY(builds_list, detail::texts(*builds, "builds"));
    out.builds = std::move(builds_list);
    RHP_TRY(platforms, detail::field(*m, 6, "platforms"));
    RHP_TRY(platforms_list, detail::texts(*platforms, "platforms"));
    out.platforms = std::move(platforms_list);
    RHP_TRY(not_before, detail::field(*m, 7, "not_before"));
    RHP_TRY(not_before_n, detail::count(*not_before, "not_before"));
    out.not_before = not_before_n;
    RHP_TRY(not_after, detail::field(*m, 8, "not_after"));
    RHP_TRY(not_after_n, detail::count(*not_after, "not_after"));
    out.not_after = not_after_n;
    RHP_TRY(role_field, detail::field(*m, 9, "role"));
    RHP_TRY(role_text, detail::text(*role_field, "role"));
    const auto parsed_role = parse_role(role_text);
    if (!parsed_role) {
        return std::unexpected{bad_body(std::format("unknown role '{}'", role_text))};
    }
    out.run_as = *parsed_role;
    RHP_TRY(libs, detail::field(*m, 10, "libs"));
    RHP_TRY(libs_list, detail::texts(*libs, "libs"));
    out.libs = std::move(libs_list);
    RHP_TRY(modules, detail::field(*m, 11, "modules"));
    const auto* list = modules->get_if<value::array>();
    if (list == nullptr || list->size() > kMaxModules) {
        return std::unexpected{bad_body(std::format("'modules' must be an array of at most {} modules", kMaxModules))};
    }
    for (const value& item : *list) {
        RHP_TRY(entry, detail::fields(item, "a module entry"));
        if (auto ok = detail::exact_size(*entry, 2, "a module entry"); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        RHP_TRY(name, detail::field(*entry, 0, "name"));
        RHP_TRY(name_text, detail::text(*name, "name"));
        RHP_TRY(hash, detail::field(*entry, 1, "hash"));
        RHP_TRY(hash_bytes, detail::digest(*hash, "hash"));
        out.modules.push_back(module_entry{std::move(name_text), hash_bytes});
    }
    RHP_TRY(health, detail::field(*m, 12, "health"));
    RHP_TRY(health_map, detail::fields(*health, "health"));
    if (auto ok = detail::exact_size(*health_map, 2, "health"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    RHP_TRY(fail_events, detail::field(*health_map, 0, "fail_events"));
    RHP_TRY(fail_list, detail::texts(*fail_events, "fail_events"));
    out.health.fail_events = std::move(fail_list);
    RHP_TRY(max_failures, detail::field(*health_map, 1, "max_handler_failures"));
    RHP_TRY(max_failures_n, detail::count(*max_failures, "max_handler_failures"));
    if (max_failures_n > (std::numeric_limits<std::uint32_t>::max)()) {
        return std::unexpected{bad_body("'max_handler_failures' is too large")};
    }
    out.health.max_handler_failures = static_cast<std::uint32_t>(max_failures_n);
    return out;
}

#undef RHP_TRY

} // namespace

result<void> validate(const manifest& m) {
    const auto bad = [](std::string message) { return std::unexpected{make_error(errc::kInvalidArgument, std::move(message), "release.manifest")}; };
    if (!detail::valid_channel(m.channel)) {
        return bad(std::format("channel '{}' must be dotted lowercase words of a-z 0-9 _ - (at most {} bytes)", m.channel, kMaxChannelName));
    }
    if (m.seq == 0 || !detail::fits(m.seq) || !detail::fits(m.not_before) || !detail::fits(m.not_after)) {
        return bad("seq must be at least 1, and seq / not_before / not_after below 2^63");
    }
    if (m.not_after != 0 && m.not_after <= m.not_before) {
        return bad("not_after must come after not_before");
    }
    if (m.run_as != role::kPatch && m.run_as != role::kAdmin) {
        return bad("a release runs as patch or admin");
    }
    if (m.modules.empty() || m.modules.size() > kMaxModules) {
        return bad(std::format("a release has 1 to {} modules", kMaxModules));
    }
    for (std::size_t i = 0; i < m.modules.size(); ++i) {
        if (m.modules[i].name.empty()) {
            return bad("a module needs a name");
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (m.modules[j].name == m.modules[i].name) {
                return bad(std::format("module '{}' appears twice", m.modules[i].name));
            }
        }
    }
    for (const auto* list : {&m.builds, &m.platforms, &m.libs, &m.health.fail_events}) {
        if (list->size() > kMaxListEntries) {
            return bad(std::format("lists hold at most {} entries", kMaxListEntries));
        }
    }
    return {};
}

result<std::vector<std::byte>> encode_manifest(const manifest& m) {
    if (auto ok = validate(m); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return detail::encode(manifest_value(m));
}

result<manifest> decode_manifest(std::span<const std::byte> body) {
    auto v = detail::decode(body);
    if (!v) {
        return std::unexpected{bad_body(std::format("the release body isn't MessagePack: {}", v.error().message))};
    }
    auto m = manifest_from(*v);
    if (!m) {
        return m;
    }
    if (auto ok = validate(*m); !ok) {
        return std::unexpected{bad_body(ok.error().message)};
    }
    auto again = detail::encode(manifest_value(*m));
    if (!again || !std::ranges::equal(*again, body)) {
        return std::unexpected{bad_body("the release body is not canonical")};
    }
    return m;
}

std::string to_hex(const release_id& id) {
    return security::to_hex(id);
}

result<release_id> id_from_hex(std::string_view hex) {
    release_id out{};
    if (hex.size() != out.size() * 2) {
        return fail(errc::kInvalidArgument, "a release id is 64 hex digits", "release.id");
    }
    for (std::size_t i = 0; i < out.size(); ++i) {
        const auto hi = kDigits.find(hex[2 * i]);
        const auto lo = kDigits.find(hex[2 * i + 1]);
        if (hi == std::string_view::npos || lo == std::string_view::npos) {
            return fail(errc::kInvalidArgument, "a release id is 64 lowercase hex digits", "release.id");
        }
        out[i] = static_cast<std::byte>((hi << 4) | lo);
    }
    return out;
}

std::string short_id(const release_id& id) {
    return to_hex(id).substr(0, 8);
}

std::string compiled_store_key(const release_id& id) {
    return std::string{detail::kBytecodePrefix} + to_hex(id);
}

} // namespace Rhp::release
