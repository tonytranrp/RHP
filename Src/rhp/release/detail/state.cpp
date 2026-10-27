#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/detail/state.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>

namespace Rhp::release::detail {

bool revoked_set::revokes(const release_id& id) const {
    return std::ranges::find(releases, id) != releases.end();
}

std::uint64_t revoked_set::floor_of(std::string_view channel) const {
    const auto it = std::ranges::find(floors, channel, &seq_floor::channel);
    return it != floors.end() ? it->seq : 0;
}

void revoked_set::merge(std::uint64_t list_seq, std::span<const release_id> ids, std::span<const security::ed25519_public_key> revoked_keys,
                        std::span<const seq_floor> revoked_floors) {
    seq = std::max(seq, list_seq);
    for (const release_id& id : ids) {
        if (std::ranges::find(releases, id) == releases.end()) {
            releases.push_back(id);
        }
    }
    for (const auto& k : revoked_keys) {
        if (std::ranges::find(keys, k) == keys.end()) {
            keys.push_back(k);
        }
    }
    for (const seq_floor& f : revoked_floors) {
        const auto it = std::ranges::find(floors, f.channel, &seq_floor::channel);
        if (it == floors.end()) {
            floors.push_back(f);
        } else {
            it->seq = std::max(it->seq, f.seq);
        }
    }
}

namespace {

value optional_id(const std::optional<release_id>& id) {
    return id ? digest_value(*id) : value{};
}

result<std::optional<release_id>> read_optional_id(const value& v, std::string_view key) {
    if (v.is_nil()) {
        return std::optional<release_id>{};
    }
    auto d = digest(v, key);
    if (!d) {
        return std::unexpected{std::move(d).error()};
    }
    return std::optional<release_id>{*d};
}

} // namespace

result<std::vector<std::byte>> encode_state(const std::vector<channel_state>& channels, const revoked_set& revoked) {
    value::array list;
    for (const channel_state& c : channels) {
        value::array quarantined;
        for (const release_id& id : c.quarantined) {
            quarantined.push_back(digest_value(id));
        }
        value::map m;
        m.emplace_back(value{"channel"}, value{c.name});
        m.emplace_back(value{"floor"}, value{c.floor});
        m.emplace_back(value{"active"}, optional_id(c.active));
        m.emplace_back(value{"previous"}, optional_id(c.previous));
        m.emplace_back(value{"candidate"}, optional_id(c.candidate));
        m.emplace_back(value{"confirm"}, value{to_string(c.confirm)});
        m.emplace_back(value{"attempts"}, value{c.attempts});
        m.emplace_back(value{"held"}, value{c.held});
        m.emplace_back(value{"quarantined"}, value{std::move(quarantined)});
        list.emplace_back(std::move(m));
    }
    value::array ids;
    for (const release_id& id : revoked.releases) {
        ids.push_back(digest_value(id));
    }
    value::array keys;
    for (const auto& k : revoked.keys) {
        keys.emplace_back(key_bytes(k));
    }
    value::array floors;
    for (const seq_floor& f : revoked.floors) {
        floors.push_back(floor_value(f));
    }
    value::map doc;
    doc.emplace_back(value{"rhp"}, value{"release-state"});
    doc.emplace_back(value{"revocation_seq"}, value{revoked.seq});
    doc.emplace_back(value{"revoked_releases"}, value{std::move(ids)});
    doc.emplace_back(value{"revoked_keys"}, value{std::move(keys)});
    doc.emplace_back(value{"revoked_floors"}, value{std::move(floors)});
    doc.emplace_back(value{"channels"}, value{std::move(list)});
    auto body = encode(value{std::move(doc)});
    if (!body) {
        return body;
    }
    const auto check = security::blake2b_256(*body);
    std::vector<std::byte> out(check.begin(), check.end());
    out.insert(out.end(), body->begin(), body->end());
    return out;
}

namespace {

result<revoked_set> decode_revoked(const value& doc) {
    revoked_set out;
    if (const value* seq = doc.find("revocation_seq"); seq != nullptr) {
        auto n = count(*seq, "revocation_seq");
        if (!n) {
            return std::unexpected{std::move(n).error()};
        }
        out.seq = *n;
    }
    if (const value* ids = doc.find("revoked_releases"); ids != nullptr && ids->get_if<value::array>() != nullptr) {
        for (const value& id : *ids->get_if<value::array>()) {
            auto d = digest(id, "revoked_releases");
            if (!d) {
                return std::unexpected{std::move(d).error()};
            }
            out.releases.push_back(*d);
        }
    }
    if (const value* keys = doc.find("revoked_keys"); keys != nullptr && keys->get_if<value::array>() != nullptr) {
        for (const value& k : *keys->get_if<value::array>()) {
            const auto* raw = k.get_if<value::bytes>();
            auto key = raw != nullptr ? security::ed25519_public_key::from_bytes(*raw)
                                      : result<security::ed25519_public_key>{std::unexpected{bad_body("a revoked key is not bytes")}};
            if (!key) {
                return std::unexpected{std::move(key).error()};
            }
            out.keys.push_back(*key);
        }
    }
    if (const value* floors = doc.find("revoked_floors"); floors != nullptr && floors->get_if<value::array>() != nullptr) {
        for (const value& f : *floors->get_if<value::array>()) {
            const value* channel = f.find("channel");
            const value* seq = f.find("seq");
            auto name = channel != nullptr ? text(*channel, "channel") : result<std::string>{std::unexpected{bad_body("a revoked floor has no channel")}};
            auto n = seq != nullptr ? count(*seq, "seq") : result<std::uint64_t>{std::unexpected{bad_body("a revoked floor has no seq")}};
            if (!name || !n) {
                return std::unexpected{bad_body("a revoked floor of the release state is malformed")};
            }
            out.floors.push_back(seq_floor{std::move(*name), *n});
        }
    }
    return out;
}

} // namespace

result<decoded_state> decode_state(std::span<const std::byte> bytes) {
    constexpr std::size_t kCheck = security::digest256{}.size();
    if (bytes.size() < kCheck) {
        return fail(errc::kIntegrity, "the release state is truncated", "release.state");
    }
    const auto body = bytes.subspan(kCheck);
    const auto check = security::blake2b_256(body);
    if (!std::ranges::equal(check, bytes.first(kCheck))) {
        return fail(errc::kIntegrity, "the release state doesn't match its checksum", "release.state");
    }
    auto v = decode(body);
    if (!v) {
        return std::unexpected{std::move(v).error()};
    }
    const value* tag = v->find("rhp");
    if (tag == nullptr || tag->get_if<std::string>() == nullptr || *tag->get_if<std::string>() != "release-state") {
        return std::unexpected{bad_body("not a release state document")};
    }
    decoded_state out;
    auto revoked = decode_revoked(*v);
    if (!revoked) {
        return std::unexpected{std::move(revoked).error()};
    }
    out.revoked = std::move(*revoked);
    const value* channels = v->find("channels");
    const auto* list = channels != nullptr ? channels->get_if<value::array>() : nullptr;
    if (list == nullptr) {
        return std::unexpected{bad_body("the release state has no channels")};
    }
    for (const value& item : *list) {
        channel_state c;
        const auto get = [&](std::string_view key) -> const value& {
            static const value kNil{};
            const value* f = item.find(key);
            return f != nullptr ? *f : kNil;
        };
        auto name = text(get("channel"), "channel");
        auto floor = count(get("floor"), "floor");
        auto active = read_optional_id(get("active"), "active");
        auto previous = read_optional_id(get("previous"), "previous");
        auto candidate = read_optional_id(get("candidate"), "candidate");
        auto confirm = text(get("confirm"), "confirm");
        auto attempts = count(get("attempts"), "attempts");
        if (!name || !floor || !active || !previous || !candidate || !confirm || !attempts || !get("held").is_bool()) {
            return std::unexpected{bad_body("a channel of the release state is malformed")};
        }
        c.name = std::move(*name);
        c.floor = *floor;
        c.active = *active;
        c.previous = *previous;
        c.candidate = *candidate;
        c.confirm = parse_confirm_mode(*confirm).value_or(confirm_mode::kNow);
        c.attempts = static_cast<std::uint32_t>(std::min<std::uint64_t>(*attempts, 1000));
        c.held = *get("held").get_if<bool>();
        if (const auto* q = get("quarantined").get_if<value::array>(); q != nullptr) {
            for (const value& id : *q) {
                if (auto d = digest(id, "quarantined")) {
                    c.quarantined.push_back(*d);
                }
            }
            if (c.quarantined.size() > kQuarantineKept) { // the newest
                c.quarantined.erase(c.quarantined.begin(), c.quarantined.end() - static_cast<std::ptrdiff_t>(kQuarantineKept));
            }
        }
        out.channels.push_back(std::move(c));
    }
    return out;
}

} // namespace Rhp::release::detail
