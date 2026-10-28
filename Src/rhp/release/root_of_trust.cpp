#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/ed25519.hpp>

namespace Rhp::release {

namespace {

constexpr std::string_view kRootEnvelopeTag = "root-envelope";

error bad_root(std::string message) {
    return make_error(errc::kInvalidArgument, std::move(message), "release.root");
}

// Printable ASCII without spaces: identity names, as key files name their keys.
bool valid_id(std::string_view id) {
    return !id.empty() && id.size() <= kMaxKeyId && std::ranges::all_of(id, [](char c) { return c > ' ' && c < 0x7f; });
}

bool valid_alg(std::string_view alg) {
    return !alg.empty() && alg.size() <= 16 && std::ranges::all_of(alg, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
}

bool valid_key_channel(std::string_view pattern) {
    if (pattern == "*") {
        return true;
    }
    if (pattern.ends_with(".*")) {
        pattern.remove_suffix(2);
    }
    return detail::valid_channel(pattern);
}

// An Ed25519 key the root names, if it is one.
std::optional<security::ed25519_public_key> ed25519_of(const root_key& k) {
    if (k.alg != kEd25519Alg) {
        return std::nullopt;
    }
    auto key = security::ed25519_public_key::from_bytes(k.pub);
    return key ? std::optional{*key} : std::nullopt;
}

value set_value(const std::vector<std::string>& items) {
    return Rhp::to_value(detail::canonical_set(items));
}

value root_value(const root_document& doc) {
    value::map keys; // std::map iterates in id order
    for (const auto& [id, k] : doc.keys) {
        value::map entry;
        entry.emplace_back(value{"alg"}, value{k.alg});
        entry.emplace_back(value{"pub"}, value{value::bytes(k.pub.begin(), k.pub.end())});
        entry.emplace_back(value{"channels"}, set_value(k.channels));
        keys.emplace_back(value{id}, value{std::move(entry)});
    }
    value::map roles;
    for (const root_role r : kRootRoles) {
        value::map entry;
        entry.emplace_back(value{"keys"}, set_value(doc.role(r).keys));
        entry.emplace_back(value{"threshold"}, value{doc.role(r).threshold});
        roles.emplace_back(value{std::string{to_string(r)}}, value{std::move(entry)});
    }
    value::map out;
    out.emplace_back(value{"rhp"}, value{"root"});
    out.emplace_back(value{"version"}, value{doc.version});
    out.emplace_back(value{"expires"}, value{doc.expires});
    out.emplace_back(value{"keys"}, value{std::move(keys)});
    out.emplace_back(value{"roles"}, value{std::move(roles)});
    out.emplace_back(value{"compromised"}, set_value(doc.compromised));
    return value{std::move(out)};
}

template <class T>
result<T> lift(result<T> r, std::string_view what) {
    if (!r) {
        return std::unexpected{detail::bad_body(std::format("{}: {}", what, r.error().message))};
    }
    return r;
}

result<root_key> key_from(const value& v, std::string_view id) {
    auto m = detail::fields(v, "a root key");
    if (!m) {
        return std::unexpected{std::move(m).error()};
    }
    if (auto ok = detail::exact_size(**m, 3, "a root key"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    auto alg = detail::field(**m, 0, "alg");
    auto pub = detail::field(**m, 1, "pub");
    auto channels = detail::field(**m, 2, "channels");
    if (!alg || !pub || !channels) {
        return std::unexpected{detail::bad_body(std::format("key '{}' is {{alg, pub, channels}}", id))};
    }
    auto alg_text = detail::text(**alg, "alg");
    auto pub_bytes = detail::raw_bytes(**pub, "pub", kMaxPublicKey);
    auto patterns = detail::texts(**channels, "channels");
    if (!alg_text || !pub_bytes || !patterns) {
        return std::unexpected{detail::bad_body(std::format("key '{}' is {{alg = string, pub = bytes, channels = [string]}}", id))};
    }
    return root_key{std::move(*alg_text), std::move(*pub_bytes), std::move(*patterns)};
}

result<role_keys> role_from(const value& v, std::string_view name) {
    auto m = detail::fields(v, "a role");
    if (!m) {
        return std::unexpected{std::move(m).error()};
    }
    if (auto ok = detail::exact_size(**m, 2, "a role"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    auto keys = detail::field(**m, 0, "keys");
    auto threshold = detail::field(**m, 1, "threshold");
    if (!keys || !threshold) {
        return std::unexpected{detail::bad_body(std::format("role '{}' is {{keys, threshold}}", name))};
    }
    auto ids = detail::texts(**keys, "keys");
    auto n = detail::count(**threshold, "threshold");
    if (!ids || !n || *n > kMaxSignatures) {
        return std::unexpected{detail::bad_body(std::format("role '{}' is {{keys = [string], threshold = 1..{}}}", name, kMaxSignatures))};
    }
    return role_keys{std::move(*ids), static_cast<std::uint32_t>(*n)};
}

} // namespace

// ---- the document ---------------------------------------------------------------------------------

result<void> validate(const root_document& doc) {
    if (doc.version == 0 || !detail::fits(doc.version) || !detail::fits(doc.expires)) {
        return std::unexpected{bad_root("a root's version is at least 1 (version and expires below 2^63)")};
    }
    if (doc.keys.empty() || doc.keys.size() > kMaxRootKeys) {
        return std::unexpected{bad_root(std::format("a root names 1 to {} keys", kMaxRootKeys))};
    }
    for (const auto& [id, k] : doc.keys) {
        if (!valid_id(id)) {
            return std::unexpected{bad_root(std::format("'{}' is not a key id (1 to {} printable characters, no spaces)", id, kMaxKeyId))};
        }
        if (!valid_alg(k.alg)) {
            return std::unexpected{bad_root(std::format("key '{}': '{}' is not an algorithm name", id, k.alg))};
        }
        if (k.pub.empty() || k.pub.size() > kMaxPublicKey || (k.alg == kEd25519Alg && k.pub.size() != security::ed25519_public_key::kSize)) {
            return std::unexpected{bad_root(std::format("key '{}': a {} public key of {} bytes", id, k.alg, k.pub.size()))};
        }
        if (k.channels.size() > kMaxListEntries || !std::ranges::all_of(k.channels, [](const std::string& p) { return valid_key_channel(p); })) {
            return std::unexpected{bad_root(std::format("key '{}': channels are patterns (\"*\", \"game.balance\" or \"game.*\")", id))};
        }
    }
    for (const std::string& id : doc.compromised) {
        if (!doc.keys.contains(id)) {
            return std::unexpected{bad_root(std::format("compromised key '{}' isn't one of the root's keys", id))};
        }
    }
    for (const root_role r : kRootRoles) {
        const role_keys& role = doc.role(r);
        for (const std::string& id : role.keys) {
            if (!doc.keys.contains(id)) {
                return std::unexpected{bad_root(std::format("role {} names key '{}', which the root doesn't list", to_string(r), id))};
            }
            if (std::ranges::find(doc.compromised, id) != doc.compromised.end()) {
                return std::unexpected{bad_root(std::format("role {} names key '{}', which is compromised", to_string(r), id))};
            }
        }
        const std::size_t distinct = detail::canonical_set(role.keys).size();
        if (r == root_role::kRoot && distinct == 0) {
            return std::unexpected{bad_root("the root role needs keys")};
        }
        if (role.threshold == 0 || role.threshold > kMaxSignatures || (distinct != 0 && role.threshold > distinct)) {
            return std::unexpected{bad_root(std::format("role {}: a threshold of {} with {} keys (1 to the number of keys, at most {})", to_string(r), role.threshold, distinct, kMaxSignatures))};
        }
    }
    return {};
}

result<std::vector<std::byte>> encode_root_document(const root_document& doc) {
    if (auto ok = validate(doc); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return detail::encode(root_value(doc));
}

result<root_document> decode_root_document(std::span<const std::byte> body) {
    auto v = detail::decode(body);
    if (!v) {
        return std::unexpected{detail::bad_body(std::format("the root isn't MessagePack: {}", v.error().message))};
    }
    auto m = detail::fields(*v, "a root");
    if (!m) {
        return std::unexpected{std::move(m).error()};
    }
    if (auto ok = detail::exact_size(**m, 6, "a root"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const value::map& f = **m;
    auto tag = detail::field(f, 0, "rhp");
    auto tag_text = tag ? detail::text(**tag, "rhp") : result<std::string>{std::unexpected{tag.error()}};
    if (!tag_text || *tag_text != "root") {
        return std::unexpected{detail::bad_body("not a root document")};
    }
    root_document doc;
    auto version = detail::field(f, 1, "version");
    auto expires = detail::field(f, 2, "expires");
    auto keys = detail::field(f, 3, "keys");
    auto roles = detail::field(f, 4, "roles");
    auto compromised = detail::field(f, 5, "compromised");
    if (!version || !expires || !keys || !roles || !compromised) {
        return std::unexpected{detail::bad_body("a root is {rhp, version, expires, keys, roles, compromised}")};
    }
    auto version_n = lift(detail::count(**version, "version"), "the root");
    auto expires_n = lift(detail::count(**expires, "expires"), "the root");
    auto compromised_ids = lift(detail::texts(**compromised, "compromised"), "the root");
    if (!version_n || !expires_n || !compromised_ids) {
        return std::unexpected{detail::bad_body("a root's version and expires are integers, compromised a list of key ids")};
    }
    doc.version = *version_n;
    doc.expires = *expires_n;
    doc.compromised = std::move(*compromised_ids);
    const auto* key_map = (*keys)->get_if<value::map>();
    if (key_map == nullptr || key_map->size() > kMaxRootKeys) {
        return std::unexpected{detail::bad_body(std::format("'keys' is a map of at most {} keys", kMaxRootKeys))};
    }
    for (const auto& [name, entry] : *key_map) {
        const auto* id = name.get_if<std::string>();
        if (id == nullptr) {
            return std::unexpected{detail::bad_body("key ids are strings")};
        }
        auto k = key_from(entry, *id);
        if (!k) {
            return std::unexpected{std::move(k).error()};
        }
        if (!doc.keys.emplace(*id, std::move(*k)).second) {
            return std::unexpected{detail::bad_body(std::format("key '{}' is listed twice", *id))};
        }
    }
    auto role_map = detail::fields(**roles, "roles");
    if (!role_map) {
        return std::unexpected{std::move(role_map).error()};
    }
    if (auto ok = detail::exact_size(**role_map, kRootRoles.size(), "roles"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    for (std::size_t i = 0; i < kRootRoles.size(); ++i) {
        const std::string_view name = to_string(kRootRoles[i]);
        auto entry = detail::field(**role_map, i, name);
        if (!entry) {
            return std::unexpected{std::move(entry).error()};
        }
        auto role = role_from(**entry, name);
        if (!role) {
            return std::unexpected{std::move(role).error()};
        }
        doc.roles[i] = std::move(*role);
    }
    if (auto ok = validate(doc); !ok) {
        return std::unexpected{detail::bad_body(ok.error().message)};
    }
    auto again = detail::encode(root_value(doc));
    if (!again || !std::ranges::equal(*again, body)) {
        return std::unexpected{detail::bad_body("the root is not canonical")};
    }
    return doc;
}

result<signed_root> make_root(root_document doc) {
    auto body = encode_root_document(doc);
    if (!body) {
        return std::unexpected{std::move(body).error()};
    }
    return signed_root{std::move(doc), std::move(*body), {}};
}

result<void> sign(signed_root& r, const security::signing_key& key) {
    return detail::add_signature(r.signatures, kRootSignatureDomain, r.body_bytes, key);
}

result<std::vector<std::byte>> encode_root(const signed_root& r) {
    return detail::encode_signed(kRootEnvelopeTag, r.body_bytes, r.signatures);
}

result<signed_root> decode_root(std::span<const std::byte> envelope) {
    auto parts = detail::decode_signed(envelope, kRootEnvelopeTag);
    if (!parts) {
        return std::unexpected{std::move(parts).error()};
    }
    auto doc = decode_root_document(parts->body);
    if (!doc) {
        return std::unexpected{std::move(doc).error()};
    }
    return signed_root{std::move(*doc), std::move(parts->body), std::move(parts->signatures)};
}

// ---- verification -----------------------------------------------------------------------------------

result<std::vector<std::string>> verify_role(const root_document& doc, root_role r, std::string_view domain, std::span<const std::byte> body,
                                             std::span<const signature> sigs) {
    const role_keys& role = doc.role(r);
    const std::vector<std::byte> message = detail::signed_message(domain, body);
    std::vector<std::string> signers;
    std::vector<security::ed25519_public_key> used;
    for (const signature& s : sigs) {
        if (std::ranges::find(role.keys, s.signer) == role.keys.end()) {
            continue;
        }
        const auto it = doc.keys.find(s.signer);
        const auto key = it != doc.keys.end() ? ed25519_of(it->second) : std::nullopt;
        if (!key || std::ranges::find(used, *key) != used.end() || !security::ed25519_check(*key, s.bytes, message)) {
            continue;
        }
        used.push_back(*key);
        signers.push_back(s.signer);
    }
    if (role.keys.empty() || signers.size() < role.threshold) {
        return fail(errc::kBadSignature,
                    std::format("{} of {} required signatures by the {} keys of root version {} hold", signers.size(), role.threshold, to_string(r), doc.version),
                    "release.root");
    }
    return signers;
}

result<void> verify_root(const signed_root& anchor) {
    if (auto ok = verify_role(anchor.body, root_role::kRoot, kRootSignatureDomain, anchor.body_bytes, anchor.signatures); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return {};
}

result<void> verify_next_root(const signed_root& trusted, const signed_root& next) {
    const std::uint64_t held = trusted.body.version;
    if (next.body.version <= held) {
        return fail(errc::kSuperseded, std::format("root version {} is not newer than {}", next.body.version, held), "release.root");
    }
    if (next.body.version != held + 1) {
        return fail(errc::kOutOfRange, std::format("root version {} doesn't follow {}: every version in between is needed", next.body.version, held), "release.root");
    }
    if (auto old_keys = verify_role(trusted.body, root_role::kRoot, kRootSignatureDomain, next.body_bytes, next.signatures); !old_keys) {
        return std::unexpected{std::move(old_keys).error()};
    }
    if (auto own_keys = verify_role(next.body, root_role::kRoot, kRootSignatureDomain, next.body_bytes, next.signatures); !own_keys) {
        return std::unexpected{std::move(own_keys).error()};
    }
    return {};
}

result<signed_root> verify_chain(const signed_root& trusted, std::span<const signed_root> newer, std::uint64_t now_unix, std::uint64_t skew) {
    if (newer.empty()) {
        return fail(errc::kInvalidArgument, "no root to walk to", "release.root");
    }
    const signed_root* held = &trusted;
    for (const signed_root& next : newer) {
        if (auto ok = verify_next_root(*held, next); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        held = &next;
    }
    if (held->body.expires != 0 && now_unix > held->body.expires && now_unix - held->body.expires > skew) {
        return fail(errc::kExpired, std::format("root version {} expired at {}", held->body.version, held->body.expires), "release.root");
    }
    return *held;
}

// ---- what a root says -----------------------------------------------------------------------------

result<trust> role_trust(const root_document& doc, root_role r) {
    const role_keys& role = doc.role(r);
    trust out;
    for (const std::string& id : detail::canonical_set(role.keys)) {
        const auto it = doc.keys.find(id);
        const auto key = it != doc.keys.end() ? ed25519_of(it->second) : std::nullopt;
        if (!key) {
            continue; // an algorithm this build can't verify
        }
        std::vector<std::string> channels = r == root_role::kRelease ? it->second.channels : std::vector<std::string>{};
        if (auto added = out.add(id, *key, std::move(channels)); !added) {
            return std::unexpected{std::move(added).error()};
        }
    }
    if (out.empty()) {
        return fail(errc::kNotFound, std::format("root version {} has no {} keys this build can verify", doc.version, to_string(r)), "release.root");
    }
    if (auto ok = out.set_threshold(role.threshold); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return out;
}

std::vector<security::ed25519_public_key> role_public_keys(const root_document& doc, root_role r) {
    std::vector<security::ed25519_public_key> out;
    for (const std::string& id : detail::canonical_set(doc.role(r).keys)) {
        if (const auto it = doc.keys.find(id); it != doc.keys.end()) {
            if (const auto key = ed25519_of(it->second)) {
                out.push_back(*key);
            }
        }
    }
    return out;
}

std::vector<security::ed25519_public_key> compromised_keys(const root_document& doc) {
    std::vector<security::ed25519_public_key> out;
    for (const std::string& id : doc.compromised) {
        if (const auto it = doc.keys.find(id); it != doc.keys.end()) {
            if (const auto key = ed25519_of(it->second)) {
                out.push_back(*key);
            }
        }
    }
    return out;
}

std::vector<security::ed25519_public_key> trusted_keys(const root_document& doc) {
    const auto bad = compromised_keys(doc);
    std::vector<security::ed25519_public_key> out;
    for (const auto& [id, k] : doc.keys) {
        if (const auto key = ed25519_of(k); key && std::ranges::find(bad, *key) == bad.end()) {
            out.push_back(*key);
        }
    }
    return out;
}

bool signed_only_by(std::span<const security::ed25519_public_key> compromised, std::span<const security::ed25519_public_key> others,
                    std::string_view domain, std::span<const std::byte> body, std::span<const signature> sigs) {
    if (compromised.empty()) {
        return false;
    }
    const std::vector<std::byte> message = detail::signed_message(domain, body);
    bool by_compromised = false;
    for (const signature& s : sigs) {
        for (const auto& k : others) {
            if (security::ed25519_check(k, s.bytes, message)) {
                return false;
            }
        }
        by_compromised = by_compromised || std::ranges::any_of(compromised, [&](const auto& k) { return security::ed25519_check(k, s.bytes, message); });
    }
    return by_compromised;
}

} // namespace Rhp::release
