#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/detail/codec.hpp>
#include <rhp/release/manifest.hpp>
#include <rhp/release/release.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>

namespace Rhp::release {

namespace {

constexpr std::size_t kMaxEnvelope = 64u << 20; // a release's bytes, sources included

error integrity(std::string message) {
    return make_error(errc::kIntegrity, std::move(message), "release");
}

// domain || body: what a signature covers.
std::vector<std::byte> signed_message(std::string_view domain, std::span<const std::byte> body) {
    std::vector<std::byte> out(domain.size() + body.size());
    std::memcpy(out.data(), domain.data(), domain.size());
    if (!body.empty()) {
        std::memcpy(out.data() + domain.size(), body.data(), body.size());
    }
    return out;
}

result<void> add_signature(std::vector<signature>& to, std::string_view domain, std::span<const std::byte> body, const security::signing_key& key) {
    if (key.name.empty() || key.secret.empty()) {
        return fail(errc::kInvalidArgument, "a signing key needs a name and a private key", "release.sign");
    }
    signature s;
    s.signer = key.name;
    s.bytes = key.secret.sign(signed_message(domain, body));
    if (const auto it = std::ranges::find(to, key.name, &signature::signer); it != to.end()) {
        *it = std::move(s);
    } else {
        if (to.size() >= kMaxSignatures) {
            return fail(errc::kLimitExceeded, std::format("at most {} signatures", kMaxSignatures), "release.sign");
        }
        to.push_back(std::move(s));
    }
    return {};
}

value signatures_value(const std::vector<signature>& sigs) {
    value::array out;
    for (const signature& s : sigs) {
        value::map m;
        m.emplace_back(value{"signer"}, value{s.signer});
        m.emplace_back(value{"sig"}, value{value::bytes(s.bytes.begin(), s.bytes.end())});
        out.emplace_back(std::move(m));
    }
    return value{std::move(out)};
}

result<std::vector<signature>> signatures_from(const value* v) {
    std::vector<signature> out;
    if (v == nullptr || v->is_nil()) {
        return out;
    }
    const auto* list = v->get_if<value::array>();
    if (list == nullptr || list->size() > kMaxSignatures) {
        return std::unexpected{detail::bad_body(std::format("'signatures' must be an array of at most {} signatures", kMaxSignatures))};
    }
    for (const value& item : *list) {
        const value* signer = item.find("signer");
        const value* sig = item.find("sig");
        const auto* name = signer != nullptr ? signer->get_if<std::string>() : nullptr;
        const auto* bytes = sig != nullptr ? sig->get_if<value::bytes>() : nullptr;
        if (name == nullptr || bytes == nullptr || bytes->size() != security::ed25519_secret_key::kSignatureSize) {
            return std::unexpected{detail::bad_body("a signature is {signer = string, sig = 64 bytes}")};
        }
        signature s;
        s.signer = *name;
        std::ranges::copy(*bytes, s.bytes.begin());
        out.push_back(std::move(s));
    }
    return out;
}

result<value> envelope_of(std::span<const std::byte> bytes, std::string_view tag) {
    if (bytes.size() > kMaxEnvelope) {
        return fail(errc::kLimitExceeded, std::format("an envelope is at most {} bytes", kMaxEnvelope), "release");
    }
    auto v = detail::decode(bytes);
    if (!v) {
        return std::unexpected{detail::bad_body(std::format("not a release document: {}", v.error().message))};
    }
    const value* rhp = v->find("rhp");
    const auto* kind = rhp != nullptr ? rhp->get_if<std::string>() : nullptr;
    if (kind == nullptr || *kind != tag) {
        return std::unexpected{detail::bad_body(std::format("expected a '{}' document, got '{}'", tag, kind != nullptr ? *kind : "?"))};
    }
    return v;
}

const value::bytes* bytes_field(const value& v, std::string_view key) {
    const value* f = v.find(key);
    return f != nullptr ? f->get_if<value::bytes>() : nullptr;
}

// ---- revocation list body ------------------------------------------------------------------------

value revocation_value(const revocation_list& list) {
    std::vector<release_id> releases = list.releases;
    std::ranges::sort(releases);
    releases.erase(std::ranges::unique(releases).begin(), releases.end());
    value::array ids;
    for (const release_id& id : releases) {
        ids.push_back(detail::digest_value(id));
    }
    std::vector<value::bytes> key_bytes;
    for (const auto& k : list.keys) {
        key_bytes.emplace_back(k.bytes().begin(), k.bytes().end());
    }
    std::ranges::sort(key_bytes);
    key_bytes.erase(std::ranges::unique(key_bytes).begin(), key_bytes.end());
    value::array keys;
    for (auto& k : key_bytes) {
        keys.emplace_back(std::move(k));
    }
    std::vector<seq_floor> floors = list.floors;
    std::ranges::sort(floors, {}, &seq_floor::channel);
    value::array floor_values;
    for (const seq_floor& f : floors) {
        value::map m;
        m.emplace_back(value{"channel"}, value{f.channel});
        m.emplace_back(value{"seq"}, value{f.seq});
        floor_values.emplace_back(std::move(m));
    }
    value::map out;
    out.emplace_back(value{"rhp"}, value{"revocations"});
    out.emplace_back(value{"seq"}, value{list.seq});
    out.emplace_back(value{"issued_at"}, value{list.issued_at});
    out.emplace_back(value{"releases"}, value{std::move(ids)});
    out.emplace_back(value{"keys"}, value{std::move(keys)});
    out.emplace_back(value{"floors"}, value{std::move(floor_values)});
    return value{std::move(out)};
}

result<void> validate(const revocation_list& list) {
    if (list.seq == 0 || !detail::fits(list.seq) || !detail::fits(list.issued_at)) {
        return fail(errc::kInvalidArgument, "a revocation list's seq is at least 1 (and seq / issued_at below 2^63)", "release.revocations");
    }
    if (list.releases.size() > kMaxListEntries || list.keys.size() > kMaxListEntries || list.floors.size() > kMaxListEntries) {
        return fail(errc::kInvalidArgument, std::format("revocation lists hold at most {} entries each", kMaxListEntries), "release.revocations");
    }
    for (std::size_t i = 0; i < list.floors.size(); ++i) {
        const seq_floor& f = list.floors[i];
        if (!detail::valid_channel(f.channel) || !detail::fits(f.seq)) {
            return fail(errc::kInvalidArgument, std::format("bad floor for channel '{}'", f.channel), "release.revocations");
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (list.floors[j].channel == f.channel) {
                return fail(errc::kInvalidArgument, std::format("two floors for channel '{}'", f.channel), "release.revocations");
            }
        }
    }
    return {};
}

} // namespace

// ---- releases --------------------------------------------------------------------------------------

result<release> make_release(manifest m, std::vector<std::string> sources) {
    if (sources.size() != m.modules.size()) {
        return fail(errc::kInvalidArgument, std::format("{} modules but {} sources", m.modules.size(), sources.size()), "release.make");
    }
    for (std::size_t i = 0; i < sources.size(); ++i) {
        m.modules[i].hash = security::blake2b_256(sources[i]);
    }
    auto body = encode_manifest(m);
    if (!body) {
        return std::unexpected{std::move(body).error()};
    }
    release r;
    r.id = security::blake2b_256(*body);
    r.body = std::move(m);
    r.body_bytes = std::move(*body);
    r.sources = std::move(sources);
    return r;
}

result<void> sign(release& r, const security::signing_key& key) {
    return add_signature(r.signatures, kReleaseSignatureDomain, r.body_bytes, key);
}

result<std::vector<std::byte>> encode_release(const release& r) {
    value::array sources;
    for (const std::string& s : r.sources) {
        sources.emplace_back(s);
    }
    value::map out;
    out.emplace_back(value{"rhp"}, value{"release-envelope"});
    out.emplace_back(value{"body"}, value{value::bytes(r.body_bytes.begin(), r.body_bytes.end())});
    out.emplace_back(value{"signatures"}, signatures_value(r.signatures));
    out.emplace_back(value{"sources"}, value{std::move(sources)});
    out.emplace_back(value{"revocations"}, r.revocations.empty() ? value{} : value{value::bytes(r.revocations.begin(), r.revocations.end())});
    return detail::encode(value{std::move(out)});
}

result<release> decode_release(std::span<const std::byte> envelope) {
    auto v = envelope_of(envelope, "release-envelope");
    if (!v) {
        return std::unexpected{std::move(v).error()};
    }
    const auto* body = bytes_field(*v, "body");
    if (body == nullptr) {
        return std::unexpected{detail::bad_body("a release envelope needs a 'body'")};
    }
    auto m = decode_manifest(*body);
    if (!m) {
        return std::unexpected{std::move(m).error()};
    }
    auto sigs = signatures_from(v->find("signatures"));
    if (!sigs) {
        return std::unexpected{std::move(sigs).error()};
    }
    const value* sources = v->find("sources");
    const auto* list = sources != nullptr ? sources->get_if<value::array>() : nullptr;
    if (list == nullptr || list->size() != m->modules.size()) {
        return std::unexpected{detail::bad_body("a release envelope needs one source per module")};
    }
    release r;
    for (std::size_t i = 0; i < list->size(); ++i) {
        const auto* text = (*list)[i].get_if<std::string>();
        if (text == nullptr) {
            return std::unexpected{detail::bad_body("sources are strings")};
        }
        if (security::blake2b_256(*text) != m->modules[i].hash) {
            return std::unexpected{integrity(std::format("the source of module '{}' doesn't match its hash", m->modules[i].name))};
        }
        r.sources.push_back(*text);
    }
    if (const value* rev = v->find("revocations"); rev != nullptr && !rev->is_nil()) {
        const auto* bytes = rev->get_if<value::bytes>();
        if (bytes == nullptr) {
            return std::unexpected{detail::bad_body("'revocations' is a signed revocation list (bytes) or nil")};
        }
        r.revocations = *bytes;
    }
    r.id = security::blake2b_256(*body);
    r.body = std::move(*m);
    r.body_bytes = *body;
    r.signatures = std::move(*sigs);
    return r;
}

// ---- revocation lists --------------------------------------------------------------------------------

result<std::vector<std::byte>> encode_revocation_list(const revocation_list& list) {
    if (auto ok = validate(list); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return detail::encode(revocation_value(list));
}

result<revocation_list> decode_revocation_list(std::span<const std::byte> body) {
    auto v = detail::decode(body);
    if (!v) {
        return std::unexpected{detail::bad_body(std::format("the revocation list isn't MessagePack: {}", v.error().message))};
    }
    auto m = detail::fields(*v, "a revocation list");
    if (!m) {
        return std::unexpected{std::move(m).error()};
    }
    if (auto ok = detail::exact_size(**m, 6, "a revocation list"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const value::map& f = **m;
    revocation_list out;
    {
        auto tag = detail::field(f, 0, "rhp");
        auto text = tag ? detail::text(**tag, "rhp") : result<std::string>{std::unexpected{tag.error()}};
        if (!text || *text != "revocations") {
            return std::unexpected{detail::bad_body("not a revocation list")};
        }
    }
    const auto number = [&](std::size_t i, std::string_view key) -> result<std::uint64_t> {
        auto field = detail::field(f, i, key);
        if (!field) {
            return std::unexpected{std::move(field).error()};
        }
        return detail::count(**field, key);
    };
    const auto array = [&](std::size_t i, std::string_view key) -> result<const value::array*> {
        auto field = detail::field(f, i, key);
        if (!field) {
            return std::unexpected{std::move(field).error()};
        }
        const auto* a = (*field)->get_if<value::array>();
        if (a == nullptr || a->size() > kMaxListEntries) {
            return std::unexpected{detail::bad_body(std::format("'{}' must be an array of at most {} entries", key, kMaxListEntries))};
        }
        return a;
    };
    auto seq = number(1, "seq");
    auto issued = number(2, "issued_at");
    auto releases = array(3, "releases");
    auto keys = array(4, "keys");
    auto floors = array(5, "floors");
    for (const auto* failed : {seq ? nullptr : &seq.error(), issued ? nullptr : &issued.error(), releases ? nullptr : &releases.error(),
                               keys ? nullptr : &keys.error(), floors ? nullptr : &floors.error()}) {
        if (failed != nullptr) {
            return std::unexpected{*failed};
        }
    }
    out.seq = *seq;
    out.issued_at = *issued;
    for (const value& item : **releases) {
        auto id = detail::digest(item, "releases");
        if (!id) {
            return std::unexpected{std::move(id).error()};
        }
        out.releases.push_back(*id);
    }
    for (const value& item : **keys) {
        const auto* b = item.get_if<value::bytes>();
        auto key = b != nullptr ? security::ed25519_public_key::from_bytes(*b) : result<security::ed25519_public_key>{std::unexpected{detail::bad_body("keys are 32 bytes")}};
        if (!key) {
            return std::unexpected{detail::bad_body("keys are 32-byte Ed25519 public keys")};
        }
        out.keys.push_back(*key);
    }
    for (const value& item : **floors) {
        auto entry = detail::fields(item, "a floor");
        if (!entry) {
            return std::unexpected{std::move(entry).error()};
        }
        if (auto ok = detail::exact_size(**entry, 2, "a floor"); !ok) {
            return std::unexpected{std::move(ok).error()};
        }
        auto channel = detail::field(**entry, 0, "channel");
        auto floor_seq = detail::field(**entry, 1, "seq");
        if (!channel || !floor_seq) {
            return std::unexpected{detail::bad_body("a floor is {channel, seq}")};
        }
        auto name = detail::text(**channel, "channel");
        auto n = detail::count(**floor_seq, "seq");
        if (!name || !n) {
            return std::unexpected{detail::bad_body("a floor is {channel = string, seq = integer}")};
        }
        out.floors.push_back(seq_floor{std::move(*name), *n});
    }
    if (auto ok = validate(out); !ok) {
        return std::unexpected{detail::bad_body(ok.error().message)};
    }
    auto again = detail::encode(revocation_value(out));
    if (!again || !std::ranges::equal(*again, body)) {
        return std::unexpected{detail::bad_body("the revocation list is not canonical")};
    }
    return out;
}

result<signed_revocations> make_revocations(revocation_list list) {
    auto body = encode_revocation_list(list);
    if (!body) {
        return std::unexpected{std::move(body).error()};
    }
    signed_revocations out;
    out.body = std::move(list);
    out.body_bytes = std::move(*body);
    return out;
}

result<void> sign(signed_revocations& r, const security::signing_key& key) {
    return add_signature(r.signatures, kRevocationSignatureDomain, r.body_bytes, key);
}

result<std::vector<std::byte>> encode_revocations(const signed_revocations& r) {
    value::map out;
    out.emplace_back(value{"rhp"}, value{"revocations-envelope"});
    out.emplace_back(value{"body"}, value{value::bytes(r.body_bytes.begin(), r.body_bytes.end())});
    out.emplace_back(value{"signatures"}, signatures_value(r.signatures));
    return detail::encode(value{std::move(out)});
}

result<signed_revocations> decode_revocations(std::span<const std::byte> envelope) {
    auto v = envelope_of(envelope, "revocations-envelope");
    if (!v) {
        return std::unexpected{std::move(v).error()};
    }
    const auto* body = bytes_field(*v, "body");
    if (body == nullptr) {
        return std::unexpected{detail::bad_body("a revocations envelope needs a 'body'")};
    }
    auto list = decode_revocation_list(*body);
    if (!list) {
        return std::unexpected{std::move(list).error()};
    }
    auto sigs = signatures_from(v->find("signatures"));
    if (!sigs) {
        return std::unexpected{std::move(sigs).error()};
    }
    signed_revocations out;
    out.body = std::move(*list);
    out.body_bytes = *body;
    out.signatures = std::move(*sigs);
    return out;
}

} // namespace Rhp::release
