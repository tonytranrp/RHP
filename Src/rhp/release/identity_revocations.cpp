#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
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
#include <rhp/release/identity_revocations.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>

namespace Rhp::release {

namespace {

using security::identity_revocation_list;
using security::public_key_ref;

constexpr std::string_view kIdentityEnvelopeTag = "identity-revocations";

bool key_less(const public_key_ref& a, const public_key_ref& b) {
    return a.alg != b.alg ? a.alg < b.alg : std::ranges::lexicographical_compare(a.pub, b.pub);
}

std::vector<public_key_ref> canonical_keys(std::vector<public_key_ref> keys) {
    std::ranges::sort(keys, key_less);
    keys.erase(std::ranges::unique(keys).begin(), keys.end());
    return keys;
}

value keys_value(const std::vector<public_key_ref>& keys) {
    value::array out;
    for (const public_key_ref& k : canonical_keys(keys)) {
        value::map m;
        m.emplace_back(value{"alg"}, value{k.alg});
        m.emplace_back(value{"pub"}, value{value::bytes(k.pub.begin(), k.pub.end())});
        out.emplace_back(std::move(m));
    }
    return value{std::move(out)};
}

value list_value(const identity_revocation_list& list) {
    value::map out;
    out.emplace_back(value{"seq"}, value{list.seq});
    out.emplace_back(value{"issued_at"}, value{list.issued_at});
    out.emplace_back(value{"cert_serials"}, Rhp::to_value(detail::canonical_set(list.cert_serials)));
    out.emplace_back(value{"signer_keys"}, keys_value(list.signer_keys));
    out.emplace_back(value{"device_keys"}, keys_value(list.device_keys));
    return value{std::move(out)};
}

bool valid_key(const public_key_ref& k) {
    const bool alg_ok = !k.alg.empty() && k.alg.size() <= 16 &&
                        std::ranges::all_of(k.alg, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
    return alg_ok && !k.pub.empty() && k.pub.size() <= kMaxPublicKey && (k.alg != kEd25519Alg || k.pub.size() == security::ed25519_public_key::kSize);
}

bool valid_serial(std::string_view s) {
    return !s.empty() && s.size() <= kMaxSerial && std::ranges::all_of(s, [](char c) { return c > ' ' && c < 0x7f; });
}

result<std::vector<public_key_ref>> keys_from(const value& v, std::string_view key) {
    const auto* list = v.get_if<value::array>();
    if (list == nullptr || list->size() > kMaxListEntries) {
        return std::unexpected{detail::bad_body(std::format("'{}' must be an array of at most {} keys", key, kMaxListEntries))};
    }
    std::vector<public_key_ref> out;
    const auto malformed = [key] { return std::unexpected{detail::bad_body(std::format("an entry of '{}' is {{alg = string, pub = bytes}}", key))}; };
    for (const value& item : *list) {
        const auto* m = item.get_if<value::map>();
        if (m == nullptr || m->size() != 2) {
            return malformed();
        }
        auto alg = detail::field(*m, 0, "alg");
        auto pub = detail::field(*m, 1, "pub");
        if (!alg || !pub) {
            return malformed();
        }
        auto alg_text = detail::text(**alg, "alg");
        auto pub_bytes = detail::raw_bytes(**pub, "pub", kMaxPublicKey);
        if (!alg_text || !pub_bytes) {
            return malformed();
        }
        out.push_back(public_key_ref{std::move(*alg_text), std::move(*pub_bytes)});
    }
    return out;
}

} // namespace

result<void> validate(const identity_revocation_list& list) {
    if (list.seq == 0 || !detail::fits(list.seq) || !detail::fits(list.issued_at)) {
        return fail(errc::kInvalidArgument, "an identity revocation list's seq is at least 1 (and seq / issued_at below 2^63)", "release.identities");
    }
    if (list.cert_serials.size() > kMaxListEntries || list.signer_keys.size() > kMaxListEntries || list.device_keys.size() > kMaxListEntries) {
        return fail(errc::kInvalidArgument, std::format("identity revocation lists hold at most {} entries each", kMaxListEntries), "release.identities");
    }
    for (const std::string& s : list.cert_serials) {
        if (!valid_serial(s)) {
            return fail(errc::kInvalidArgument, std::format("'{}' is not a certificate serial (1 to {} printable characters)", s, kMaxSerial), "release.identities");
        }
    }
    for (const auto* keys : {&list.signer_keys, &list.device_keys}) {
        for (const public_key_ref& k : *keys) {
            if (!valid_key(k)) {
                return fail(errc::kInvalidArgument, std::format("a revoked {} key of {} bytes", k.alg, k.pub.size()), "release.identities");
            }
        }
    }
    return {};
}

result<std::vector<std::byte>> encode_identity_revocation_list(const identity_revocation_list& list) {
    if (auto ok = validate(list); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return detail::encode(list_value(list));
}

result<identity_revocation_list> decode_identity_revocation_list(std::span<const std::byte> body) {
    auto v = detail::decode(body);
    if (!v) {
        return std::unexpected{detail::bad_body(std::format("the identity revocation list isn't MessagePack: {}", v.error().message))};
    }
    auto m = detail::fields(*v, "an identity revocation list");
    if (!m) {
        return std::unexpected{std::move(m).error()};
    }
    if (auto ok = detail::exact_size(**m, 5, "an identity revocation list"); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const value::map& f = **m;
    auto seq = detail::field(f, 0, "seq");
    auto issued = detail::field(f, 1, "issued_at");
    auto serials = detail::field(f, 2, "cert_serials");
    auto signers = detail::field(f, 3, "signer_keys");
    auto devices = detail::field(f, 4, "device_keys");
    if (!seq || !issued || !serials || !signers || !devices) {
        return std::unexpected{detail::bad_body("an identity revocation list is {seq, issued_at, cert_serials, signer_keys, device_keys}")};
    }
    identity_revocation_list out;
    auto seq_n = detail::count(**seq, "seq");
    auto issued_n = detail::count(**issued, "issued_at");
    auto serial_texts = detail::texts(**serials, "cert_serials");
    auto signer_keys = keys_from(**signers, "signer_keys");
    auto device_keys = keys_from(**devices, "device_keys");
    if (!seq_n || !issued_n || !serial_texts) {
        return std::unexpected{detail::bad_body("seq and issued_at are integers, cert_serials strings")};
    }
    if (!signer_keys || !device_keys) {
        return std::unexpected{!signer_keys ? signer_keys.error() : device_keys.error()};
    }
    out.seq = *seq_n;
    out.issued_at = *issued_n;
    out.cert_serials = std::move(*serial_texts);
    out.signer_keys = std::move(*signer_keys);
    out.device_keys = std::move(*device_keys);
    if (auto ok = validate(out); !ok) {
        return std::unexpected{detail::bad_body(ok.error().message)};
    }
    auto again = detail::encode(list_value(out));
    if (!again || !std::ranges::equal(*again, body)) {
        return std::unexpected{detail::bad_body("the identity revocation list is not canonical")};
    }
    return out;
}

result<signed_identity_revocations> make_identity_revocations(identity_revocation_list list) {
    auto body = encode_identity_revocation_list(list);
    if (!body) {
        return std::unexpected{std::move(body).error()};
    }
    return signed_identity_revocations{std::move(list), std::move(*body), {}};
}

result<void> sign(signed_identity_revocations& r, const security::signing_key& key) {
    return detail::add_signature(r.signatures, kIdentityRevocationSignatureDomain, r.body_bytes, key);
}

result<std::vector<std::byte>> encode_identity_revocations(const signed_identity_revocations& r) {
    return detail::encode_signed(kIdentityEnvelopeTag, r.body_bytes, r.signatures);
}

result<signed_identity_revocations> decode_identity_revocations(std::span<const std::byte> envelope) {
    auto parts = detail::decode_signed(envelope, kIdentityEnvelopeTag);
    if (!parts) {
        return std::unexpected{std::move(parts).error()};
    }
    auto list = decode_identity_revocation_list(parts->body);
    if (!list) {
        return std::unexpected{std::move(list).error()};
    }
    return signed_identity_revocations{std::move(*list), std::move(parts->body), std::move(parts->signatures)};
}

} // namespace Rhp::release
