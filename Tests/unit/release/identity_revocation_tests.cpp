// Identity revocations (decision AL12): the signed document, the union a manager keeps, its caps
// and the recover step.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/release/identity_revocations.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/release/store.hpp>
#include <rhp/security/identity_revocations.hpp>

using Rhp::errc;
using Rhp::release::root_role;
using namespace release_test;

namespace identity_revocation_fixture {

constexpr std::uint64_t kNow = 1'760'000'000;
constexpr std::uint64_t kJump = std::uint64_t{1} << 32;

Rhp::security::identity_revocation_list list_of(std::uint64_t seq, std::vector<std::string> serials, std::vector<Rhp::security::public_key_ref> signers = {},
                                                std::vector<Rhp::security::public_key_ref> devices = {}) {
    Rhp::security::identity_revocation_list l;
    l.seq = seq;
    l.issued_at = kNow;
    l.cert_serials = std::move(serials);
    l.signer_keys = std::move(signers);
    l.device_keys = std::move(devices);
    return l;
}

std::vector<std::byte> identity_envelope(const Rhp::security::identity_revocation_list& l, const std::vector<const signer*>& by) {
    auto r = Rhp::release::make_identity_revocations(l);
    REQUIRE(r.has_value());
    for (const signer* s : by) {
        REQUIRE(Rhp::release::sign(*r, s->key()));
    }
    auto bytes = Rhp::release::encode_identity_revocations(*r);
    REQUIRE(bytes.has_value());
    return *bytes;
}

Rhp::release::manager_options options_at(std::uint64_t now) {
    Rhp::release::manager_options o;
    o.wall_clock = [now] { return std::chrono::system_clock::time_point{} + std::chrono::seconds{now}; };
    return o;
}

Rhp::release::root_key ed_key(const signer& s) {
    const auto pub = s.secret.public_key().bytes();
    return Rhp::release::root_key{"ed25519", std::vector<std::byte>(pub.begin(), pub.end()), {}};
}

} // namespace identity_revocation_fixture

using namespace identity_revocation_fixture;

TEST_CASE("an identity revocation list round-trips canonically", "[release][identities]") {
    signer dev{"dev"};
    const auto device = Rhp::security::public_key_ref{"p256", std::vector<std::byte>(65, std::byte{4})};
    const auto l = list_of(3, {"77", "12"}, {Rhp::security::key_ref(dev.secret.public_key())}, {device});
    const auto bytes = identity_envelope(l, {&dev});
    const auto back = Rhp::release::decode_identity_revocations(bytes);
    REQUIRE(back.has_value());
    CHECK(back->body.seq == 3);
    CHECK(back->body.cert_serials == std::vector<std::string>{"12", "77"}); // sorted
    CHECK(back->body.device_keys == std::vector{device});
    CHECK(back->signatures.size() == 1);
    // Bad entries are refused.
    CHECK_FALSE(Rhp::release::make_identity_revocations(list_of(0, {})).has_value());
    CHECK_FALSE(Rhp::release::make_identity_revocations(list_of(1, {"has space"})).has_value());
    CHECK_FALSE(Rhp::release::make_identity_revocations(list_of(1, {}, {Rhp::security::public_key_ref{"ed25519", std::vector<std::byte>(31)}})).has_value());
    CHECK_FALSE(Rhp::release::make_identity_revocations(list_of(1, std::vector<std::string>(Rhp::release::kMaxListEntries + 1, "x"))).has_value());
    // Another document is not identity revocations.
    CHECK_FALSE(Rhp::release::decode_identity_revocations(revocations(Rhp::release::revocation_list{1, 0, {}, {}, {}}, {&dev})).has_value());
}

TEST_CASE("a manager keeps the union of identity revocations and restores it", "[release][identities]") {
    signer dev{"dev"}, other{"other"};
    Rhp::release::memory_store store;
    const auto signer_key = Rhp::security::key_ref(other.secret.public_key());
    {
        Rhp::release::manager m{trust_of({{&dev, {"*"}}}), options_at(kNow), store};
        REQUIRE(m.revoke_identities(identity_envelope(list_of(1, {"s1"}), {&dev})));
        REQUIRE(m.revoke_identities(identity_envelope(list_of(2, {"s2"}, {signer_key}), {&dev})));
        const auto ids = m.identities();
        CHECK(ids->is_revoked_serial("s1"));
        CHECK(ids->is_revoked_serial("s2"));
        CHECK(ids->is_revoked_signer(other.secret.public_key()));
        CHECK_FALSE(ids->is_revoked_signer(dev.secret.public_key()));
        CHECK_FALSE(ids->is_revoked_device(other.secret.public_key()));
        CHECK(m.trust_held().identity_seq == 2);
        // Older or repeated: superseded; unsigned or signed by an untrusted key: refused.
        CHECK(m.revoke_identities(identity_envelope(list_of(2, {"s9"}), {&dev})).error().code == errc::kSuperseded);
        CHECK(m.revoke_identities(identity_envelope(list_of(3, {"s9"}), {})).error().code == errc::kBadSignature);
        CHECK(m.revoke_identities(identity_envelope(list_of(3, {"s9"}), {&other})).error().code == errc::kBadSignature);
        CHECK_FALSE(ids->is_revoked_serial("s9"));
    }
    Rhp::release::manager m{trust_of({{&dev, {"*"}}}), options_at(kNow), store};
    REQUIRE(m.restore());
    CHECK(m.identities()->is_revoked_serial("s1"));
    CHECK(m.identities()->is_revoked_signer(other.secret.public_key()));
    CHECK(m.trust_held().identity_seq == 2);
}

TEST_CASE("identity revocation seqs are capped like release revocation lists", "[release][identities]") {
    signer dev{"dev"};
    Rhp::release::manager m{trust_of({{&dev, {"*"}}}), options_at(kNow)};
    std::vector<Rhp::release::release_event> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    // The first counts from the host's clock, later ones from the last.
    CHECK(m.revoke_identities(identity_envelope(list_of(kNow + kJump + 1, {"a"}), {&dev})).error().code == errc::kOutOfRange);
    REQUIRE_FALSE(events.empty());
    CHECK(events.back().what == Rhp::release::release_event::kind::kRefused);
    CHECK(m.identities()->seq() == 0);
    REQUIRE(m.revoke_identities(identity_envelope(list_of(7, {"a"}), {&dev})));
    CHECK(events.back().what == Rhp::release::release_event::kind::kTrust);
    CHECK(m.revoke_identities(identity_envelope(list_of(7 + kJump + 1, {"b"}), {&dev})).error().code == errc::kOutOfRange);
    REQUIRE(m.revoke_identities(identity_envelope(list_of(7 + kJump, {"b"}), {&dev})));
    CHECK(m.identities()->is_revoked_serial("a"));
    CHECK(m.identities()->is_revoked_serial("b"));
}

TEST_CASE("identity revocations from the root's revocation role and their recover step", "[release][identities][root]") {
    signer root_a{"root-a"}, rel{"release-1"}, rev{"revocation-1"}, rev2{"revocation-2"};
    const auto doc = [&](std::uint64_t v) {
        Rhp::release::root_document d;
        d.version = v;
        for (const signer* s : {&root_a, &rel, &rev, &rev2}) {
            d.keys[s->name] = ed_key(*s);
        }
        d.role(root_role::kRoot).keys = {root_a.name};
        d.role(root_role::kRelease).keys = {rel.name};
        d.role(root_role::kRevocation).keys = {rev.name, rev2.name};
        return d;
    };
    const auto sealed = [&](Rhp::release::root_document d) {
        auto r = *Rhp::release::make_root(std::move(d));
        REQUIRE(Rhp::release::sign(r, root_a.key()));
        return r;
    };
    Rhp::release::memory_store store;
    Rhp::release::manager m{sealed(doc(1)), options_at(kNow), store};
    CHECK(m.revoke_identities(identity_envelope(list_of(1, {"x"}), {&rel})).error().code == errc::kBadSignature); // the release role signs no revocations
    REQUIRE(m.revoke_identities(identity_envelope(list_of(1, {"honest"}), {&rev2})));
    REQUIRE(m.revoke_identities(identity_envelope(list_of(kNow, {"stolen"}), {&rev})));
    CHECK(m.identities()->is_revoked_serial("stolen"));
    // Through kTrust's path: version 2 marks revocation-1 compromised.
    auto d2 = doc(2);
    d2.role(root_role::kRevocation).keys = {rev2.name};
    d2.compromised = {rev.name};
    const std::vector<std::vector<std::byte>> docs{*Rhp::release::encode_root(sealed(d2))};
    const auto state = m.update_trust(docs);
    REQUIRE(state.has_value());
    CHECK(state->root_version == 2);
    CHECK(state->identity_seq == 1); // back to the honest list
    CHECK(m.identities()->is_revoked_serial("honest"));
    CHECK_FALSE(m.identities()->is_revoked_serial("stolen"));
    std::size_t kept = 0;
    for (const auto& k : *store.keys()) {
        kept += k.starts_with("trust/identities/") ? 1 : 0;
    }
    CHECK(kept == 1);
    // Identity revocations arrive through update_trust too.
    const std::vector<std::vector<std::byte>> more{identity_envelope(list_of(2, {"later"}), {&rev2})};
    REQUIRE(m.update_trust(more));
    CHECK(m.identities()->is_revoked_serial("later"));
}
