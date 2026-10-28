#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/security/ed25519.hpp>

using Rhp::errc;
using Rhp::release::root_role;
using namespace release_test;

namespace {

Rhp::release::root_key root_key_of(const signer& s, std::vector<std::string> channels = {}) {
    const auto pub = s.secret.public_key().bytes();
    return Rhp::release::root_key{"ed25519", std::vector<std::byte>(pub.begin(), pub.end()), std::move(channels)};
}

// A root whose root role is `root_keys` (threshold `n`) and whose other roles hold `release` and `revocation`.
Rhp::release::root_document root_doc(std::uint64_t version, const std::vector<const signer*>& root_keys, std::uint32_t n, const signer* release = nullptr,
                                     const signer* revocation = nullptr) {
    Rhp::release::root_document doc;
    doc.version = version;
    for (const signer* s : root_keys) {
        doc.keys[s->name] = root_key_of(*s);
        doc.role(root_role::kRoot).keys.push_back(s->name);
    }
    doc.role(root_role::kRoot).threshold = n;
    if (release != nullptr) {
        doc.keys[release->name] = root_key_of(*release, {"game.*"});
        doc.role(root_role::kRelease).keys.push_back(release->name);
    }
    if (revocation != nullptr) {
        doc.keys[revocation->name] = root_key_of(*revocation);
        doc.role(root_role::kRevocation).keys.push_back(revocation->name);
    }
    return doc;
}

Rhp::release::signed_root signed_root_by(Rhp::release::root_document doc, const std::vector<const signer*>& signers) {
    auto r = Rhp::release::make_root(std::move(doc));
    REQUIRE(r.has_value());
    for (const signer* s : signers) {
        REQUIRE(Rhp::release::sign(*r, s->key()));
    }
    return *r;
}

struct root_signers {
    signer a{"root-a"}, b{"root-b"}, c{"root-c"}, d{"root-d"}, e{"root-e"};
    signer rel{"release-1"}, rev{"revocation-1"};
};

} // namespace

TEST_CASE("a root document round-trips canonically", "[release][root]") {
    root_signers k;
    auto doc = root_doc(1, {&k.a, &k.b}, 2, &k.rel, &k.rev);
    doc.expires = 1'900'000'000;
    doc.keys["p256-later"] = Rhp::release::root_key{"p256", std::vector<std::byte>(65, std::byte{4}), {}};
    const auto root = signed_root_by(doc, {&k.a, &k.b});
    const auto bytes = Rhp::release::encode_root(root);
    REQUIRE(bytes.has_value());
    const auto back = Rhp::release::decode_root(*bytes);
    REQUIRE(back.has_value());
    CHECK(back->body == doc);
    CHECK(back->body_bytes == root.body_bytes);
    CHECK(back->signatures == root.signatures);
    // The role's key order doesn't matter: the encoding sorts it.
    auto reordered = doc;
    reordered.role(root_role::kRoot).keys = {"root-b", "root-a"};
    CHECK(*Rhp::release::encode_root_document(reordered) == root.body_bytes);
    // Not the root tag, or another envelope: refused.
    CHECK_FALSE(Rhp::release::decode_root_document(std::vector<std::byte>{std::byte{0xc0}}).has_value());
}

TEST_CASE("a root document is validated", "[release][root]") {
    root_signers k;
    auto doc = root_doc(1, {&k.a, &k.b}, 2);
    CHECK(Rhp::release::validate(doc));
    auto bad = doc;
    bad.version = 0;
    CHECK_FALSE(Rhp::release::validate(bad));
    bad = doc;
    bad.role(root_role::kRoot).threshold = 3; // more than its keys
    CHECK_FALSE(Rhp::release::validate(bad));
    bad = doc;
    bad.role(root_role::kRoot).keys.clear();
    CHECK_FALSE(Rhp::release::validate(bad));
    bad = doc;
    bad.role(root_role::kRelease).keys = {"nobody"};
    CHECK_FALSE(Rhp::release::validate(bad));
    bad = doc;
    bad.compromised = {"root-a"}; // still in the root role
    CHECK_FALSE(Rhp::release::validate(bad));
    bad = doc;
    bad.keys["root-a"].pub.pop_back(); // an Ed25519 key is 32 bytes
    CHECK_FALSE(Rhp::release::validate(bad));
    bad = doc;
    bad.keys["root-a"].channels = {"Game"};
    CHECK_FALSE(Rhp::release::validate(bad));
}

TEST_CASE("a genesis root verifies against its own root keys", "[release][root]") {
    root_signers k;
    const auto doc = root_doc(1, {&k.a, &k.b, &k.c}, 2, &k.rel, &k.rev);
    CHECK(Rhp::release::verify_root(signed_root_by(doc, {&k.a, &k.c})));
    const auto one = Rhp::release::verify_root(signed_root_by(doc, {&k.a}));
    REQUIRE_FALSE(one.has_value());
    CHECK(one.error().code == errc::kBadSignature);
    // A key outside the root role doesn't count, nor one key twice under two ids.
    CHECK_FALSE(Rhp::release::verify_root(signed_root_by(doc, {&k.a, &k.rel})).has_value());
    auto twice = doc;
    twice.keys["root-a2"] = root_key_of(k.a);
    twice.role(root_role::kRoot).keys.push_back("root-a2");
    signer a2{"root-a2", k.a.secret};
    CHECK_FALSE(Rhp::release::verify_root(signed_root_by(twice, {&k.a, &a2})).has_value());
    // A signature of another algorithm is kept but never counts.
    auto later = doc;
    later.keys["root-c"].alg = "p256";
    later.keys["root-c"].pub = std::vector<std::byte>(65, std::byte{4});
    CHECK_FALSE(Rhp::release::verify_root(signed_root_by(later, {&k.a, &k.c})).has_value());
}

TEST_CASE("a root rotation needs the old and the new root thresholds", "[release][root]") {
    root_signers k;
    const auto genesis = signed_root_by(root_doc(1, {&k.a, &k.b, &k.c}, 2, &k.rel, &k.rev), {&k.a, &k.b});
    REQUIRE(Rhp::release::verify_root(genesis));

    // c leaves, d joins: a and b sign for both versions.
    const auto rotated = signed_root_by(root_doc(2, {&k.a, &k.b, &k.d}, 2, &k.rel, &k.rev), {&k.a, &k.b});
    CHECK(Rhp::release::verify_next_root(genesis, rotated));

    // Every root key replaced: signed only by the new keys, the old threshold is missing.
    const auto takeover = signed_root_by(root_doc(2, {&k.d, &k.e}, 2, &k.rel, &k.rev), {&k.d, &k.e});
    const auto refused_old = Rhp::release::verify_next_root(genesis, takeover);
    REQUIRE_FALSE(refused_old.has_value());
    CHECK(refused_old.error().code == errc::kBadSignature);
    CHECK(refused_old.error().message.find("root version 1") != std::string::npos);

    // Signed only by the old keys: the new threshold is missing.
    const auto unsigned_new = signed_root_by(root_doc(2, {&k.d, &k.e}, 2, &k.rel, &k.rev), {&k.a, &k.b});
    const auto refused_new = Rhp::release::verify_next_root(genesis, unsigned_new);
    REQUIRE_FALSE(refused_new.has_value());
    CHECK(refused_new.error().message.find("root version 2") != std::string::npos);

    // Both: the full rotation goes through.
    CHECK(Rhp::release::verify_next_root(genesis, signed_root_by(root_doc(2, {&k.d, &k.e}, 2, &k.rel, &k.rev), {&k.a, &k.b, &k.d, &k.e})));
}

TEST_CASE("a root version may not be skipped or repeated", "[release][root]") {
    root_signers k;
    const auto v1 = signed_root_by(root_doc(1, {&k.a}, 1), {&k.a});
    const auto v2 = signed_root_by(root_doc(2, {&k.a}, 1), {&k.a});
    const auto v3 = signed_root_by(root_doc(3, {&k.a}, 1), {&k.a});
    CHECK(Rhp::release::verify_next_root(v1, v3).error().code == errc::kOutOfRange);
    CHECK(Rhp::release::verify_next_root(v2, v1).error().code == errc::kSuperseded);
    CHECK(Rhp::release::verify_next_root(v2, v2).error().code == errc::kSuperseded);
    // Several versions at once: every one in between.
    const std::vector<Rhp::release::signed_root> walk{v2, v3};
    const auto newest = Rhp::release::verify_chain(v1, walk, 0);
    REQUIRE(newest.has_value());
    CHECK(newest->body.version == 3);
    const std::vector<Rhp::release::signed_root> gap{v3};
    CHECK(Rhp::release::verify_chain(v1, gap, 0).error().code == errc::kOutOfRange);
    CHECK(Rhp::release::verify_chain(v1, {}, 0).error().code == errc::kInvalidArgument);
}

TEST_CASE("an expired root is refused as an update but not as an anchor", "[release][root]") {
    root_signers k;
    constexpr std::uint64_t kNow = 1'800'000'000;
    auto d1 = root_doc(1, {&k.a}, 1);
    d1.expires = kNow - 1000; // expired long ago: still an anchor
    const auto v1 = signed_root_by(d1, {&k.a});
    CHECK(Rhp::release::verify_root(v1));
    auto d2 = root_doc(2, {&k.a}, 1);
    d2.expires = kNow - 10;
    const auto v2 = signed_root_by(d2, {&k.a});
    const std::vector<Rhp::release::signed_root> expired{v2};
    CHECK(Rhp::release::verify_chain(v1, expired, kNow).error().code == errc::kExpired);
    CHECK(Rhp::release::verify_chain(v1, expired, kNow, 60)); // within the clock skew
    // An expired root on the way to a valid one is fine.
    auto d3 = root_doc(3, {&k.a}, 1);
    d3.expires = kNow + 3600;
    const std::vector<Rhp::release::signed_root> through{v2, signed_root_by(d3, {&k.a})};
    CHECK(Rhp::release::verify_chain(v1, through, kNow));
}

TEST_CASE("a root names the trust of each role", "[release][root]") {
    root_signers k;
    auto doc = root_doc(1, {&k.a}, 1, &k.rel, &k.rev);
    doc.keys[k.d.name] = root_key_of(k.d);
    doc.compromised = {k.d.name};
    const auto releases = Rhp::release::role_trust(doc, root_role::kRelease);
    REQUIRE(releases.has_value());
    REQUIRE(releases->entries().size() == 1);
    CHECK(releases->entries()[0].name == "release-1");
    CHECK(releases->entries()[0].channels == std::vector<std::string>{"game.*"});
    const auto lists = Rhp::release::role_trust(doc, root_role::kRevocation);
    REQUIRE(lists.has_value());
    CHECK(lists->entries()[0].channels == std::vector<std::string>{"*"});
    CHECK(Rhp::release::role_trust(doc, root_role::kOperatorCa).error().code == errc::kNotFound);
    CHECK(Rhp::release::compromised_keys(doc) == std::vector{k.d.secret.public_key()});
    CHECK(Rhp::release::trusted_keys(doc).size() == 3);
    CHECK(Rhp::release::role_public_keys(doc, root_role::kRevocation) == std::vector{k.rev.secret.public_key()});
}

TEST_CASE("signed_only_by tells lists signed only by compromised keys", "[release][root]") {
    root_signers k;
    Rhp::release::revocation_list list;
    list.seq = 1;
    auto by_c = *Rhp::release::make_revocations(list);
    REQUIRE(Rhp::release::sign(by_c, k.c.key()));
    const std::vector bad{k.c.secret.public_key()};
    const std::vector good{k.a.secret.public_key(), k.b.secret.public_key()};
    const auto only = [&](const Rhp::release::signed_revocations& r) {
        return Rhp::release::signed_only_by(bad, good, Rhp::release::kRevocationSignatureDomain, r.body_bytes, r.signatures);
    };
    CHECK(only(by_c));
    auto with_a = by_c;
    REQUIRE(Rhp::release::sign(with_a, k.a.key()));
    CHECK_FALSE(only(with_a)); // a trusted key signed it too
    auto by_e = *Rhp::release::make_revocations(list);
    REQUIRE(Rhp::release::sign(by_e, k.e.key()));
    CHECK_FALSE(only(by_e)); // signed by a key the root never named: kept
    CHECK_FALSE(Rhp::release::signed_only_by({}, good, Rhp::release::kRevocationSignatureDomain, by_c.body_bytes, by_c.signatures));
}
