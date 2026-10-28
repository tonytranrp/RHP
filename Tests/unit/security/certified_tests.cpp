// The certified signer policy (decision AL11): claims made by the key, and every check the trust
// makes against a signature_context (app, env, audience, identity, expiry, replay, role, dev tags,
// revocation).
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/signer.hpp>

using Rhp::errc;
using Rhp::role;
using Rhp::value;
using namespace Rhp::security;
using namespace std::chrono_literals;

namespace certified_fixtures {

constexpr std::string_view kSource = "return 1 + 1";

struct claims_pki {
    ed25519_secret_key ca = *ed25519_secret_key::generate();
    ed25519_secret_key op = *ed25519_secret_key::generate();
    std::string ca_env;

    [[nodiscard]] operator_cert cert(role max = role::kPatch, std::vector<std::string> apps = {}, std::vector<std::string> envs = {}, std::uint64_t serial = 1) const {
        const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        operator_cert_fields f;
        f.serial = serial;
        f.principal = "alice";
        const auto pub_key = op.public_key(); // bytes() views it: keep it alive
        const auto pub = pub_key.bytes();
        f.pub.assign(pub.begin(), pub.end());
        f.not_before = now - 60;
        f.not_after = now + 3600;
        f.max_role = max;
        f.apps = std::move(apps);
        f.envs = std::move(envs);
        return *issue_operator_cert(ca, std::move(f));
    }

    [[nodiscard]] certified::key key(operator_cert c, certified::claim_options claims = {}) const { return {op, std::move(c), std::move(claims)}; }

    [[nodiscard]] certified::trust trust(certified::trust_options options = {}) const {
        trusted_cas cas;
        REQUIRE(cas.add({"ops", ca.public_key(), ca_env}));
        return certified::trust{std::move(cas), options};
    }
};

[[nodiscard]] signature_context here(role granted = role::kPatch) {
    signature_context c;
    c.identity = "alice-session";
    c.granted = granted;
    c.app = "game";
    c.env = "dev";
    c.host_id = "host-1";
    c.now = std::chrono::system_clock::now();
    c.level = Rhp::hardening::kDev;
    return c;
}

} // namespace certified_fixtures

using namespace certified_fixtures;

TEST_CASE("certified: a signature verifies once and names the certificate", "[security][certified]") {
    claims_pki k;
    const auto key = k.key(k.cert());
    const auto trust = k.trust();
    auto sig = key.sign(kSource, {.identity = "alice-session", .app = "game", .env = "dev", .audience = "host-1"});
    REQUIRE(sig);
    auto who = trust.verify(kSource, *sig, here());
    REQUIRE(who);
    CHECK(*who == "alice#1");
    // The claims it made.
    const auto* claims_bytes = sig->find("claims")->get_if<value::bytes>();
    REQUIRE(claims_bytes != nullptr);
    auto claims = decode_claims(*claims_bytes);
    REQUIRE(claims);
    CHECK(claims->identity == "alice-session");
    CHECK(claims->app == "game");
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    CHECK(claims->not_after <= static_cast<std::uint64_t>(now) + 600);
    CHECK(claims->not_after > static_cast<std::uint64_t>(now) + 590);
}

TEST_CASE("certified: a replayed nonce is refused", "[security][certified]") {
    claims_pki k;
    const auto key = k.key(k.cert());
    const auto trust = k.trust();
    auto sig = key.sign(kSource);
    REQUIRE(sig);
    REQUIRE(trust.verify(kSource, *sig, here()));
    CHECK(trust.verify(kSource, *sig, here()).error().code == errc::kBadSignature);
    const auto copy = trust; // copies share the cache
    CHECK(copy.verify(kSource, *sig, here()).error().code == errc::kBadSignature);
    // A fresh signature of the same source has a fresh nonce.
    CHECK(trust.verify(kSource, *key.sign(kSource), here()));
}

TEST_CASE("certified: the replay cache refuses once full of live nonces", "[security][certified]") {
    claims_pki k;
    const auto key = k.key(k.cert());
    const auto trust = k.trust({.max_lifetime = 3600s, .replay_entries = 2});
    CHECK(trust.verify(kSource, *key.sign(kSource), here()));
    CHECK(trust.verify(kSource, *key.sign(kSource), here()));
    CHECK(trust.verify(kSource, *key.sign(kSource), here()).error().code == errc::kLimitExceeded);
    // Later than every claim's not_after, the old nonces are gone (the certificate is still valid).
    auto later = here();
    later.now += 700s;
    certified::claim_options longer;
    longer.lifetime = 1200s;
    CHECK(trust.verify(kSource, *k.key(k.cert(), longer).sign(kSource), later));
}

TEST_CASE("certified: claims must match the host", "[security][certified]") {
    claims_pki k;
    const auto key = k.key(k.cert());
    const auto trust = k.trust();
    const auto refused = [&](const signing_context& c) { return trust.verify(kSource, *key.sign(kSource, c), here()).error().code; };
    CHECK(refused({.app = "editor"}) == errc::kOutOfScope);
    CHECK(refused({.env = "prod"}) == errc::kOutOfScope);
    CHECK(refused({.audience = "host-2"}) == errc::kOutOfScope);
    CHECK(refused({.identity = "bob"}) == errc::kOutOfScope);
    // Empty = any.
    CHECK(trust.verify(kSource, *key.sign(kSource, {}), here()));
    // A claim the host can't match (it has no app) fails closed.
    auto no_app = here();
    no_app.app = {};
    CHECK(trust.verify(kSource, *key.sign(kSource, {.app = "game"}), no_app).error().code == errc::kOutOfScope);
}

TEST_CASE("certified: the key's own claim options apply when the client says nothing", "[security][certified]") {
    claims_pki k;
    certified::claim_options claims;
    claims.app = "editor";
    const auto key = k.key(k.cert(), claims);
    const auto trust = k.trust();
    CHECK(trust.verify(kSource, *key.sign(kSource), here()).error().code == errc::kOutOfScope);
    CHECK(trust.verify(kSource, *key.sign(kSource, {.app = "game"}), here())); // the client's wins
}

TEST_CASE("certified: expired claims are refused", "[security][certified]") {
    claims_pki k;
    const auto key = k.key(k.cert());
    const auto trust = k.trust();
    auto sig = key.sign(kSource);
    REQUIRE(sig);
    auto later = here();
    later.now += 601s;
    CHECK(trust.verify(kSource, *sig, later).error().code == errc::kExpired);
    // Claims further ahead than max_lifetime.
    certified::claim_options long_lived;
    long_lived.lifetime = 2h;
    const auto strict = k.trust({.max_lifetime = 30min, .replay_entries = 16});
    CHECK(strict.verify(kSource, *k.key(k.cert(), long_lived).sign(kSource), here()).error().code == errc::kExpired);
}

TEST_CASE("certified: the certificate's apps and envs must list the host's", "[security][certified]") {
    claims_pki k;
    const auto trust = k.trust();
    CHECK(trust.verify(kSource, *k.key(k.cert(role::kPatch, {"editor"})).sign(kSource), here()).error().code == errc::kOutOfScope);
    CHECK(trust.verify(kSource, *k.key(k.cert(role::kPatch, {"game"}, {"prod"})).sign(kSource), here()).error().code == errc::kOutOfScope);
    CHECK(trust.verify(kSource, *k.key(k.cert(role::kPatch, {"game"}, {"dev"})).sign(kSource), here()));
}

TEST_CASE("certified: max_role below the session's role is refused", "[security][certified]") {
    claims_pki k;
    const auto trust = k.trust();
    const auto key = k.key(k.cert(role::kPatch));
    CHECK(trust.verify(kSource, *key.sign(kSource), here(role::kAdmin)).error().code == errc::kForbidden);
    CHECK(trust.verify(kSource, *key.sign(kSource), here(role::kObserve)));
    CHECK(trust.verify(kSource, *key.sign(kSource), here(role::kPatch)));
}

TEST_CASE("certified: tampering with the source or claims breaks the signature", "[security][certified]") {
    claims_pki k;
    const auto key = k.key(k.cert());
    const auto trust = k.trust();
    auto sig = key.sign(kSource);
    REQUIRE(sig);
    CHECK(trust.verify("return 2", *sig, here()).error().code == errc::kBadSignature);
    // Other claims under the same signature.
    auto other = key.sign(kSource, {.identity = "bob"});
    REQUIRE(other);
    value::map swapped;
    swapped.emplace_back(value{"cert"}, *sig->find("cert"));
    swapped.emplace_back(value{"claims"}, *other->find("claims"));
    swapped.emplace_back(value{"sig"}, *sig->find("sig"));
    CHECK(trust.verify(kSource, value{std::move(swapped)}, here()).error().code == errc::kBadSignature);
    CHECK(trust.verify(kSource, value{}, here()).error().code == errc::kBadSignature);
    CHECK(trust.verify(kSource, value{"nonsense"}, here()).error().code == errc::kBadSignature);
}

TEST_CASE("certified: a CA the trust doesn't have is refused", "[security][certified]") {
    claims_pki k;
    claims_pki other;
    CHECK(other.trust().verify(kSource, *k.key(k.cert()).sign(kSource), here()).error().code == errc::kBadSignature);
    // A key that isn't the certificate's can't sign.
    const certified::key wrong{other.op, k.cert()};
    CHECK(wrong.sign(kSource).error().code == errc::kInvalidArgument);
}

TEST_CASE("certified: production refuses dev-tagged CAs and certificates", "[security][certified]") {
    claims_pki k;
    auto prod = here();
    prod.level = Rhp::hardening::kProduction;
    prod.env = "prod";
    // A dev certificate (envs lists dev), even when it also lists prod.
    CHECK(k.trust().verify(kSource, *k.key(k.cert(role::kPatch, {}, {"dev", "prod"})).sign(kSource), prod).error().code == errc::kForbidden);
    CHECK(k.trust().verify(kSource, *k.key(k.cert(role::kPatch, {}, {"prod"})).sign(kSource), prod));
    // A dev CA.
    k.ca_env = "dev";
    CHECK(k.trust().verify(kSource, *k.key(k.cert()).sign(kSource), prod).error().code == errc::kForbidden);
    CHECK(k.trust().verify(kSource, *k.key(k.cert()).sign(kSource), here())); // a dev host takes it
}

TEST_CASE("certified: revoked serials are refused", "[security][certified]") {
    claims_pki k;
    auto trust = k.trust();
    const auto copy = trust; // handed to a host before the revocation
    const auto key = k.key(k.cert(role::kPatch, {}, {}, 41));
    CHECK(copy.verify(kSource, *key.sign(kSource), here()));
    trust.revoke(41);
    CHECK(copy.verify(kSource, *key.sign(kSource), here()).error().code == errc::kRevoked);
    trust.set_revocation_check([](const operator_cert& c) { return c.fields.serial == 42; });
    CHECK(copy.verify(kSource, *k.key(k.cert(role::kPatch, {}, {}, 42)).sign(kSource), here()).error().code == errc::kRevoked);
    CHECK(copy.verify(kSource, *k.key(k.cert(role::kPatch, {}, {}, 43)).sign(kSource), here()));
}

TEST_CASE("certified: a root of trust replaces the CAs and adds a revocation check", "[security][certified]") {
    claims_pki k;
    claims_pki other;
    auto trust = k.trust();
    const auto copy = trust;
    const auto mine = k.key(k.cert());
    const auto theirs = other.key(other.cert());
    trusted_cas root;
    REQUIRE(root.add({"root:ca-2", other.ca.public_key(), {}}));
    trust.set_root_of_trust(root, [](const operator_cert& c) { return c.fields.serial == 7; });
    CHECK(copy.verify(kSource, *mine.sign(kSource), here()).error().code == errc::kBadSignature);
    CHECK(copy.verify(kSource, *theirs.sign(kSource), here()));
    CHECK(copy.verify(kSource, *other.key(other.cert(role::kPatch, {}, {}, 7)).sign(kSource), here()).error().code == errc::kRevoked);
    REQUIRE(copy.root_cas());
    CHECK(copy.root_cas()->size() == 1);
    // A root naming no CAs: the trust's own are back.
    trust.set_root_of_trust(std::nullopt, {});
    CHECK(copy.verify(kSource, *mine.sign(kSource), here()));
    CHECK(copy.verify(kSource, *theirs.sign(kSource), here()).error().code == errc::kBadSignature);
}

TEST_CASE("certified: the certificate's scopes reach the context", "[security][certified]") {
    claims_pki k;
    const auto trust = k.trust();
    const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    operator_cert_fields f;
    f.serial = 5;
    f.principal = "alice";
    const auto pub_key = k.op.public_key(); // bytes() views it: keep it alive
    const auto pub = pub_key.bytes();
    f.pub.assign(pub.begin(), pub.end());
    f.not_before = now - 60;
    f.not_after = now + 3600;
    f.scopes = {"op:exec", "!cap:economy.*"};
    const auto key = k.key(*issue_operator_cert(k.ca, f));
    Rhp::scope_set scopes;
    auto context = here();
    context.scopes = &scopes;
    REQUIRE(trust.verify(kSource, *key.sign(kSource), context));
    CHECK(scopes == *Rhp::scope_set::parse("op:exec,!cap:economy.*"));
    // A certificate without scopes leaves them as they are; one with a malformed pattern isn't issued.
    Rhp::scope_set untouched;
    context.scopes = &untouched;
    REQUIRE(trust.verify(kSource, *k.key(k.cert()).sign(kSource), context));
    CHECK(untouched.unrestricted());
    f.scopes = {"lib:a,lib:b"};
    CHECK(issue_operator_cert(k.ca, f).error().code == errc::kInvalidArgument);
    f.scopes = {"nonsense"};
    CHECK(issue_operator_cert(k.ca, f).error().code == errc::kInvalidArgument);
}

TEST_CASE("certified: a P-256 operator key held by a key handle signs", "[security][certified][p256]") {
    claims_pki k;
    const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto secret = generate_private_key(key_algorithm::kP256);
    REQUIRE(secret);
    auto handle = key_handle::from_private_key(key_algorithm::kP256, secret->bytes());
    if (!handle) {
        CHECK(handle.error().code == errc::kDisabled);
        SKIP("no TLS backend: P-256 reports kDisabled");
    }
    // A hardware key: only its public half and a sign callback.
    const key_handle software = *handle;
    auto hardware = key_handle::from_callback(key_algorithm::kP256, software.public_key(), [software](std::span<const std::byte> m) { return software.sign(m); });
    REQUIRE(hardware);
    operator_cert_fields f;
    f.serial = 256;
    f.principal = "hsm";
    f.alg = std::string{kAlgP256};
    f.pub.assign(hardware->public_key().begin(), hardware->public_key().end());
    f.not_before = now - 60;
    f.not_after = now + 3600;
    auto cert = issue_operator_cert(k.ca, f);
    REQUIRE(cert);
    REQUIRE(cert->key_alg() == key_algorithm::kP256);
    CHECK(cert->operator_key().error().code == errc::kInvalidArgument);
    const certified::key key{*hardware, *cert};
    const auto trust = k.trust();
    auto sig = key.sign(kSource);
    REQUIRE(sig);
    CHECK(trust.verify(kSource, *sig, here()) == "hsm#256");
    CHECK(trust.verify("return 2", *key.sign(kSource), here()).error().code == errc::kBadSignature);
    // An Ed25519 key with the P-256 certificate, or the other way round: refused before signing.
    CHECK(certified::key{k.op, *cert}.sign(kSource).error().code == errc::kInvalidArgument);
    CHECK(certified::key{*hardware, k.cert()}.sign(kSource).error().code == errc::kInvalidArgument);
}

TEST_CASE("certified: without a context the strictest defaults apply", "[security][certified]") {
    claims_pki k;
    const auto trust = k.trust();
    // No context: role admin, no app or env, so a patch certificate or an app claim doesn't pass.
    CHECK(trust.verify(kSource, *k.key(k.cert()).sign(kSource)).error().code == errc::kForbidden);
    CHECK(trust.verify(kSource, *k.key(k.cert(role::kAdmin)).sign(kSource)));
    CHECK(trust.verify(kSource, *k.key(k.cert(role::kAdmin)).sign(kSource, {.app = "game"})).error().code == errc::kOutOfScope);
}

TEST_CASE("certified: the context helpers keep plain signers unchanged", "[security][certified]") {
    // ed25519 has no context overloads: verify_in_context and sign_in_context call the plain ones.
    static_assert(!context_trust<trusted_signers>);
    static_assert(!context_key<signing_key>);
    const auto secret = *ed25519_secret_key::generate();
    const signing_key key{"dev", secret};
    const trusted_signers trust{{"dev", secret.public_key()}};
    auto sig = sign_in_context(key, kSource, {.identity = "x"});
    REQUIRE(sig);
    CHECK(*sig == *key.sign(kSource));
    CHECK(*verify_in_context(trust, kSource, *sig, here()) == "dev");
}

TEST_CASE("certified: claims encode canonically", "[security][certified]") {
    script_claims c;
    c.not_after = 1234;
    c.app = "game";
    c.nonce[0] = std::byte{9};
    auto bytes = encode_claims(c);
    REQUIRE(bytes);
    auto back = decode_claims(*bytes);
    REQUIRE(back);
    CHECK(*back == c);
    auto longer = *bytes;
    longer.push_back(std::byte{0});
    CHECK_FALSE(decode_claims(longer));
}
