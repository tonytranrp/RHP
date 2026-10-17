#include <chrono>
#include <format>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <rhp/security/http_auth.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/base64.hpp>
#include <rhp/utils/byte_buffer.hpp>

namespace {

using Rhp::security::http_proof;
using Rhp::security::verify_http_authorization;

struct http_fixture {
    Rhp::security::key secret = *Rhp::security::key::generate();
    Rhp::security::psk_identity identity{"dev", secret};
    Rhp::security::keyring keys{{"dev", secret, Rhp::role::kPatch}};
    std::string body = "return 42";

    [[nodiscard]] http_proof request(std::string_view authorization = {}) const { return {authorization, "POST", "/exec", "signature", "text/plain", Rhp::utils::as_bytes(body)}; }

    [[nodiscard]] std::string sign(std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) const {
        auto header = Rhp::security::http_authorization(identity, request(), now);
        REQUIRE(header);
        return *header;
    }
};

} // namespace

TEST_CASE("http proof grants the key's identity and role", "[security][http]") {
    const http_fixture f;
    const auto header = f.sign();
    auto grant = verify_http_authorization(f.keys, f.request(header));
    REQUIRE(grant);
    CHECK(grant->identity == "dev");
    CHECK(grant->granted == Rhp::role::kPatch);
    CHECK(grant->expires > std::chrono::system_clock::now() + Rhp::security::kHttpSkew);
    CHECK(f.sign() != header); // a fresh nonce every time
}

TEST_CASE("http proof covers every part of the request", "[security][http]") {
    const http_fixture f;
    const auto header = f.sign();
    const auto refused = [&](http_proof changed) {
        changed.authorization = header;
        const auto checked = verify_http_authorization(f.keys, changed);
        return !checked && checked.error().code == Rhp::errc::kAuth;
    };
    auto r = f.request();
    SECTION("method") {
        r.method = "GET";
    }
    SECTION("target") {
        r.target = "/modules/a";
    }
    SECTION("body") {
        r.body = Rhp::utils::as_bytes("return 43");
    }
    SECTION("signature header") {
        r.signature = "changed";
    }
    SECTION("content type") {
        r.content_type = "application/msgpack";
    }
    CHECK(refused(r));
}

TEST_CASE("http proof is refused outside the clock skew", "[security][http]") {
    const http_fixture f;
    const auto now = std::chrono::system_clock::now();
    const auto header = f.sign(now);
    CHECK(verify_http_authorization(f.keys, f.request(header), now + Rhp::security::kHttpSkew));
    CHECK_FALSE(verify_http_authorization(f.keys, f.request(header), now + Rhp::security::kHttpSkew + std::chrono::seconds{2}));
    CHECK_FALSE(verify_http_authorization(f.keys, f.request(header), now - Rhp::security::kHttpSkew - std::chrono::seconds{2}));
}

TEST_CASE("http proof refuses malformed and foreign authorization", "[security][http]") {
    const http_fixture f;
    const auto header = f.sign();
    Rhp::security::keyring other{{"dev", *Rhp::security::key::generate(), Rhp::role::kAdmin}};
    CHECK_FALSE(verify_http_authorization(other, f.request(header)));
    Rhp::security::keyring unknown{{"someone", f.secret, Rhp::role::kAdmin}};
    CHECK_FALSE(verify_http_authorization(unknown, f.request(header)));
    for (const auto& bad : {std::string{"RHP dev,0,nonce,mac"}, std::string{"Bearer x"}, std::string{"RHP dev,1,2"}, std::string{"RHP ,1,2,3"},
                                  std::string{"RHP "} + std::string(600, 'x'), header + ",extra"}) {
        const auto checked = verify_http_authorization(f.keys, f.request(bad));
        REQUIRE_FALSE(checked);
        CHECK(checked.error().code == Rhp::errc::kAuth);
    }
    // One nonce has one spelling: a non-canonical base64 nonce is refused before the MAC.
    auto noncanonical = header;
    const auto first_comma = noncanonical.find(',');
    const auto nonce_at = noncanonical.find(',', first_comma + 1) + 1;
    noncanonical.insert(nonce_at, " ");
    CHECK_FALSE(verify_http_authorization(f.keys, f.request(noncanonical)));
}

TEST_CASE("http proof binds the TLS channel when asked to", "[security][http]") {
    const http_fixture f;
    const std::string client_side(32, 'c');
    const std::string relay_side(32, 'r');
    auto bound = f.request();
    bound.channel = Rhp::security::kHttpChannelTlsExporter;
    bound.binding = Rhp::utils::as_bytes(client_side);
    auto header = Rhp::security::http_authorization(f.identity, bound);
    REQUIRE(header);
    bound.authorization = *header;
    // The host on the same TLS connection computes the same binding.
    auto grant = verify_http_authorization(f.keys, bound);
    REQUIRE(grant);
    CHECK(grant->bound);
    // A relay that terminated TLS has another connection to the host: another binding.
    auto relayed = bound;
    relayed.binding = Rhp::utils::as_bytes(relay_side);
    CHECK_FALSE(verify_http_authorization(f.keys, relayed));
    // Dropping the header (an unbound transcript) doesn't match either.
    auto stripped = bound;
    stripped.channel = {};
    stripped.binding = {};
    CHECK_FALSE(verify_http_authorization(f.keys, stripped));
    // Asked for, but the connection has no TLS: refused on both ends.
    auto plaintext = bound;
    plaintext.binding = {};
    CHECK_FALSE(verify_http_authorization(f.keys, plaintext));
    plaintext.authorization = {};
    CHECK_FALSE(Rhp::security::http_authorization(f.identity, plaintext));
    auto unknown = bound;
    unknown.channel = "tls-unique";
    CHECK_FALSE(verify_http_authorization(f.keys, unknown));
    // An unbound proof isn't marked bound.
    auto plain = verify_http_authorization(f.keys, f.request(f.sign()));
    REQUIRE(plain);
    CHECK_FALSE(plain->bound);
}

TEST_CASE("http answer proof covers status content type and body of one request", "[security][http]") {
    const http_fixture f;
    const auto header = f.sign();
    auto grant = verify_http_authorization(f.keys, f.request(header));
    REQUIRE(grant);
    REQUIRE(grant->answer_key);
    const std::string body = "answer";
    const Rhp::security::http_answer answer{200, "application/msgpack", Rhp::utils::as_bytes(body)};
    const auto proof = Rhp::security::http_answer_proof(*grant->answer_key, answer);
    CHECK(Rhp::security::verify_http_answer(f.identity, header, answer, proof));

    const auto rejected = [&](const Rhp::security::http_answer& changed, std::string_view with = {}) {
        const auto checked = Rhp::security::verify_http_answer(f.identity, header, changed, with.empty() ? std::string_view{proof} : with);
        return !checked && checked.error().code == Rhp::errc::kIntegrity;
    };
    const std::string other = "answe!";
    CHECK(rejected({500, answer.content_type, answer.body}));
    CHECK(rejected({200, "text/plain", answer.body}));
    CHECK(rejected({200, answer.content_type, Rhp::utils::as_bytes(other)}));
    CHECK(rejected(answer, "not a proof"));
    CHECK_FALSE(Rhp::security::verify_http_answer(f.identity, header, answer, ""));
    // The proof answers this request only: another request's key gives another proof.
    const auto second = f.sign();
    CHECK_FALSE(Rhp::security::verify_http_answer(f.identity, second, answer, proof));
    // Someone without the key can't make one.
    const Rhp::security::psk_identity stranger{"dev", *Rhp::security::key::generate()};
    CHECK_FALSE(Rhp::security::verify_http_answer(stranger, header, answer, proof));
    const Rhp::security::psk_identity renamed{"other", f.secret};
    CHECK_FALSE(Rhp::security::verify_http_answer(renamed, header, answer, proof));
}

TEST_CASE("http replay guard admits a proof once per identity quota", "[security][http]") {
    const auto now = std::chrono::system_clock::now();
    Rhp::security::http_replay_guard guard{2};
    const auto grant = [&](std::string identity, std::string nonce) { return Rhp::security::http_grant{std::move(identity), Rhp::role::kPatch, std::move(nonce), now + std::chrono::seconds{31}}; };
    REQUIRE(guard.admit(grant("observe", "a"), now));
    const auto replay = guard.admit(grant("observe", "a"), now);
    REQUIRE_FALSE(replay);
    CHECK(replay.error().code == Rhp::errc::kAuth);
    REQUIRE(guard.admit(grant("observe", "b"), now));
    const auto full = guard.admit(grant("observe", "c"), now);
    REQUIRE_FALSE(full);
    CHECK(full.error().code == Rhp::errc::kLimitExceeded);
    CHECK(guard.admit(grant("admin", "a"), now)); // another key's quota is untouched
    REQUIRE(guard.next_expiry());
    CHECK(guard.admit(grant("observe", "c"), now + std::chrono::seconds{32})); // expired entries free the quota
    CHECK(guard.size() == 1);
}

TEST_CASE("http signature header round trips the signer's value", "[security][http]") {
    const Rhp::value signature = Rhp::value::map{{"signer", "dev"}, {"sig", Rhp::value::bytes(64, std::byte{7})}};
    auto header = Rhp::security::http_signature_header(signature);
    REQUIRE(header);
    auto read = Rhp::security::read_http_signature(*header);
    REQUIRE(read);
    CHECK(*read == signature);
    CHECK(Rhp::security::read_http_signature("")->is_nil());
    const auto bad = Rhp::security::read_http_signature("not base64!");
    REQUIRE_FALSE(bad);
    CHECK(bad.error().code == Rhp::errc::kBadSignature);
}
