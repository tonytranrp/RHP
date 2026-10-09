#include <cstddef>
#include <memory>
#include <string>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/utils/byte_buffer.hpp>

using Rhp::errc;
using Rhp::value;
using namespace Rhp::security;

namespace {

struct fixture {
    key dev = *key::generate();
    key qa = *key::generate();
    psk_keyring host{keyring{{"dev", dev, Rhp::role::kAdmin}, {"qa", qa, Rhp::role::kPatch}}};
};

struct outcome {
    Rhp::result<auth_grant> host;
    Rhp::result<auth_grant> client;
};

// Runs the three messages between both sides.
outcome handshake(const psk_keyring& host, const psk_identity& client) {
    auto h = host.begin();
    auto c = client.begin();
    auto hello = c->hello();
    REQUIRE(hello);
    auto challenge = h->challenge(*hello);
    if (!challenge) {
        return {std::unexpected{challenge.error()}, std::unexpected{challenge.error()}};
    }
    auto response = c->respond(*challenge);
    if (!response) {
        return {Rhp::fail(errc::kAuth, "client refused"), std::unexpected{response.error()}};
    }
    return {h->verify(*response), c->finish()};
}

} // namespace

TEST_CASE("psk: the right key gets the identity, role and matching frame keys", "[security][psk]") {
    fixture f;
    auto r = handshake(f.host, psk_identity{"qa", f.qa});
    REQUIRE(r.host);
    REQUIRE(r.client);
    CHECK(r.host->identity == "qa");
    CHECK(r.host->granted == Rhp::role::kPatch);
    CHECK(r.client->identity == "qa");

    // What one side seals, the other side's incoming key verifies — per direction.
    const std::string text = "header and payload";
    const auto data = Rhp::utils::as_bytes(text);
    const auto from_client = r.client->outgoing->seal(data);
    CHECK(r.host->incoming->verify(data, from_client));
    const auto from_host = r.host->outgoing->seal(data);
    CHECK(r.client->incoming->verify(data, from_host));
    // Directions differ, so a frame can't be reflected back.
    CHECK_FALSE(r.client->incoming->verify(data, from_client));
    // Tampering fails.
    const std::string other = "header and payloaD";
    CHECK_FALSE(r.host->incoming->verify(Rhp::utils::as_bytes(other), from_client));
}

TEST_CASE("psk: every session gets fresh keys", "[security][psk]") {
    fixture f;
    auto a = handshake(f.host, psk_identity{"dev", f.dev});
    auto b = handshake(f.host, psk_identity{"dev", f.dev});
    REQUIRE(a.host);
    REQUIRE(b.host);
    const std::string text = "same frame";
    const auto mac = a.client->outgoing->seal(Rhp::utils::as_bytes(text));
    CHECK_FALSE(b.host->incoming->verify(Rhp::utils::as_bytes(text), mac));
}

TEST_CASE("psk: a wrong key fails on both sides without the client proving anything", "[security][psk]") {
    fixture f;
    auto r = handshake(f.host, psk_identity{"dev", f.qa});
    REQUIRE_FALSE(r.client);
    CHECK(r.client.error().code == errc::kAuth);
    REQUIRE_FALSE(r.host);
}

TEST_CASE("psk: an unknown key name looks like a wrong key", "[security][psk]") {
    fixture f;
    auto h = f.host.begin();
    auto c = psk_identity{"ghost", f.dev}.begin();
    auto hello = c->hello();
    REQUIRE(hello);
    auto challenge = h->challenge(*hello);
    REQUIRE(challenge); // a normal challenge, not an early "no such key"
    CHECK(challenge->find("proof") != nullptr);
    auto response = c->respond(*challenge);
    REQUIRE_FALSE(response);
    CHECK(response.error().code == errc::kAuth);
}

TEST_CASE("psk: forged or out-of-order messages are refused", "[security][psk]") {
    fixture f;
    auto h = f.host.begin();
    CHECK(h->challenge(value{"not a map"}).error().code == errc::kProtocol);
    CHECK(h->verify(value{}).error().code == errc::kProtocol); // response before challenge

    auto h2 = f.host.begin();
    auto c = psk_identity{"dev", f.dev}.begin();
    auto hello = c->hello();
    REQUIRE(hello);
    REQUIRE(h2->challenge(*hello));
    value::map forged;
    forged.emplace_back(value{"proof"}, value{value::bytes(32, std::byte{0})});
    CHECK(h2->verify(value{std::move(forged)}).error().code == errc::kAuth);
    CHECK(h2->verify(value{}).error().code == errc::kProtocol); // only one try

    auto c2 = psk_identity{"dev", f.dev}.begin();
    REQUIRE(c2->hello());
    CHECK(c2->respond(value{value::map{}}).error().code == errc::kProtocol);
    CHECK(c2->finish().error().code == errc::kProtocol);
}

TEST_CASE("psk: the concepts", "[security][psk]") {
    STATIC_REQUIRE(authenticator<psk_keyring>);
    STATIC_REQUIRE(credential<psk_identity>);
    STATIC_REQUIRE(std::same_as<psk_keyring::credential, psk_identity>);
}
