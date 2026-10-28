// Device keys (decision AL10): the allow-list, known hosts and the handshake between both sides
// in-process (the network runs are Tests/integration/stage13_device_keys_tests.cpp).
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <format>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/core/value.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/authenticator.hpp>
#include <rhp/security/device_keys.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/known_hosts.hpp>
#include <rhp/utils/byte_buffer.hpp>

using Rhp::errc;
using namespace Rhp::security;
namespace fs = std::filesystem;

namespace device_keys_fixtures {

key_handle new_key() {
    auto secret = generate_private_key(key_algorithm::kEd25519);
    REQUIRE(secret);
    auto k = key_handle::from_private_key(key_algorithm::kEd25519, secret->bytes());
    REQUIRE(k);
    return *k;
}

std::vector<std::byte> pub_of(const key_handle& k) {
    return {k.public_key().begin(), k.public_key().end()};
}

std::vector<std::byte> binding(std::byte fill) {
    return std::vector<std::byte>(32, fill);
}

struct device_fixture {
    key_handle host_key = new_key();
    key_handle phone = new_key();
    key_handle stranger = new_key();
    device_allow_list allowed;
    known_hosts pins;

    device_fixture() {
        auto scopes = Rhp::scope_set::parse("lib:game");
        REQUIRE(scopes);
        REQUIRE(allowed.add({"phone", Rhp::role::kPatch, key_algorithm::kEd25519, pub_of(phone), *scopes, std::nullopt}));
        REQUIRE(pins.add({"lab:7777", host_key.alg(), pub_of(host_key)}));
    }

    [[nodiscard]] device_keys host(std::shared_ptr<const revoked_identities> revoked = {}) const { return {allowed, host_key, std::move(revoked)}; }
    [[nodiscard]] device_credential as(const key_handle& k) const { return {"phone", k, pins, "lab:7777", {}}; }
};

struct outcome {
    Rhp::result<auth_grant> host;
    Rhp::result<auth_grant> client;
};

// The three messages between both sides, each side bound to its own channel binding.
outcome handshake(const device_keys& host, const device_credential& client, std::span<const std::byte> host_binding, std::span<const std::byte> client_binding) {
    auto h = host.begin();
    auto c = client.begin();
    auto hello = c->hello();
    REQUIRE(hello);
    h->bind_channel(host_binding);
    auto challenge = h->challenge(*hello);
    if (!challenge) {
        return {std::unexpected{challenge.error()}, std::unexpected{challenge.error()}};
    }
    c->bind_channel(client_binding);
    auto response = c->respond(*challenge);
    if (!response) {
        return {Rhp::fail(errc::kAuth, "client refused"), std::unexpected{response.error()}};
    }
    return {h->verify(*response), c->finish()};
}

outcome handshake(const device_keys& host, const device_credential& client) {
    const auto b = binding(std::byte{7});
    return handshake(host, client, b, b);
}

struct device_temp_folder {
    fs::path path;

    device_temp_folder() {
        std::string suffix;
        for (const std::byte b : *Rhp::platform::random_array<6>()) {
            suffix += std::format("{:02x}", std::to_integer<unsigned>(b));
        }
        path = fs::temp_directory_path() / ("rhp_device_keys_" + suffix);
        REQUIRE(Rhp::platform::make_private_directory(path));
    }
    ~device_temp_folder() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    device_temp_folder(const device_temp_folder&) = delete;
    device_temp_folder& operator=(const device_temp_folder&) = delete;
};

} // namespace device_keys_fixtures

using namespace device_keys_fixtures;

TEST_CASE("device keys: a listed key gets its name and role and scopes and matching frame keys", "[security][device]") {
    device_fixture f;
    auto r = handshake(f.host(), f.as(f.phone));
    REQUIRE(r.host);
    REQUIRE(r.client);
    CHECK(r.host->identity == "phone");
    CHECK(r.host->granted == Rhp::role::kPatch);
    CHECK(r.host->scopes == *Rhp::scope_set::parse("lib:game"));
    CHECK(r.host->host_key == f.host_key.fingerprint());
    CHECK(r.client->host_key == f.host_key.fingerprint());

    const std::string text = "header and payload";
    const auto data = Rhp::utils::as_bytes(text);
    CHECK(r.host->incoming->verify(data, r.client->outgoing->seal(data)));
    CHECK(r.client->incoming->verify(data, r.host->outgoing->seal(data)));
    CHECK_FALSE(r.client->incoming->verify(data, r.client->outgoing->seal(data)));
}

TEST_CASE("device keys: an unlisted key is challenged like a listed one and fails at verify", "[security][device]") {
    device_fixture f;
    auto r = handshake(f.host(), f.as(f.stranger));
    REQUIRE(r.client); // the host proved itself: the client can't tell it isn't listed
    REQUIRE_FALSE(r.host);
    CHECK(r.host.error().code == errc::kAuth);
}

TEST_CASE("device keys: a listed public key signed by another key fails", "[security][device]") {
    device_fixture f;
    // Claims the phone's public key but signs with the stranger's private key.
    const key_handle impostor_signer = f.stranger;
    auto impostor = key_handle::from_callback(key_algorithm::kEd25519, f.phone.public_key(),
                                              [impostor_signer](std::span<const std::byte> m) { return impostor_signer.sign(m); });
    REQUIRE(impostor);
    auto r = handshake(f.host(), f.as(*impostor));
    REQUIRE_FALSE(r.host);
    CHECK(r.host.error().code == errc::kAuth);
}

TEST_CASE("device keys: plaintext and a different channel binding are refused", "[security][device][tls]") {
    device_fixture f;
    auto plain = handshake(f.host(), f.as(f.phone), {}, {});
    REQUIRE_FALSE(plain.host);
    CHECK(plain.host.error().code == errc::kAuth);
    CHECK(plain.host.error().message == "device keys need TLS");

    // The client alone without a binding refuses too.
    auto h = f.host().begin();
    auto c = f.as(f.phone).begin();
    const auto b = binding(std::byte{1});
    h->bind_channel(b);
    auto challenge = h->challenge(*c->hello());
    REQUIRE(challenge);
    auto refused = c->respond(*challenge);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().message == "device keys need TLS");

    // A relay with a TLS connection to each side has two bindings: the host's signature fails.
    auto relayed = handshake(f.host(), f.as(f.phone), binding(std::byte{1}), binding(std::byte{2}));
    REQUIRE_FALSE(relayed.client);
    CHECK(relayed.client.error().code == errc::kAuth);
}

TEST_CASE("device keys: a revoked device key is refused like an unlisted one", "[security][device][revocation]") {
    device_fixture f;
    auto revoked = std::make_shared<revoked_identities>();
    REQUIRE(handshake(f.host(revoked), f.as(f.phone)).host);
    identity_revocation_list list;
    list.seq = 1;
    list.device_keys.push_back({"ed25519", pub_of(f.phone)});
    revoked->merge(list); // the host's policy asks at every handshake
    auto r = handshake(f.host(revoked), f.as(f.phone));
    REQUIRE_FALSE(r.host);
    CHECK(r.host.error().code == errc::kAuth);
}

TEST_CASE("device keys: the client refuses a host key that isn't pinned or changed", "[security][device][known_hosts]") {
    device_fixture f;
    const device_keys other_host{f.allowed, f.stranger};
    auto changed = handshake(other_host, f.as(f.phone));
    REQUIRE_FALSE(changed.client);
    CHECK(changed.client.error().code == errc::kAuth);
    CHECK(changed.client.error().message.find("changed") != std::string::npos);

    device_credential elsewhere = f.as(f.phone);
    elsewhere.endpoint = "elsewhere:1";
    auto unknown = handshake(f.host(), elsewhere);
    REQUIRE_FALSE(unknown.client);
    CHECK(unknown.client.error().message.find("not in known_hosts") != std::string::npos);
}

TEST_CASE("device keys: trust on first use pins the key when the callback accepts it", "[security][device][known_hosts]") {
    device_fixture f;
    device_credential c = f.as(f.phone);
    c.endpoint = "new:1";
    std::string asked;
    c.trust_new = [&](std::string_view endpoint, std::string_view fingerprint) {
        asked = std::format("{} {}", endpoint, fingerprint);
        return false;
    };
    auto rejected = handshake(f.host(), c);
    REQUIRE_FALSE(rejected.client);
    CHECK(asked == "new:1 " + f.host_key.fingerprint());
    CHECK(f.pins.check("new:1", f.host_key.alg(), f.host_key.public_key()) == known_hosts::match::kUnknown);

    c.trust_new = [](std::string_view, std::string_view) { return true; };
    REQUIRE(handshake(f.host(), c).host);
    // Copies share the pins: the next handshake needs no callback.
    CHECK(f.pins.check("new:1", f.host_key.alg(), f.host_key.public_key()) == known_hosts::match::kPinned);
    c.trust_new = {};
    CHECK(handshake(f.host(), c).host);
    // A host that isn't the one pinned is refused without asking.
    bool asked_again = false;
    c.trust_new = [&](std::string_view, std::string_view) { return asked_again = true; };
    CHECK_FALSE(handshake(device_keys{f.allowed, f.stranger}, c).client);
    CHECK_FALSE(asked_again);
}

TEST_CASE("device keys: a PSK hello to a device-key host is a protocol error", "[security][device]") {
    device_fixture f;
    auto h = f.host().begin();
    h->bind_channel(binding(std::byte{1}));
    Rhp::value::map hello;
    hello.emplace_back("key", Rhp::value{std::string{"dev"}});
    auto r = h->challenge(Rhp::value{std::move(hello)});
    REQUIRE_FALSE(r);
    CHECK(r.error().code == errc::kProtocol);
}

TEST_CASE("device allow-list: lines with scopes and env tags parse and print back", "[security][device]") {
    device_fixture f;
    const std::string pub = base64_encode(f.phone.public_key());
    const std::string text = std::format("# devices\nphone patch ed25519 {} lib:game env=prod\ntablet observe ed25519 {} env=dev\n", pub,
                                         base64_encode(f.stranger.public_key()));
    auto list = device_allow_list::parse(text);
    REQUIRE(list);
    REQUIRE(list->size() == 2);
    CHECK(list->find("phone")->granted == Rhp::role::kPatch);
    CHECK(list->find(key_algorithm::kEd25519, f.phone.public_key())->name == "phone");
    CHECK(list->env_of("phone") == key_env::kProd);
    CHECK(list->env_of("tablet") == key_env::kDev);
    CHECK(list->without(key_env::kDev).size() == 1);
    auto again = device_allow_list::parse(list->to_text());
    REQUIRE(again);
    CHECK(again->to_text() == list->to_text());

    CHECK(device_allow_list::parse("phone patch ed25519\n").error().code == errc::kInvalidArgument);
    CHECK(device_allow_list::parse(std::format("phone boss ed25519 {}\n", pub)).error().message.find("unknown role") != std::string::npos);
    CHECK(device_allow_list::parse(std::format("phone patch rsa {}\n", pub)).error().message.find("unknown algorithm") != std::string::npos);
    CHECK(device_allow_list::parse("phone patch ed25519 AAAA\n").error().code == errc::kInvalidArgument);
    CHECK(device_allow_list::parse(std::format("a patch ed25519 {0}\nb patch ed25519 {0}\n", pub)).error().code == errc::kAlreadyLoaded);
    CHECK(device_allow_list::parse(std::format("a patch ed25519 {} lib:a lib:b\n", pub)).error().message.find("unexpected") != std::string::npos);
}

TEST_CASE("known hosts: lines parse and a file-backed set writes every pin", "[security][device][known_hosts]") {
    device_fixture f;
    device_temp_folder dir;
    const fs::path file = dir.path / "known_hosts";
    auto pins = known_hosts::load(file); // no file yet: empty
    REQUIRE(pins);
    CHECK(pins->entries().empty());
    REQUIRE(pins->add({"lab:7777", f.host_key.alg(), pub_of(f.host_key)}));
    REQUIRE(pins->add({"lab:7777", f.host_key.alg(), pub_of(f.host_key)})); // already pinned: no change
    CHECK(fs::exists(file));
    CHECK_FALSE(Rhp::platform::readable_by_others(file));
    auto reread = known_hosts::load(file);
    REQUIRE(reread);
    REQUIRE(reread->entries().size() == 1);
    CHECK(reread->check("lab:7777", f.host_key.alg(), f.host_key.public_key()) == known_hosts::match::kPinned);
    CHECK(reread->check("lab:7777", f.stranger.alg(), f.stranger.public_key()) == known_hosts::match::kChanged);
    CHECK(reread->check("lab:1", f.host_key.alg(), f.host_key.public_key()) == known_hosts::match::kUnknown);
    CHECK(reread->find("lab:7777").size() == 1);

    CHECK_FALSE(pins->add({"two words", f.host_key.alg(), pub_of(f.host_key)}));
    CHECK_FALSE(pins->add({"x:1", key_algorithm::kP256, pub_of(f.host_key)}));
    CHECK(known_hosts::parse("lab:1 ed25519\n").error().code == errc::kInvalidArgument);
    CHECK(known_hosts::parse("lab:1 rsa AAAA\n").error().code == errc::kInvalidArgument);
}
