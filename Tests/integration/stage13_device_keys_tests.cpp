// Stage 13b device keys over the wire (decisions AL10, AL11): config<>::auth<device_keys> over TCP
// with TLS, what a device-key host refuses (plaintext, a TLS-terminating relay, unpinned or changed
// host keys, revoked keys), trust on first use, and a production host refusing dev-tagged keys of
// each kind (keyring PSKs, device keys, trusted signers).
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/hardening.hpp>
#include <rhp_test/tls_relay.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/security/device_keys.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/key_handle.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/known_hosts.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;

namespace stage13_device_fixtures {

using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>::auth<Rhp::security::device_keys>;
using loop_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>::auth<Rhp::security::device_keys>;
using loop_psk_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

Rhp::security::key_handle new_key() {
    auto secret = Rhp::security::generate_private_key(Rhp::security::key_algorithm::kEd25519);
    REQUIRE(secret);
    auto k = Rhp::security::key_handle::from_private_key(Rhp::security::key_algorithm::kEd25519, secret->bytes());
    REQUIRE(k);
    return *k;
}

std::vector<std::byte> pub_of(const Rhp::security::key_handle& k) {
    return {k.public_key().begin(), k.public_key().end()};
}

struct devices {
    Rhp::security::key_handle host_key = new_key();
    Rhp::security::key_handle phone = new_key();
    Rhp::security::key_handle tablet = new_key();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();
    std::shared_ptr<Rhp::security::revoked_identities> revoked = std::make_shared<Rhp::security::revoked_identities>();

    // phone: patch, untagged; tablet: patch, env=dev.
    [[nodiscard]] Rhp::security::device_keys auth() const {
        Rhp::security::device_allow_list list;
        REQUIRE(list.add({"phone", Rhp::role::kPatch, phone.alg(), pub_of(phone), {}, std::nullopt}));
        REQUIRE(list.add({"tablet", Rhp::role::kPatch, tablet.alg(), pub_of(tablet), {}, Rhp::security::key_env::kDev}));
        return {std::move(list), host_key, revoked};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
    // `who`'s credential with the host key pinned for `endpoint`.
    [[nodiscard]] Rhp::security::device_credential as(const Rhp::security::key_handle& who, std::string endpoint) const {
        Rhp::security::known_hosts pins;
        REQUIRE(pins.add({endpoint, host_key.alg(), pub_of(host_key)}));
        return {"device", who, pins, std::move(endpoint), {}};
    }
};

// A host pumped by its own thread.
template <class Cfg>
class running_host {
public:
    template <class... Args>
    explicit running_host(Args&&... args) : host_(std::forward<Args>(args)...) {
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }
    ~running_host() {
        pump_.request_stop();
        pump_.join();
    }
    running_host(const running_host&) = delete;
    running_host& operator=(const running_host&) = delete;

    Rhp::host<Cfg>* operator->() noexcept { return &host_; }

private:
    Rhp::host<Cfg> host_;
    std::jthread pump_;
};

[[nodiscard]] bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

Rhp::client_options quick() {
    Rhp::client_options o;
    o.connect_timeout = 5s;
    return o;
}

} // namespace stage13_device_fixtures

using namespace stage13_device_fixtures;

TEST_CASE("stage13: device keys authenticate over TCP with TLS and the welcome names the host key", "[stage13][device][tls]") {
    devices d;
    running_host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls), d.auth(), d.trusted()};
    const auto port = host->port();
    REQUIRE(port);
    const std::string at = "127.0.0.1:" + std::to_string(*port);
    Rhp::client<tcp_cfg> c{Rhp::endpoint::dial("127.0.0.1", *port, Rhp::net::require_tls), d.as(d.phone, at), d.signer(), quick()};
    CHECK(c.exec<int>("return 6 * 7") == 42);
    const auto who = c.info();
    CHECK(who.identity == "phone");
    CHECK(who.granted == Rhp::role::kPatch);
    CHECK(who.tls);
    CHECK(who.host_key == d.host_key.fingerprint());
}

TEST_CASE("stage13: a device-key host refuses plaintext and keys it doesn't list", "[stage13][device]") {
    devices d;
    running_host<loop_cfg> plain{Rhp::endpoint::listen("s13d.plain", 1), d.auth(), d.trusted()};
    Rhp::client<loop_cfg> over_plaintext{Rhp::endpoint::dial("s13d.plain", 1), d.as(d.phone, "s13d.plain"), d.signer(), quick()};
    CHECK_FALSE(over_plaintext.connect());

    running_host<loop_cfg> host{Rhp::endpoint::listen("s13d.tls", 1, Rhp::net::require_tls), d.auth(), d.trusted()};
    Rhp::client<loop_cfg> stranger{Rhp::endpoint::dial("s13d.tls", 1, Rhp::net::require_tls), d.as(new_key(), "s13d.tls"), d.signer(), quick()};
    CHECK_FALSE(stranger.connect());
    Rhp::client<loop_cfg> phone{Rhp::endpoint::dial("s13d.tls", 1, Rhp::net::require_tls), d.as(d.phone, "s13d.tls"), d.signer(), quick()};
    CHECK(phone.exec<int>("return 1") == 1);
}

TEST_CASE("stage13: a relay that terminates TLS can't pass the device-key handshake; a plain relay can", "[stage13][device][tls][security]") {
    devices d;
    running_host<loop_cfg> host{Rhp::endpoint::listen("s13d.mitm_host", 1, Rhp::net::require_tls), d.auth(), d.trusted()};
    {
        rhp_test::tls_relay mitm{Rhp::endpoint::listen("s13d.mitm_front", 1), Rhp::endpoint::dial("s13d.mitm_host", 1), true};
        Rhp::client<loop_cfg> victim{Rhp::endpoint::dial("s13d.mitm_front", 1, Rhp::net::require_tls), d.as(d.phone, "front"), d.signer(), quick()};
        auto r = victim.connect();
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::kAuth);
    }
    {
        rhp_test::tls_relay dumb{Rhp::endpoint::listen("s13d.plain_front", 1), Rhp::endpoint::dial("s13d.mitm_host", 1), false};
        Rhp::client<loop_cfg> through{Rhp::endpoint::dial("s13d.plain_front", 1, Rhp::net::require_tls), d.as(d.phone, "front"), d.signer(), quick()};
        CHECK(through.exec<int>("return 5") == 5);
    }
}

TEST_CASE("stage13: a device-key client refuses a changed host key and asks about a new one", "[stage13][device][known_hosts]") {
    devices d;
    running_host<loop_cfg> host{Rhp::endpoint::listen("s13d.pins", 1, Rhp::net::require_tls), d.auth(), d.trusted()};
    const auto dial = Rhp::endpoint::dial("s13d.pins", 1, Rhp::net::require_tls);

    // Pinned to another key: refused without asking.
    Rhp::security::device_credential changed{"device", d.phone, {}, "s13d.pins", [](std::string_view, std::string_view) { return true; }};
    REQUIRE(changed.pins.add({"s13d.pins", d.tablet.alg(), pub_of(d.tablet)}));
    Rhp::client<loop_cfg> wrong{dial, changed, d.signer(), quick()};
    auto refused = wrong.connect();
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::kAuth);
    CHECK(contains(refused.error().message, "changed"));

    // Not pinned: the callback decides; yes pins the key for the next connection.
    Rhp::security::device_credential fresh{"device", d.phone, {}, "s13d.pins", [](std::string_view, std::string_view) { return false; }};
    Rhp::client<loop_cfg> no{dial, fresh, d.signer(), quick()};
    CHECK_FALSE(no.connect());
    fresh.trust_new = [&](std::string_view endpoint, std::string_view fingerprint) { return endpoint == "s13d.pins" && fingerprint == d.host_key.fingerprint(); };
    Rhp::client<loop_cfg> yes{dial, fresh, d.signer(), quick()};
    CHECK(yes.exec<int>("return 2") == 2);
    CHECK(fresh.pins.check("s13d.pins", d.host_key.alg(), d.host_key.public_key()) == Rhp::security::known_hosts::match::kPinned);
}

TEST_CASE("stage13: a device key the identity revocations name is refused at its next handshake", "[stage13][device][revocation]") {
    devices d;
    running_host<loop_cfg> host{Rhp::endpoint::listen("s13d.revoked", 1, Rhp::net::require_tls), d.auth(), d.trusted()};
    const auto dial = Rhp::endpoint::dial("s13d.revoked", 1, Rhp::net::require_tls);
    {
        Rhp::client<loop_cfg> before{dial, d.as(d.phone, "s13d.revoked"), d.signer(), quick()};
        CHECK(before.exec<int>("return 3") == 3);
    }
    Rhp::security::identity_revocation_list list;
    list.seq = 1;
    list.device_keys.push_back({"ed25519", pub_of(d.phone)});
    d.revoked->merge(list); // what a served release::manager's identities() does when it accepts a list
    Rhp::client<loop_cfg> after{dial, d.as(d.phone, "s13d.revoked"), d.signer(), quick()};
    CHECK_FALSE(after.connect());
}

TEST_CASE("stage13: a production host refuses dev-tagged PSKs and device keys and signers", "[stage13][device][hardening]") {
    const Rhp::host_options production{.hardening = Rhp::hardening::kProduction};
    const auto prod_signer = *Rhp::security::ed25519_secret_key::generate();
    const auto dev_signer = *Rhp::security::ed25519_secret_key::generate();
    Rhp::security::trusted_signers signers{{"prod", prod_signer.public_key()}, {"devsig", dev_signer.public_key()}};
    REQUIRE(signers.set_env("prod", Rhp::security::key_env::kProd));
    REQUIRE(signers.set_env("devsig", Rhp::security::key_env::kDev));

    // Keyring PSKs.
    const auto prod_psk = *Rhp::security::key::generate();
    const auto dev_psk = *Rhp::security::key::generate();
    auto ring = Rhp::security::keyring::parse("prod patch " + prod_psk.to_base64() + " env=prod\ndevkey patch " + dev_psk.to_base64() + " env=dev\n");
    REQUIRE(ring);
    running_host<loop_psk_cfg> psk_host{Rhp::endpoint::listen("s13d.prod_psk", 1), std::move(*ring), signers, production};
    const auto psk_at = Rhp::endpoint::dial("s13d.prod_psk", 1);
    Rhp::client<loop_psk_cfg> dev_key{psk_at, Rhp::security::psk_identity{"devkey", dev_psk}, Rhp::security::signing_key{"prod", prod_signer}, quick()};
    auto refused = dev_key.connect();
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::kAuth);
    Rhp::client<loop_psk_cfg> prod_key{psk_at, Rhp::security::psk_identity{"prod", prod_psk}, Rhp::security::signing_key{"prod", prod_signer}, quick()};
    CHECK(prod_key.exec<int>("return 4") == 4);

    // Trusted signers: a dev signer's scripts are unsigned to this host.
    Rhp::client<loop_psk_cfg> dev_signed{psk_at, Rhp::security::psk_identity{"prod", prod_psk}, Rhp::security::signing_key{"devsig", dev_signer}, quick()};
    auto unsigned_exec = dev_signed.exec<int>("return 5");
    REQUIRE_FALSE(unsigned_exec);
    CHECK(unsigned_exec.error().code == errc::kBadSignature);

    // Device keys: the tablet is tagged env=dev, the phone untagged.
    devices d;
    running_host<loop_cfg> device_host{Rhp::endpoint::listen("s13d.prod_device", 1, Rhp::net::require_tls), d.auth(), signers, production};
    const auto device_at = Rhp::endpoint::dial("s13d.prod_device", 1, Rhp::net::require_tls);
    Rhp::client<loop_cfg> tablet{device_at, d.as(d.tablet, "s13d.prod_device"), Rhp::security::signing_key{"prod", prod_signer}, quick()};
    auto tablet_refused = tablet.connect();
    REQUIRE_FALSE(tablet_refused);
    CHECK(tablet_refused.error().code == errc::kAuth);
    Rhp::client<loop_cfg> phone{device_at, d.as(d.phone, "s13d.prod_device"), Rhp::security::signing_key{"prod", prod_signer}, quick()};
    CHECK(phone.exec<int>("return 6") == 6);
}

TEST_CASE("stage13: below production dev-tagged keys still authenticate", "[stage13][device][hardening]") {
    rhp_test::needs(Rhp::hardening::kLan, "a dev-tagged key (production refuses them)");
    devices d;
    running_host<loop_cfg> host{Rhp::endpoint::listen("s13d.dev_ok", 1, Rhp::net::require_tls), d.auth(), d.trusted()};
    Rhp::client<loop_cfg> tablet{Rhp::endpoint::dial("s13d.dev_ok", 1, Rhp::net::require_tls), d.as(d.tablet, "s13d.dev_ok"), d.signer(), quick()};
    CHECK(tablet.exec<int>("return 7") == 7);
}
