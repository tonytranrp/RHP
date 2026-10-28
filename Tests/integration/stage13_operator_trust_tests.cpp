// Operator certificates and a served release manager (decisions AL11, AL12): the operator CAs come
// from the root of trust's operator_ca role, rotate with it, and the manager's identity revocations
// withdraw certificate serials.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "../unit/release/release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/release/identity_revocations.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using release_test::signer;
using Rhp::errc;
using Rhp::release::root_role;

namespace stage13_operator_trust_fixture {

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>::signer<Rhp::security::certified>;

struct world {
    Rhp::security::key psk = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key op = *Rhp::security::ed25519_secret_key::generate();
    signer root_a{"root-a"}, rel{"release-1"}, rev{"revocation-1"}, ca1{"ca-1"}, ca2{"ca-2"}, file_ca{"file-ca"};

    [[nodiscard]] Rhp::security::keyring ring() const { return Rhp::security::keyring{{"ops", psk, Rhp::role::kPatch}}; }
    [[nodiscard]] Rhp::security::psk_identity as() const { return {"ops", psk}; }

    // The trust the host is made with: only "file-ca" (what a trusted-CA file would say).
    [[nodiscard]] Rhp::security::certified::trust trust() const {
        Rhp::security::trusted_cas cas;
        REQUIRE(cas.add({"file-ca", file_ca.secret.public_key(), {}}));
        return Rhp::security::certified::trust{std::move(cas)};
    }

    // A key whose certificate `ca` issued, with `serial`.
    [[nodiscard]] Rhp::security::certified::key key(const signer& ca, std::uint64_t serial) const {
        const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        Rhp::security::operator_cert_fields f;
        f.serial = serial;
        f.principal = "alice";
        const auto pub_key = op.public_key(); // bytes() views it: keep it alive
        const auto pub = pub_key.bytes();
        f.pub.assign(pub.begin(), pub.end());
        f.not_before = now - 60;
        f.not_after = now + 3600;
        return {op, *Rhp::security::issue_operator_cert(ca.secret, std::move(f))};
    }

    static Rhp::release::root_key root_key_of(const signer& s) {
        const auto pub_key = s.secret.public_key(); // bytes() views it: keep it alive
        const auto pub = pub_key.bytes();
        return Rhp::release::root_key{"ed25519", std::vector<std::byte>(pub.begin(), pub.end()), {}};
    }

    // Version `version` naming `operator_cas` as its operator CAs (none: no operator_ca role).
    [[nodiscard]] Rhp::release::signed_root root(std::uint64_t version, std::vector<const signer*> operator_cas) const {
        Rhp::release::root_document d;
        d.version = version;
        for (const signer* s : {&root_a, &rel, &rev}) {
            d.keys[s->name] = root_key_of(*s);
        }
        for (const signer* s : operator_cas) {
            d.keys[s->name] = root_key_of(*s);
            d.role(root_role::kOperatorCa).keys.push_back(s->name);
        }
        d.role(root_role::kRoot).keys = {root_a.name};
        d.role(root_role::kRelease).keys = {rel.name};
        d.role(root_role::kRevocation).keys = {rev.name};
        auto r = *Rhp::release::make_root(std::move(d));
        REQUIRE(Rhp::release::sign(r, root_a.key()));
        return r;
    }
};

std::vector<std::vector<std::byte>> revoking_serial(std::string serial, std::uint64_t seq, const signer& by) {
    Rhp::security::identity_revocation_list l;
    l.seq = seq;
    l.cert_serials = {std::move(serial)};
    auto doc = *Rhp::release::make_identity_revocations(std::move(l));
    REQUIRE(Rhp::release::sign(doc, by.key()));
    return {*Rhp::release::encode_identity_revocations(doc)};
}

// A host serving `releases`, pumped on its own thread.
class serving_host {
public:
    serving_host(Rhp::endpoint ep, const world& w, Rhp::release::manager& releases) : host_(std::move(ep), w.ring(), w.trust()) {
        REQUIRE(host_.serve(releases));
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~serving_host() {
        pump_.request_stop();
        if (pump_.joinable()) {
            pump_.join();
        }
    }

    serving_host(const serving_host&) = delete;
    serving_host& operator=(const serving_host&) = delete;

private:
    Rhp::host<cfg> host_;
    std::jthread pump_;
};

} // namespace stage13_operator_trust_fixture

using namespace stage13_operator_trust_fixture;

TEST_CASE("stage13: the root of trust names the operator CAs and rotating it moves them", "[stage13][certified][root]") {
    world w;
    Rhp::release::manager releases{w.root(1, {&w.ca1}), {}, Rhp::release::memory_store{}};
    REQUIRE(releases.restore());
    const auto at = Rhp::endpoint::listen("s13ot.rotate", 1);
    serving_host host{at, w, releases};

    Rhp::client<cfg> by_ca1{at.reversed(), w.as(), w.key(w.ca1, 11)};
    Rhp::client<cfg> by_ca2{at.reversed(), w.as(), w.key(w.ca2, 12)};
    Rhp::client<cfg> by_file{at.reversed(), w.as(), w.key(w.file_ca, 13)};
    CHECK(by_ca1.exec<int>("return 1") == 1);
    CHECK(by_ca2.exec("return 1").error().code == errc::kBadSignature);
    // The root names operator CAs: they replace the trust's own.
    CHECK(by_file.exec("return 1").error().code == errc::kBadSignature);

    // Version 2 moves to ca-2: ca-1 stops verifying at once.
    const std::vector<std::vector<std::byte>> root2{*Rhp::release::encode_root(w.root(2, {&w.ca2}))};
    REQUIRE(by_ca2.trust(root2));
    CHECK(by_ca1.exec("return 1").error().code == errc::kBadSignature);
    CHECK(by_ca2.exec<int>("return 2") == 2);

    // Version 3 names none: the trust's own CAs are back.
    const std::vector<std::vector<std::byte>> root3{*Rhp::release::encode_root(w.root(3, {}))};
    REQUIRE(by_file.trust(root3));
    CHECK(by_ca2.exec("return 1").error().code == errc::kBadSignature);
    CHECK(by_file.exec<int>("return 3") == 3);
}

TEST_CASE("stage13: a root rotated by the app takes effect at the next pump", "[stage13][certified][root]") {
    world w;
    Rhp::release::manager releases{w.root(1, {&w.ca1}), {}, Rhp::release::memory_store{}};
    REQUIRE(releases.restore());
    const auto at = Rhp::endpoint::listen("s13ot.update_root", 1);
    Rhp::host<cfg> host{at, w.ring(), w.trust()};
    REQUIRE(host.serve(releases));
    const std::vector<Rhp::release::signed_root> newer{w.root(2, {&w.ca2})};
    REQUIRE(releases.update_root(newer));
    host.pump(); // the host hands the new CAs on
    std::jthread pump{[&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    Rhp::client<cfg> by_ca1{at.reversed(), w.as(), w.key(w.ca1, 21)};
    Rhp::client<cfg> by_ca2{at.reversed(), w.as(), w.key(w.ca2, 22)};
    CHECK(by_ca1.exec("return 1").error().code == errc::kBadSignature);
    CHECK(by_ca2.exec<int>("return 1") == 1);
    pump.request_stop();
}

TEST_CASE("stage13: identity revocations withdraw an operator certificate by serial", "[stage13][certified][root]") {
    world w;
    Rhp::release::manager releases{w.root(1, {&w.ca1}), {}, Rhp::release::memory_store{}};
    REQUIRE(releases.restore());
    const auto at = Rhp::endpoint::listen("s13ot.revoked", 1);
    serving_host host{at, w, releases};
    Rhp::client<cfg> revoked{at.reversed(), w.as(), w.key(w.ca1, 77)};
    Rhp::client<cfg> kept{at.reversed(), w.as(), w.key(w.ca1, 78)};
    CHECK(revoked.exec<int>("return 1") == 1);
    REQUIRE(kept.trust(revoking_serial("77", 1, w.rev)));
    CHECK(revoked.exec("return 1").error().code == errc::kRevoked);
    CHECK(kept.exec<int>("return 2") == 2);
}

TEST_CASE("stage13: without a root the trust's own CAs verify and revocations still apply", "[stage13][certified][root]") {
    world w;
    Rhp::release::trust keys;
    REQUIRE(keys.add(w.rev.name, w.rev.secret.public_key()));
    Rhp::release::manager releases{std::move(keys), {}, Rhp::release::memory_store{}};
    REQUIRE(releases.restore());
    const auto at = Rhp::endpoint::listen("s13ot.no_root", 1);
    serving_host host{at, w, releases};
    Rhp::client<cfg> by_file{at.reversed(), w.as(), w.key(w.file_ca, 31)};
    Rhp::client<cfg> by_ca1{at.reversed(), w.as(), w.key(w.ca1, 32)};
    CHECK(by_file.exec<int>("return 1") == 1);
    CHECK(by_ca1.exec("return 1").error().code == errc::kBadSignature);
    REQUIRE(by_file.trust(revoking_serial("31", 1, w.rev)));
    CHECK(by_file.exec("return 1").error().code == errc::kRevoked);
}
