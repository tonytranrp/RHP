// kTrust (Stage 13b, wire revision 7): a client pushes root of trust versions and identity
// revocations to a host's release manager; revoked script signer keys sign nothing any more.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
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
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_revocations.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::release::root_role;
using namespace release_test;

namespace stage13_trust_fixture {

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

struct world {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key watcher = *Rhp::security::key::generate();
    signer developer{"dev"}, other{"ops"};
    signer root_a{"root-a"}, rel{"release-1"}, rev{"revocation-1"}, rel2{"release-2"};

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin}, {"watcher", watcher, Rhp::role::kObserve}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const {
        return Rhp::security::trusted_signers{{"dev", developer.secret.public_key()}, {"ops", other.secret.public_key()}};
    }

    static Rhp::release::root_key key(const signer& s) {
        const auto pub_key = s.secret.public_key(); // bytes() views it: keep it alive
        const auto pub = pub_key.bytes();
        return Rhp::release::root_key{"ed25519", std::vector<std::byte>(pub.begin(), pub.end()), {}};
    }

    [[nodiscard]] Rhp::release::signed_root root(std::uint64_t version, const signer& release) const {
        Rhp::release::root_document d;
        d.version = version;
        for (const signer* s : {&root_a, &release, &rev}) {
            d.keys[s->name] = key(*s);
        }
        d.role(root_role::kRoot).keys = {root_a.name};
        d.role(root_role::kRelease).keys = {release.name};
        d.role(root_role::kRevocation).keys = {rev.name};
        auto r = *Rhp::release::make_root(std::move(d));
        REQUIRE(Rhp::release::sign(r, root_a.key()));
        return r;
    }
};

std::vector<std::byte> identities_revoking(const Rhp::security::ed25519_public_key& signer_key, std::uint64_t seq, const signer& by) {
    Rhp::security::identity_revocation_list l;
    l.seq = seq;
    l.signer_keys = {Rhp::security::key_ref(signer_key)};
    l.cert_serials = {"1001"};
    auto doc = *Rhp::release::make_identity_revocations(std::move(l));
    REQUIRE(Rhp::release::sign(doc, by.key()));
    return *Rhp::release::encode_identity_revocations(doc);
}

} // namespace stage13_trust_fixture

using namespace stage13_trust_fixture;

TEST_CASE("stage13: kTrust pushes a root and identity revocations to a host", "[stage13][trust]") {
    world w;
    Rhp::release::manager releases{w.root(1, w.rel), {}, Rhp::release::memory_store{}};
    REQUIRE(releases.restore());
    const auto at = Rhp::endpoint::listen("itest.s13.trust", 1);
    Rhp::host<cfg> host{at, w.ring(), w.trusted()};
    REQUIRE(host.serve(releases));
    std::jthread pump{[&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", w.admin}, w.developer.key()};
    Rhp::client<cfg> watcher{at.reversed(), Rhp::security::psk_identity{"watcher", w.watcher}, w.developer.key()};
    REQUIRE(admin.exec<int>("return 1"));

    // Observe may push: the documents carry their own signatures.
    const std::vector<std::vector<std::byte>> root2{*Rhp::release::encode_root(w.root(2, w.rel2))};
    const auto pushed = watcher.trust(root2);
    REQUIRE(pushed.has_value());
    CHECK(pushed->root_version == 2);
    CHECK(pushed->identity_seq == 0);

    // A skipped version is refused with its code; nothing changes.
    const std::vector<std::vector<std::byte>> root4{*Rhp::release::encode_root(w.root(4, w.rel2))};
    CHECK(watcher.trust(root4).error().code == errc::kOutOfRange);

    // Identity revocations by a key outside the revocation role: refused.
    const std::vector<std::vector<std::byte>> forged{identities_revoking(w.developer.secret.public_key(), 1, w.rel2)};
    CHECK(watcher.trust(forged).error().code == errc::kBadSignature);
    REQUIRE(admin.exec<int>("return 2"));

    // Revoking the script signer "dev": its scripts are refused, "ops" still signs.
    const std::vector<std::vector<std::byte>> revoked{identities_revoking(w.developer.secret.public_key(), 1, w.rev)};
    const auto after = watcher.trust(revoked);
    REQUIRE(after.has_value());
    CHECK(after->identity_seq == 1);
    CHECK(admin.exec<int>("return 3").error().code == errc::kRevoked);
    CHECK(releases.identities()->is_revoked_serial("1001"));
    Rhp::client<cfg> ops{at.reversed(), Rhp::security::psk_identity{"admin", w.admin}, w.other.key()};
    CHECK(*ops.exec<int>("return 4") == 4);

    const auto status = watcher.release_status();
    REQUIRE(status.has_value());
    CHECK(status->root_version == 2);
    CHECK(status->identity_seq == 1);
    pump.request_stop();
}

TEST_CASE("stage13: kTrust to a host without a release manager is refused", "[stage13][trust]") {
    world w;
    const auto at = Rhp::endpoint::listen("itest.s13.trust_none", 1);
    Rhp::host<cfg> host{at, w.ring(), w.trusted()};
    std::jthread pump{[&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            std::this_thread::sleep_for(1ms);
        }
    }};
    Rhp::client<cfg> watcher{at.reversed(), Rhp::security::psk_identity{"watcher", w.watcher}, w.developer.key()};
    const std::vector<std::vector<std::byte>> root2{*Rhp::release::encode_root(w.root(2, w.rel2))};
    CHECK_FALSE(watcher.trust(root2).has_value());
    pump.request_stop();
}
