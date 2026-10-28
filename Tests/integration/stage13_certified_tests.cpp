// Certified script signatures over the wire (decision AL11): a client with signer<certified> signs
// with an operator certificate and claims built from its identity and options; the host checks them
// against its own app, environment, id and hardening.
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/security/certified.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/operator_cert.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::hardening;

namespace stage13_certified_fixtures {

using cert_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>::signer<Rhp::security::certified>;

struct pki {
    Rhp::security::key patch_psk = *Rhp::security::key::generate();
    Rhp::security::key admin_psk = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key ca = *Rhp::security::ed25519_secret_key::generate();
    Rhp::security::ed25519_secret_key op = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const { return Rhp::security::keyring{{"patch", patch_psk, Rhp::role::kPatch}, {"admin", admin_psk, Rhp::role::kAdmin}}; }

    [[nodiscard]] Rhp::security::certified::trust trust(std::string ca_env = {}) const {
        Rhp::security::trusted_cas cas;
        REQUIRE(cas.add({"ops", ca.public_key(), std::move(ca_env)}));
        return Rhp::security::certified::trust{std::move(cas)};
    }

    [[nodiscard]] Rhp::security::certified::key key(Rhp::role max = Rhp::role::kPatch, std::vector<std::string> envs = {}) const {
        const auto now = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        Rhp::security::operator_cert_fields f;
        f.serial = 9;
        f.principal = "alice";
        const auto pub = op.public_key().bytes();
        f.pub.assign(pub.begin(), pub.end());
        f.not_before = now - 60;
        f.not_after = now + 3600;
        f.max_role = max;
        f.apps = {"game"};
        f.envs = std::move(envs);
        return {op, *Rhp::security::issue_operator_cert(ca, std::move(f))};
    }

    [[nodiscard]] Rhp::security::psk_identity as(std::string_view who) const {
        return who == "admin" ? Rhp::security::psk_identity{"admin", admin_psk} : Rhp::security::psk_identity{"patch", patch_psk};
    }
};

// A host pumped by its own thread.
class running_host {
public:
    running_host(Rhp::endpoint ep, const pki& k, Rhp::host_options options, std::string ca_env = {}) : host_(std::move(ep), k.ring(), k.trust(std::move(ca_env)), std::move(options)) {
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~running_host() {
        pump_.request_stop();
        if (pump_.joinable()) {
            pump_.join();
        }
    }

    running_host(const running_host&) = delete;
    running_host& operator=(const running_host&) = delete;

    Rhp::host<cert_cfg>* operator->() noexcept { return &host_; }

private:
    Rhp::host<cert_cfg> host_;
    std::jthread pump_;
};

[[nodiscard]] Rhp::client_options claims(std::string app, std::string env = {}, std::string audience = {}) {
    Rhp::client_options o;
    o.app = std::move(app);
    o.env = std::move(env);
    o.audience = std::move(audience);
    return o;
}

} // namespace stage13_certified_fixtures

using namespace stage13_certified_fixtures;

TEST_CASE("stage13: a certified client runs signed code and the audit names the certificate", "[stage13][certified]") {
    pki k;
    const auto at = Rhp::endpoint::listen("s13c.runs", 1);
    running_host host{at, k, {.app = "game", .host_id = "host-1"}};
    std::string signer;
    auto audit = host->on<Rhp::event::script_executed>([&](const Rhp::event::script_executed& e) { signer = e.signer; });
    Rhp::client<cert_cfg> c{at.reversed(), k.as("patch"), k.key(), claims("game", Rhp::kBuildHardening == hardening::kProduction ? "prod" : "dev", "host-1")};
    CHECK(c.exec<int>("return 40 + 2") == 42);
    CHECK(c.load("mod", "return {}"));
    // Each exec carries a fresh nonce: the same source runs again.
    CHECK(c.exec<int>("return 40 + 2") == 42);
    CHECK(signer == "alice#9");
}

TEST_CASE("stage13: certified claims for another app or host are refused", "[stage13][certified]") {
    pki k;
    const auto at = Rhp::endpoint::listen("s13c.claims", 1);
    running_host host{at, k, {.app = "game", .host_id = "host-1"}};
    Rhp::client<cert_cfg> editor{at.reversed(), k.as("patch"), k.key(), claims("editor")};
    CHECK(editor.exec("return 1").error().code == errc::kOutOfScope);
    Rhp::client<cert_cfg> elsewhere{at.reversed(), k.as("patch"), k.key(), claims("game", "", "host-2")};
    CHECK(elsewhere.exec("return 1").error().code == errc::kOutOfScope);
    // The host's environment comes from its hardening: "prod" at production, "dev" below.
    const std::string other_env = Rhp::kBuildHardening == hardening::kProduction ? "dev" : "prod";
    Rhp::client<cert_cfg> wrong_env{at.reversed(), k.as("patch"), k.key(), claims("game", other_env)};
    CHECK(wrong_env.exec("return 1").error().code == errc::kOutOfScope);
}

TEST_CASE("stage13: a certificate's max_role below the session's is refused", "[stage13][certified]") {
    pki k;
    const auto at = Rhp::endpoint::listen("s13c.max_role", 1);
    running_host host{at, k, {.app = "game"}};
    Rhp::client<cert_cfg> admin{at.reversed(), k.as("admin"), k.key(Rhp::role::kPatch), claims("game")};
    CHECK(admin.exec("return 1").error().code == errc::kForbidden);
    Rhp::client<cert_cfg> allowed{at.reversed(), k.as("admin"), k.key(Rhp::role::kAdmin), claims("game")};
    CHECK(allowed.exec<int>("return 1") == 1);
}

TEST_CASE("stage13: a production host refuses dev-tagged CAs and certificates", "[stage13][certified]") {
    pki k;
    {
        const auto at = Rhp::endpoint::listen("s13c.production_dev_ca", 1);
        running_host host{at, k, {.hardening = hardening::kProduction, .app = "game"}, "dev"};
        Rhp::client<cert_cfg> c{at.reversed(), k.as("patch"), k.key(), claims("game")};
        CHECK(c.exec("return 1").error().code == errc::kForbidden);
    }
    const auto at = Rhp::endpoint::listen("s13c.production", 1);
    running_host host{at, k, {.hardening = hardening::kProduction, .app = "game"}, "prod"};
    Rhp::client<cert_cfg> dev_cert{at.reversed(), k.as("patch"), k.key(Rhp::role::kPatch, {"dev"}), claims("game")};
    CHECK(dev_cert.exec("return 1").error().code == errc::kForbidden);
    // A production host's environment is "prod".
    Rhp::client<cert_cfg> prod{at.reversed(), k.as("patch"), k.key(Rhp::role::kPatch, {"prod"}), claims("game", "prod")};
    CHECK(prod.exec<int>("return 1") == 1);
}
