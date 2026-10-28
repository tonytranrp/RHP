// Stage 13a hardening over the wire (decisions AL1, AL2, AL4, AL7): what each level refuses, the
// limits it caps. host_options::hardening raises a host's level in any build, so
// the refusals of lan and production are checked everywhere; what a build leaves out is checked in
// that build.
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/hardening.hpp>

#include <rhp/build_config.hpp>
#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/security/signer.hpp>
#include <rhp/wire/messages.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::hardening;

namespace stage13_hardening_fixtures {

using loop_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;
// A client config at hardening lan, or the build's level when that is stricter.
using lan_client_cfg = tcp_cfg::hardening<Rhp::strictest(hardening::kLan, Rhp::kBuildHardening)>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::key observe = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin}, {"patch", patch, Rhp::role::kPatch}, {"watcher", observe, Rhp::role::kObserve}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
    [[nodiscard]] Rhp::security::psk_identity as(std::string_view who) const {
        if (who == "admin") {
            return {"admin", admin};
        }
        if (who == "patch") {
            return {"patch", patch};
        }
        return {"watcher", observe};
    }
};

// A host pumped by its own thread.
template <class Cfg>
class running_host {
public:
    running_host(Rhp::endpoint ep, const keys& k, Rhp::host_options options = {}) : host_(std::move(ep), k.ring(), k.trusted(), std::move(options)) {
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

    Rhp::host<Cfg>* operator->() noexcept { return &host_; }

private:
    Rhp::host<Cfg> host_;
    std::jthread pump_;
};

[[nodiscard]] bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

[[nodiscard]] Rhp::wire::debug_request paused() {
    Rhp::wire::debug_request r;
    r.action = "paused";
    return r;
}

} // namespace stage13_hardening_fixtures

using namespace stage13_hardening_fixtures;

// ---- lan ----------------------------------------------------------------------------------------------

TEST_CASE("stage13: hardening lan refuses insecure_lan endpoints", "[stage13][hardening]") {
    keys k;
    const Rhp::host_options lan{.hardening = hardening::kLan};
    {
        Rhp::host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::insecure_lan), k.ring(), k.trusted(), lan};
        const auto port = host.port();
        REQUIRE_FALSE(port);
        CHECK(port.error().code == errc::kForbidden);
        CHECK(contains(port.error().message, "insecure_lan"));
    }
    {
        Rhp::host_options gateway = lan;
        gateway.gateway = Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::insecure_lan);
        Rhp::host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), gateway};
        CHECK(host.port()); // the native listener is fine
        CHECK(host.gateway_port().error().code == errc::kForbidden);
    }
    // A client's config is the same ceiling: hardening lan (or the build's) refuses insecure_lan.
    Rhp::client<lan_client_cfg> c{Rhp::endpoint::dial("192.168.1.10", 7777, Rhp::net::insecure_lan), k.as("patch"), k.signer()};
    const auto refused = c.connect();
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::kForbidden);
    CHECK(contains(refused.error().message, "insecure_lan"));
}

TEST_CASE("stage13: hardening lan gives admin patch's libraries and caps observe", "[stage13][hardening]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s13h.lan", 1);
    running_host<loop_cfg> host{at, k, {.hardening = hardening::kLan}};
    Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.signer()};
    CHECK(admin.exec<bool>("return io == nil and debug == nil and package == nil and collectgarbage == nil and os.execute == nil") == true);
    CHECK(admin.exec("setmetatable({}, {__gc = print})").error().code == errc::kForbidden);

    // No limits in the config: observe runs under kObserveCaps all the same.
    Rhp::client<loop_cfg> watcher{at.reversed(), k.as("watcher"), k.signer()};
    const auto stopped = watcher.exec("while true do end");
    REQUIRE_FALSE(stopped);
    CHECK((stopped.error().code == errc::kBudgetExceeded || stopped.error().code == errc::kTimeout));
    CHECK(watcher.exec<int>("return 6 * 7") == 42);

    // kObserveCaps' request rate: a burst past it is refused; admin's requests aren't rated.
    int refused = 0;
    for (int i = 0; i < 2 * static_cast<int>(Rhp::kObserveCaps.request_rate); ++i) {
        const auto r = watcher.exec("return 1");
        refused += !r && r.error().code == errc::kLimitExceeded ? 1 : 0;
    }
    CHECK(refused > 0);
    for (int i = 0; i < 2 * static_cast<int>(Rhp::kObserveCaps.request_rate); ++i) {
        CHECK(admin.exec("return 1"));
    }
}

TEST_CASE("stage13: observe identities have limits of their own", "[stage13][hardening]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s13h.observe_limits", 1);
    running_host<loop_cfg> host{at, k, {.observe_limits = Rhp::limits{.instructions = 50'000}}};
    Rhp::client<loop_cfg> watcher{at.reversed(), k.as("watcher"), k.signer()};
    CHECK(watcher.exec("for i = 1, 1e6 do end").error().code == errc::kBudgetExceeded);
    Rhp::client<loop_cfg> patch{at.reversed(), k.as("patch"), k.signer()};
    CHECK(patch.exec("for i = 1, 1e6 do end")); // the config's limits: none
}

// ---- production ---------------------------------------------------------------------------------------

TEST_CASE("stage13: hardening production refuses unsigned observe code and the debugger", "[stage13][hardening]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s13h.production", 1);
    running_host<loop_cfg> host{at, k, {.hardening = hardening::kProduction}};
    Rhp::client<loop_cfg> unsigned_watcher{at.reversed(), k.as("watcher")};
    CHECK(unsigned_watcher.exec("return 1").error().code == errc::kBadSignature);
    Rhp::client<loop_cfg> watcher{at.reversed(), k.as("watcher"), k.signer()};
    CHECK(watcher.exec<int>("return 1") == 1);

    Rhp::client<loop_cfg> patch{at.reversed(), k.as("patch"), k.signer()};
    CHECK(patch.debug(paused()).error().code == errc::kForbidden);

    Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.signer()};
    CHECK(admin.exec<bool>("return io == nil and debug == nil") == true);
}

TEST_CASE("stage13: hardening production caps every role's limits", "[stage13][hardening]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s13h.production_caps", 1);
    running_host<loop_cfg> host{at, k, {.hardening = hardening::kProduction}};
    // No limits in the config: patch is stopped by kProductionCaps' wall time.
    Rhp::client<loop_cfg> patch{at.reversed(), k.as("patch"), k.signer()};
    const auto started = std::chrono::steady_clock::now();
    const auto stopped = patch.exec("while true do end");
    REQUIRE_FALSE(stopped);
    CHECK(stopped.error().code == errc::kTimeout);
    CHECK(std::chrono::steady_clock::now() - started >= std::chrono::milliseconds{Rhp::kProductionCaps.wall_ms});
}

TEST_CASE("stage13: hardening production refuses advertising and an unbound gateway", "[stage13][hardening]") {
    keys k;
    Rhp::host_options unbound{.hardening = hardening::kProduction};
    unbound.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    Rhp::host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), unbound};
    REQUIRE(host.port());
    const auto gateway = host.gateway_port();
    REQUIRE_FALSE(gateway);
    CHECK(gateway.error().code == errc::kForbidden);
    CHECK(contains(gateway.error().message, "http_require_binding"));
    CHECK(host.advertise().error().code == errc::kForbidden);

    Rhp::host_options bound = unbound;
    bound.http_require_binding = true;
    Rhp::host<tcp_cfg> binding{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), bound};
    CHECK(binding.gateway_port());
}

// ---- signing ------------------------------------------------------------------------------------------

TEST_CASE("stage13: unsigned_scripts doesn't start above hardening dev", "[stage13][hardening]") {
    rhp_test::needs(hardening::kDev, "a host with signer<unsigned_scripts>");
#if RHP_HARDENING == 0 // a lan or production build refuses the config at compile time (Rhp::host_configuration)
    keys k;
    using open_cfg = loop_cfg::signer<Rhp::security::unsigned_scripts>;
    Rhp::host<open_cfg> host{Rhp::endpoint::listen("s13h.unsigned", 1), k.ring(), {.hardening = hardening::kLan}};
    const auto port = host.port();
    REQUIRE_FALSE(port);
    CHECK(port.error().code == errc::kForbidden);
    CHECK(contains(port.error().message, "unsigned_scripts"));
#endif
}
