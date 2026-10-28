// Stage 13a hardening over the wire (decisions AL1, AL2, AL4, AL7): what each level refuses, the
// limits it caps, and dev sessions. host_options::hardening raises a host's level in any build, so
// the refusals of lan and production are checked everywhere; what a build leaves out is checked in
// that build.
#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/eventually.hpp>
#include <rhp_test/hardening.hpp>

#include <rhp/build_config.hpp>
#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/security/dev_session.hpp>
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

TEST_CASE("stage13: a served release manager runs at the host's hardening level", "[stage13][hardening][release]") {
    keys k;
    Rhp::release::manager releases{Rhp::release::trust{}, {.app = "s13h"}};
    CHECK(releases.options().hardening == Rhp::kBuildHardening);
    Rhp::host<loop_cfg> host{Rhp::endpoint::listen("s13h.releases", 1), k.ring(), k.trusted(), {.hardening = hardening::kLan}};
    REQUIRE(host.serve(releases));
    CHECK(releases.options().hardening == Rhp::strictest(hardening::kLan, Rhp::kBuildHardening));
}

// ---- every level --------------------------------------------------------------------------------------

TEST_CASE("stage13: an identity that keeps pinned modules gets its builtins back when its sessions end", "[stage13][hardening][pin]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s13h.pinned_builtins", 1);
    running_host<loop_cfg> host{at, k};
    {
        Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.signer()};
        REQUIRE(admin.load("s13h.kept", "return {get = function() return string.upper('kept') end}"));
        REQUIRE(admin.pin("s13h.kept"));
        REQUIRE(admin.exec("string.upper = function() return 'changed' end string.extra = 1 table.insert = nil"));
        CHECK(admin.call("s13h.kept", "get") == Rhp::value_list{Rhp::value{"changed"}});
    }
    // When the last session's close is queued for pump(), so is the release: a new session comes after it.
    REQUIRE(rhp_test::eventually([&] { return host->sessions() == 0; }));
    Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.signer()};
    CHECK(admin.exec<bool>("return string.upper('a') == 'A' and string.extra == nil and table.insert ~= nil and ('a'):upper() == 'A'") == true);
    CHECK(admin.call("s13h.kept", "get") == Rhp::value_list{Rhp::value{"KEPT"}}); // the pinned module stays, with builtins as they were made
    REQUIRE(admin.unpin("s13h.kept"));
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

// ---- dev sessions -------------------------------------------------------------------------------------

TEST_CASE("stage13: a dev session writes a connect file a client can use", "[stage13][hardening][dev_session]") {
    rhp_test::needs(hardening::kDev, "dev sessions");
    if (!Rhp::security::dev_session_directory()) {
        SKIP("this platform has no user configuration folder for the connect file");
    }
    const std::string app = "rhp_stage13_dev_session";
    const auto path = Rhp::security::dev_session_path(app);
    REQUIRE(path);
    keys k;
    {
        running_host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0), k, {.dev_session = app}};
        const auto port = host->port();
        REQUIRE(port);
        auto session = Rhp::security::read_dev_session(*path);
        REQUIRE(session);
        CHECK(session->app == app);
        CHECK(session->transport == "tcp");
        CHECK(session->host == "127.0.0.1");
        CHECK(session->port == *port);
        CHECK(session->identity.warnings.empty()); // owner-only, a generated PSK
        const auto signer = session->identity.signer_key();
        REQUIRE(signer);

        // What `rhp-cli connect --dev` does: no key files, a signed exec as admin.
        Rhp::client<tcp_cfg> dev{Rhp::endpoint::dial(session->host, session->port), session->identity.credential(), *signer};
        CHECK(dev.exec<int>("return 6 * 7") == 42);
        CHECK(dev.info().granted == Rhp::role::kAdmin);
        // The host's own keys and signers still work beside it.
        Rhp::client<tcp_cfg> patch{Rhp::endpoint::dial("127.0.0.1", *port), k.as("patch"), k.signer()};
        CHECK(patch.exec<int>("return 1") == 1);
    }
    CHECK_FALSE(std::filesystem::exists(*path)); // gone with the host
}

TEST_CASE("stage13: a dev session listens on loopback or local IPC only", "[stage13][hardening][dev_session]") {
    rhp_test::needs(hardening::kDev, "dev sessions");
    keys k;
    const std::string app = "rhp_stage13_dev_refused";
    const auto refused = [](const auto& host) {
        const auto port = host.port();
        return !port && port.error().code == errc::kForbidden;
    };
    {
        Rhp::host<tcp_cfg> anywhere{Rhp::endpoint::listen("0.0.0.0", 0), k.ring(), k.trusted(), {.dev_session = app}};
        CHECK(refused(anywhere));
    }
    {
        Rhp::host<loop_cfg> in_process{Rhp::endpoint::listen("s13h.dev_loopback", 1), k.ring(), k.trusted(), {.dev_session = app}};
        CHECK(refused(in_process)); // no other process can dial it
    }
    {
        Rhp::host<tcp_cfg> reverse{Rhp::endpoint::dial("127.0.0.1", 9), k.ring(), k.trusted(), {.dev_session = app}};
        CHECK(refused(reverse));
    }
    if (const auto path = Rhp::security::dev_session_path(app)) {
        CHECK_FALSE(std::filesystem::exists(*path));
    }
}

TEST_CASE("stage13: a dev session is refused above hardening dev", "[stage13][hardening][dev_session]") {
    keys k;
    const std::string app = "rhp_stage13_dev_lan";
    Rhp::host<tcp_cfg> lan{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), {.hardening = hardening::kLan, .dev_session = app}};
    const auto port = lan.port();
    REQUIRE_FALSE(port);
    CHECK(port.error().code == errc::kForbidden);
    if constexpr (Rhp::kBuildHardening != hardening::kDev) {
        // Not in the binary at all: the default options are refused the same way.
        CHECK(contains(port.error().message, "compiled out"));
        Rhp::host<tcp_cfg> plain{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), {.dev_session = app}};
        CHECK(plain.port().error().code == errc::kForbidden);
    }
    if (const auto path = Rhp::security::dev_session_path(app)) {
        CHECK_FALSE(std::filesystem::exists(*path));
    }
}
