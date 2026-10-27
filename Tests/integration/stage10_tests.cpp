#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "../unit/release/release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/client/fleet.hpp>
#include <rhp/client/rollout.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/release.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/wire/ops.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp_test/eventually.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using namespace release_test;

namespace stage10_fixtures {

// Written by the release channels' scripts, read by the tests through an exec (both on the pump
// thread: the var's layers keep reloads and reverts in order).
inline int g_speed = 1;

using game_lib = Rhp::lib<"s10">::var<"speed", &g_speed>;

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin}, {"patch", patch, Rhp::role::kPatch}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
};

// A host pumped on its own thread, serving a release manager when given one.
class running_host {
public:
    running_host(Rhp::endpoint ep, const keys& k, Rhp::release::manager* releases) : host_(std::move(ep), k.ring(), k.trusted()) {
        REQUIRE(host_.install<game_lib>());
        if (releases != nullptr) {
            REQUIRE(host_.serve(*releases));
            REQUIRE_FALSE(host_.serve(*releases)); // one manager per host
        }
        sub_ = host_.on<Rhp::event::release_changed>([this](const Rhp::event::release_changed& e) {
            const std::scoped_lock lock{mutex_};
            events_.push_back(e.kind + ":" + e.channel);
        });
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

    std::vector<std::string> events() {
        const std::scoped_lock lock{mutex_};
        return events_;
    }

private:
    Rhp::host<cfg> host_;
    Rhp::event::subscription sub_;
    std::mutex mutex_;
    std::vector<std::string> events_;
    std::jthread pump_;
};

using rhp_test::eventually;

Rhp::release::manager make_manager(const signer& dev, Rhp::release::memory_store store) {
    Rhp::release::manager_options o;
    o.app = "s10game";
    o.health_window = 50ms;
    Rhp::release::manager m{trust_of({{&dev, {"game.*"}}}), o, std::move(store)};
    REQUIRE(m.install<game_lib>());
    REQUIRE(m.restore());
    return m;
}

std::vector<std::byte> speed_release(const signer& dev, std::uint64_t seq, int speed) {
    const std::string source = "s10.speed = " + std::to_string(speed);
    auto man = manifest_for("game.balance", seq, {{"tuning", source}});
    man.app = "s10game";
    return envelope(man, {{"tuning", source}}, {&dev});
}

int speed_of(Rhp::client<cfg>& c) {
    const auto v = c.exec<int>("return s10.speed");
    REQUIRE(v.has_value());
    return *v;
}

// A TCP host serving its own release manager (fleets dial addresses and ports).
using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;

class fleet_host {
public:
    fleet_host(std::string name, const keys& k, const signer& dev, bool with_lib) : name_(std::move(name)), releases_(make(dev, with_lib)),
                                                                                     host_(Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted()) {
        REQUIRE(host_.install<game_lib>());
        REQUIRE(host_.serve(releases_));
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~fleet_host() {
        pump_.request_stop();
        if (pump_.joinable()) {
            pump_.join();
        }
    }

    fleet_host(const fleet_host&) = delete;
    fleet_host& operator=(const fleet_host&) = delete;

    [[nodiscard]] Rhp::net::service_record record() {
        Rhp::net::service_record r;
        r.name = name_;
        r.address = "127.0.0.1";
        r.port = *host_.port();
        r.protocol_revision = Rhp::wire::kProtocolRevision;
        return r;
    }

private:
    static Rhp::release::manager make(const signer& dev, bool with_lib) {
        Rhp::release::manager_options o;
        o.app = "s10game";
        o.health_window = 20ms;
        Rhp::release::manager m{trust_of({{&dev, {"game.*"}}}), o};
        if (with_lib) {
            REQUIRE(m.install<game_lib>());
        }
        return m;
    }

    std::string name_;
    Rhp::release::manager releases_;
    Rhp::host<tcp_cfg> host_;
    std::jthread pump_;
};

// A release that needs lib s10 (a host whose manager lacks it refuses it).
std::vector<std::byte> lib_release(const signer& dev, std::uint64_t seq) {
    auto man = manifest_for("game.balance", seq, {{"tuning", "local x = s10.speed"}});
    man.app = "s10game";
    man.libs = {"s10"};
    return envelope(man, {{"tuning", "local x = s10.speed"}}, {&dev});
}

} // namespace stage10_fixtures

using namespace stage10_fixtures;

TEST_CASE("stage10: a client applies a release and reads the host's channels", "[stage10][releases]") {
    g_speed = 1;
    keys k;
    const signer dev{"dev"};
    Rhp::release::memory_store store;
    auto releases = make_manager(dev, store);
    const auto at = Rhp::endpoint::listen("itest.s10.apply", 1);
    running_host host{at, k, &releases};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};

    const auto applied = admin.release_apply(speed_release(dev, 1, 7));
    REQUIRE(applied.has_value());
    CHECK(applied->channel == "game.balance");
    CHECK(applied->running == "active");
    CHECK(applied->signers == std::vector<std::string>{"dev"});
    CHECK(speed_of(admin) == 7);

    const auto status = admin.release_status();
    REQUIRE(status.has_value());
    CHECK(status->app == "s10game");
    REQUIRE(status->channels.size() == 1);
    CHECK(status->channels[0].active->seq == 1);
    CHECK(status->channels[0].modules == std::vector<std::string>{"tuning"});
    CHECK(eventually([&] { return !host.events().empty() && host.events().back() == "applied:game.balance"; }));
}

TEST_CASE("stage10: release refusals reach the client with their codes", "[stage10][releases]") {
    g_speed = 1;
    keys k;
    const signer dev{"dev"};
    const signer stranger{"stranger"};
    auto releases = make_manager(dev, {});
    const auto at = Rhp::endpoint::listen("itest.s10.refused", 1);
    running_host host{at, k, &releases};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    Rhp::client<cfg> patcher{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};

    CHECK(patcher.release_apply(speed_release(dev, 1, 7)).error().code == errc::kForbidden); // admin only
    CHECK(admin.release_apply(speed_release(stranger, 1, 7)).error().code == errc::kBadSignature);
    REQUIRE(admin.release_apply(speed_release(dev, 2, 7)));
    CHECK(admin.release_apply(speed_release(dev, 1, 9)).error().code == errc::kSuperseded);
    CHECK(admin.release_apply(speed_release(dev, 3, 9), "sometimes").error().code == errc::kInvalidArgument);
    const std::vector<std::byte> junk{std::byte{1}, std::byte{2}};
    CHECK(admin.release_apply(junk).error().code == errc::kProtocol);
    CHECK(patcher.release_status()); // observe may read
    CHECK(speed_of(admin) == 7);
}

TEST_CASE("stage10: a manual candidate is confirmed or deactivated remotely", "[stage10][releases]") {
    g_speed = 1;
    keys k;
    const signer dev{"dev"};
    auto releases = make_manager(dev, {});
    const auto at = Rhp::endpoint::listen("itest.s10.confirm", 1);
    running_host host{at, k, &releases};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    REQUIRE(admin.release_apply(speed_release(dev, 1, 2)));
    const auto cand = admin.release_apply(speed_release(dev, 2, 5), "manual");
    REQUIRE(cand.has_value());
    CHECK(cand->running == "candidate");
    CHECK(speed_of(admin) == 5);
    REQUIRE(admin.release_deactivate("game.balance"));
    CHECK(speed_of(admin) == 2);
    REQUIRE(admin.release_apply(speed_release(dev, 3, 6), "manual"));
    REQUIRE(admin.release_confirm("game.balance"));
    const auto status = admin.release_status();
    REQUIRE(status.has_value());
    CHECK(status->channels[0].running == "active");
    CHECK(status->channels[0].active->seq == 3);
    CHECK(admin.release_confirm("game.balance").error().code == errc::kNotFound);
    const std::vector<std::byte> short_id(3);
    CHECK(admin.release_deactivate("game.balance", false, short_id).error().code == errc::kInvalidArgument);
    REQUIRE(admin.release_deactivate("game.balance", true));
    CHECK(speed_of(admin) == 1);
}

TEST_CASE("stage10: a health-watched candidate confirms itself on the host", "[stage10][releases]") {
    g_speed = 1;
    keys k;
    const signer dev{"dev"};
    auto releases = make_manager(dev, {});
    const auto at = Rhp::endpoint::listen("itest.s10.health", 1);
    running_host host{at, k, &releases};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    REQUIRE(admin.release_apply(speed_release(dev, 1, 4), "health"));
    CHECK(eventually([&] {
        const auto s = admin.release_status();
        return s && !s->channels.empty() && s->channels[0].running == "active";
    }));
    CHECK(eventually([&] { return !host.events().empty() && host.events().back() == "confirmed:game.balance"; }));
}

TEST_CASE("stage10: a revocation list sent by any identity stops the revoked release", "[stage10][releases]") {
    g_speed = 1;
    keys k;
    const signer dev{"dev"};
    const signer ops{"ops"};
    Rhp::release::manager_options o;
    o.app = "s10game";
    Rhp::release::manager releases{trust_of({{&dev, {"game.*"}}, {&ops, {"*"}}}), o};
    REQUIRE(releases.install<game_lib>());
    const auto at = Rhp::endpoint::listen("itest.s10.revoke", 1);
    running_host host{at, k, &releases};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    Rhp::client<cfg> patcher{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    const auto bytes = speed_release(dev, 1, 8);
    REQUIRE(admin.release_apply(bytes));
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.releases = {id_of(bytes)};
    const auto changed = patcher.revoke(revocations(list, {&ops}));
    REQUIRE(changed.has_value());
    CHECK(*changed == 1);
    CHECK(speed_of(admin) == 1);
    CHECK(patcher.revoke(revocations(list, {&dev})).error().code == errc::kSuperseded); // seq 1 again
    Rhp::release::revocation_list newer = list;
    newer.seq = 2;
    CHECK(patcher.revoke(revocations(newer, {&dev})).error().code == errc::kBadSignature); // dev may only sign game.*
}

TEST_CASE("stage10: a host without a release manager says so", "[stage10][releases]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s10.none", 1);
    running_host host{at, k, nullptr};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    CHECK(admin.release_status().error().code == errc::kNotFound);
}

TEST_CASE("stage10: what a host ran comes back after it restarts", "[stage10][releases]") {
    g_speed = 1;
    keys k;
    const signer dev{"dev"};
    Rhp::release::memory_store store;
    {
        auto releases = make_manager(dev, store);
        const auto at = Rhp::endpoint::listen("itest.s10.restart1", 1);
        running_host host{at, k, &releases};
        Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
        REQUIRE(admin.release_apply(speed_release(dev, 5, 3)));
        CHECK(speed_of(admin) == 3);
    }
    CHECK(g_speed == 1); // no host runs: nothing else touches it
    auto releases = make_manager(dev, store); // restore() runs inside
    CHECK(g_speed == 3);
    const auto at = Rhp::endpoint::listen("itest.s10.restart2", 1);
    running_host host{at, k, &releases};
    Rhp::client<cfg> admin{at.reversed(), Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    const auto status = admin.release_status();
    REQUIRE(status.has_value());
    CHECK(status->channels[0].active->seq == 5);
}

TEST_CASE("stage10: a rollout spreads a release over a fleet stage by stage", "[stage10][rollout]") {
    keys k;
    const signer dev{"dev"};
    fleet_host a{"a", k, dev, true};
    fleet_host b{"b", k, dev, true};
    fleet_host c{"c", k, dev, true};
    Rhp::fleet<tcp_cfg> group{Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    for (auto* h : {&a, &b, &c}) {
        REQUIRE(group.add(h->record()));
    }
    Rhp::rollout_plan plan;
    plan.canaries = {"b"};
    plan.stages = {{0.5, 50ms}, {1.0, 0ms}};
    plan.poll = 10ms;
    std::vector<std::string> lines;
    plan.on_progress = [&](std::string_view line) { lines.emplace_back(line); };
    const auto report = group.rollout(lib_release(dev, 1), plan);
    const std::string why = report.err ? report.err->message : std::string{"ok"};
    INFO(why);
    CHECK(report.completed);
    CHECK(report.stages_done == 3); // canary, half, the rest
    REQUIRE(report.hosts.size() == 3);
    for (const auto& h : report.hosts) {
        CHECK(h.status == Rhp::rollout_host::state::kConfirmed);
    }
    for (const auto& s : group.release_status()) {
        REQUIRE(s.outcome.has_value());
        REQUIRE(s.outcome->channels.size() == 1);
        CHECK(s.outcome->channels[0].running == "active");
    }
    // The same release again: everyone already runs it.
    const auto again = group.rollout(lib_release(dev, 1), plan);
    CHECK(again.completed);
    for (const auto& h : again.hosts) {
        CHECK(h.status == Rhp::rollout_host::state::kAlready);
    }
}

TEST_CASE("stage10: a rerun that stops leaves hosts that already ran the release alone", "[stage10][rollout]") {
    keys k;
    const signer dev{"dev"};
    fleet_host a{"a", k, dev, true};
    fleet_host b{"b", k, dev, true};
    Rhp::fleet<tcp_cfg> group{Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    REQUIRE(group.add(a.record()));
    REQUIRE(group.add(b.record()));
    Rhp::rollout_plan plan;
    plan.stages = {{1.0, 20ms}};
    plan.poll = 10ms;
    REQUIRE(group.rollout(lib_release(dev, 1), plan).completed);
    fleet_host c{"c", k, dev, false}; // joins without the lib: it refuses the release
    REQUIRE(group.add(c.record()));
    const auto rerun = group.rollout(lib_release(dev, 1), plan);
    CHECK_FALSE(rerun.completed);
    for (const auto& s : group.release_status()) {
        REQUIRE(s.outcome.has_value());
        if (s.host.name != "c") {
            REQUIRE(s.outcome->channels.size() == 1);
            CHECK(s.outcome->channels[0].running == "active");
        }
    }
}

TEST_CASE("stage10: a failing canary stops the rollout and nothing is left running", "[stage10][rollout]") {
    keys k;
    const signer dev{"dev"};
    fleet_host good1{"good1", k, dev, true};
    fleet_host bad{"bad", k, dev, false}; // its manager lacks lib s10: it refuses the release
    fleet_host good2{"good2", k, dev, true};
    Rhp::fleet<tcp_cfg> group{Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    for (auto* h : {&good1, &bad, &good2}) {
        REQUIRE(group.add(h->record()));
    }
    Rhp::rollout_plan plan;
    plan.canaries = {"good1", "bad"};
    plan.stages = {{1.0, 20ms}};
    plan.poll = 10ms;
    const auto report = group.rollout(lib_release(dev, 1), plan);
    CHECK_FALSE(report.completed);
    CHECK(report.stages_done == 0);
    REQUIRE(report.err.has_value());
    for (const auto& h : report.hosts) {
        if (h.host.name == "bad") {
            CHECK(h.status == Rhp::rollout_host::state::kFailed);
            REQUIRE(h.err.has_value());
            CHECK(h.err->code == errc::kNotFound);
        } else if (h.host.name == "good1") {
            CHECK(h.status == Rhp::rollout_host::state::kRolledBack);
        } else {
            CHECK(h.status == Rhp::rollout_host::state::kPending); // never reached
        }
    }
    for (const auto& s : group.release_status()) {
        REQUIRE(s.outcome.has_value());
        for (const auto& ch : s.outcome->channels) {
            CHECK(ch.running == "empty");
        }
    }
    // The same release again: good1 rolled it back, so it fails there instead of counting as skipped.
    plan.max_failures = 1;
    const auto rerun = group.rollout(lib_release(dev, 1), plan);
    CHECK_FALSE(rerun.completed);
    for (const auto& h : rerun.hosts) {
        if (h.host.name == "good1") {
            CHECK(h.status == Rhp::rollout_host::state::kFailed);
            REQUIRE(h.err.has_value());
            CHECK(h.err->code == errc::kSuperseded);
        }
    }
    // Allowed to fail once: the rollout goes through the others.
    const auto tolerant = group.rollout(lib_release(dev, 2), plan);
    CHECK(tolerant.completed);
}

TEST_CASE("stage10: a rollout refuses what isn't a release envelope", "[stage10][rollout]") {
    keys k;
    const signer dev{"dev"};
    fleet_host a{"a", k, dev, true};
    Rhp::fleet<tcp_cfg> group{Rhp::security::psk_identity{"admin", k.admin}, k.signer()};
    REQUIRE(group.add(a.record()));
    const std::vector<std::byte> junk{std::byte{0x90}};
    const auto report = group.rollout(junk);
    CHECK_FALSE(report.completed);
    REQUIRE(report.err.has_value());
    CHECK(report.err->code == errc::kProtocol);
    // Plans that can't mean anything are refused before any host is touched.
    Rhp::rollout_plan unknown;
    unknown.canaries = {"nobody"};
    CHECK(group.rollout(lib_release(dev, 1), unknown).err->code == errc::kNotFound);
    Rhp::rollout_plan nan;
    nan.stages = {{std::numeric_limits<double>::quiet_NaN(), 0ms}};
    CHECK(group.rollout(lib_release(dev, 1), nan).err->code == errc::kInvalidArgument);
    for (const auto& s : group.release_status()) {
        REQUIRE(s.outcome.has_value());
        CHECK(s.outcome->channels.empty());
    }
}
