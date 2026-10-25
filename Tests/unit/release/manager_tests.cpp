#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/store.hpp>
#include <rhp/release/trust.hpp>
#include <rhp/script/lib.hpp>

using Rhp::errc;
using Rhp::release::confirm_mode;
using Rhp::release::slot;
using namespace release_test;

namespace release_manager_fixture {

inline int g_speed = 1;
inline std::vector<int> g_spawned;

inline void spawn(int id) {
    g_spawned.push_back(id);
}
inline void despawn(int id) {
    std::erase(g_spawned, id);
}

using game_lib = Rhp::lib<"game">::var<"speed", &g_speed>::fn<"spawn", &spawn, Rhp::undo<&despawn>>;

} // namespace release_manager_fixture

namespace {

namespace fx = release_manager_fixture;

struct fake_clocks {
    std::chrono::steady_clock::time_point steady = std::chrono::steady_clock::time_point{} + std::chrono::hours{1};
    std::chrono::system_clock::time_point wall = std::chrono::system_clock::time_point{} + std::chrono::seconds{1'760'000'000};
};

struct fixture {
    signer dev{"dev"};
    std::shared_ptr<fake_clocks> clocks = std::make_shared<fake_clocks>();
    Rhp::release::memory_store store;

    fixture() {
        fx::g_speed = 1;
        fx::g_spawned.clear();
    }

    [[nodiscard]] Rhp::release::manager_options options(std::string app = "mygame") const {
        Rhp::release::manager_options o;
        o.app = std::move(app);
        o.build = "1.0";
        o.clock = [c = clocks] { return c->steady; };
        o.wall_clock = [c = clocks] { return c->wall; };
        o.health_window = std::chrono::milliseconds{1000};
        o.output = [](std::string_view, std::string_view) {};
        return o;
    }

    [[nodiscard]] Rhp::release::manager make(Rhp::release::manager_options o) const {
        Rhp::release::manager m{trust_of({{&dev, {"*"}}}), std::move(o), store};
        REQUIRE(m.install<fx::game_lib>());
        return m;
    }

    [[nodiscard]] Rhp::release::manager make() const { return make(options()); }

    [[nodiscard]] std::vector<std::byte> speed_release(std::uint64_t seq, int speed, std::string channel = "game.balance") const {
        return envelope(std::move(channel), seq, {{"tuning", "game.speed = " + std::to_string(speed)}}, dev);
    }
};

const Rhp::release::channel_status* status_of(const std::vector<Rhp::release::channel_status>& all, std::string_view channel) {
    for (const auto& s : all) {
        if (s.channel == channel) {
            return &s;
        }
    }
    return nullptr;
}

} // namespace

TEST_CASE("release manager runs an applied release and swaps in the next one", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.restore());
    const auto first = m.apply(f.speed_release(1, 5));
    REQUIRE(first.has_value());
    CHECK(first->running == slot::kActive);
    CHECK(fx::g_speed == 5);
    const auto second = m.apply(f.speed_release(2, 9));
    REQUIRE(second.has_value());
    CHECK(second->replaced == first->id);
    CHECK(fx::g_speed == 9);
    const auto st = m.status();
    const auto* s = status_of(st, "game.balance");
    REQUIRE(s != nullptr);
    CHECK(s->active->seq == 2);
    CHECK(s->previous == first->id);
    CHECK(s->floor == 2);
    CHECK(s->modules == std::vector<std::string>{"tuning"});
}

TEST_CASE("release manager refuses an old seq and accepts the same release again as a no-op", "[release][manager]") {
    fixture f;
    auto m = f.make();
    const auto r2 = f.speed_release(2, 5);
    REQUIRE(m.apply(r2));
    const auto again = m.apply(r2);
    REQUIRE(again.has_value());
    CHECK(again->already);
    CHECK(m.apply(f.speed_release(1, 7)).error().code == errc::kSuperseded);
    CHECK(m.apply(f.speed_release(2, 7)).error().code == errc::kSuperseded); // same seq, other body
    CHECK(fx::g_speed == 5);
}

TEST_CASE("release manager refuses releases out of scope, expired, too privileged or missing libs", "[release][manager]") {
    fixture f;
    auto m = f.make();
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.app = "othergame";
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kOutOfScope);
    }
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.builds = {"2.0"};
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kOutOfScope);
    }
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.platforms = {"not-this-os"};
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kOutOfScope);
    }
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.not_after = 1'700'000'000; // before the fake wall clock
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kExpired);
    }
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.not_before = 1'900'000'000;
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kExpired);
    }
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.run_as = Rhp::role::kAdmin;
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kForbidden);
    }
    {
        auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
        man.libs = {"ui"};
        CHECK(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})).error().code == errc::kNotFound);
    }
    {
        const signer stranger{"stranger"};
        CHECK(m.apply(envelope("game.balance", 1, {{"a", "game.speed = 2"}}, stranger)).error().code == errc::kBadSignature);
    }
    CHECK(fx::g_speed == 1);
    CHECK(m.status().empty());
}

TEST_CASE("a release that fails to load leaves the old one running", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(envelope("game.balance", 1, {{"tuning", "game.speed = 3"}, {"spawns", "game.spawn(1)"}}, f.dev)));
    CHECK(fx::g_speed == 3);
    CHECK(fx::g_spawned == std::vector<int>{1});
    const auto broken = m.apply(envelope("game.balance", 2, {{"tuning", "game.speed = 4"}, {"spawns", "error('boom')"}}, f.dev));
    REQUIRE_FALSE(broken.has_value());
    CHECK(fx::g_speed == 3);                     // the reloaded module was rolled back
    CHECK(fx::g_spawned == std::vector<int>{1}); // the old spawns module still runs
    CHECK(status_of(m.status(), "game.balance")->active->seq == 1);
    // The failed seq was never accepted: a fixed release with the same seq is welcome.
    REQUIRE(m.apply(envelope("game.balance", 2, {{"tuning", "game.speed = 4"}, {"spawns", "game.spawn(2)"}}, f.dev)));
    CHECK(fx::g_speed == 4);
    CHECK(fx::g_spawned == std::vector<int>{2});
}

TEST_CASE("modules a new release drops are unloaded and their effects undone", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(envelope("game.balance", 1, {{"tuning", "game.speed = 3"}, {"spawns", "game.spawn(7)"}}, f.dev)));
    REQUIRE(m.apply(envelope("game.balance", 2, {{"tuning", "game.speed = 3"}}, f.dev)));
    CHECK(fx::g_spawned.empty());
    CHECK(status_of(m.status(), "game.balance")->modules == std::vector<std::string>{"tuning"});
}

TEST_CASE("a module carries its state across releases through on_save and on_restore", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(envelope("game.balance", 1, {{"counter", "count = 41 function on_save() return count end"}}, f.dev)));
    REQUIRE(m.apply(envelope("game.balance", 2, {{"counter", "count = 0 function on_restore(s) count = s + 1 end function get() return count end"}}, f.dev)));
    auto* box = m.sandbox("game.balance");
    REQUIRE(box != nullptr);
    const auto mod = box->find("counter");
    REQUIRE(mod.has_value());
    CHECK(*box->call(*mod, "get") == Rhp::value_list{Rhp::value{42}});
}

TEST_CASE("a manual candidate waits for confirm and rolls back on deactivate", "[release][manager]") {
    fixture f;
    auto m = f.make();
    const auto first = m.apply(f.speed_release(1, 2));
    REQUIRE(first);
    const auto cand = m.apply(f.speed_release(2, 8), confirm_mode::kManual);
    REQUIRE(cand.has_value());
    CHECK(cand->running == slot::kCandidate);
    CHECK(fx::g_speed == 8);
    auto s = *status_of(m.status(), "game.balance");
    CHECK(s.active->id == first->id);
    CHECK(s.candidate->id == cand->id);
    REQUIRE(m.deactivate("game.balance"));
    CHECK(fx::g_speed == 2);
    s = *status_of(m.status(), "game.balance");
    CHECK(s.running == slot::kActive);
    CHECK_FALSE(s.candidate.has_value());
    CHECK(s.floor == 2); // the floor doesn't go back down

    const auto third = m.apply(f.speed_release(3, 6), confirm_mode::kManual);
    REQUIRE(third);
    REQUIRE(m.confirm("game.balance"));
    s = *status_of(m.status(), "game.balance");
    CHECK(s.active->id == third->id);
    CHECK(s.previous == first->id);
    CHECK(m.confirm("game.balance").error().code == errc::kNotFound);
}

TEST_CASE("a health-watched candidate is confirmed after a quiet window", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    REQUIRE(m.apply(f.speed_release(2, 8), confirm_mode::kHealth));
    m.pump();
    CHECK(status_of(m.status(), "game.balance")->running == slot::kCandidate);
    f.clocks->steady += std::chrono::milliseconds{1500};
    m.pump();
    const auto s = *status_of(m.status(), "game.balance");
    CHECK(s.running == slot::kActive);
    CHECK(s.active->seq == 2);
}

TEST_CASE("a candidate whose handlers fail is rolled back", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    std::vector<Rhp::release::release_event> events;
    m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    REQUIRE(m.apply(envelope("game.balance", 2, {{"tuning", "game.speed = 8 rhp.every_frame(function() error('bad frame') end)"}}, f.dev), confirm_mode::kHealth));
    m.pump();
    m.pump();
    CHECK(fx::g_speed == 2);
    const auto s = *status_of(m.status(), "game.balance");
    CHECK(s.active->seq == 1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.back().what == Rhp::release::release_event::kind::kRolledBack);
    CHECK(events.back().reason.find("handler failures") != std::string::npos);
}

TEST_CASE("a candidate that publishes a fail event is rolled back", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    auto man = manifest_for("game.balance", 2, {{"tuning", "game.speed = 8 rhp.after(0, function() rhp.publish('game.desync') end)"}});
    man.health.fail_events = {"game.desync"};
    REQUIRE(m.apply(envelope(man, {{"tuning", "game.speed = 8 rhp.after(0, function() rhp.publish('game.desync') end)"}}, {&f.dev}), confirm_mode::kHealth));
    for (int i = 0; i < 4; ++i) {
        m.pump();
    }
    CHECK(fx::g_speed == 2);
}

TEST_CASE("deactivate with hold leaves the channel empty", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    REQUIRE(m.apply(f.speed_release(2, 3)));
    REQUIRE(m.deactivate("game.balance", true));
    CHECK(fx::g_speed == 1);
    const auto s = *status_of(m.status(), "game.balance");
    CHECK(s.running == slot::kEmpty);
    CHECK(s.held);
    CHECK(m.sandbox("game.balance") == nullptr);
    CHECK(m.deactivate("game.balance").error().code == errc::kNotFound);
}

TEST_CASE("deactivating an active release falls back to the previous one", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    REQUIRE(m.apply(f.speed_release(2, 3)));
    REQUIRE(m.deactivate("game.balance"));
    CHECK(fx::g_speed == 2);
    CHECK(status_of(m.status(), "game.balance")->active->seq == 1);
}

TEST_CASE("a restart brings back the active release from the store", "[release][manager]") {
    fixture f;
    {
        auto m = f.make();
        REQUIRE(m.restore());
        REQUIRE(m.apply(f.speed_release(4, 6)));
        CHECK(fx::g_speed == 6);
    }
    CHECK(fx::g_speed == 1); // the manager's end undid everything
    auto m = f.make();
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->restored == std::vector<std::string>{"game.balance"});
    CHECK(fx::g_speed == 6);
    CHECK(m.apply(f.speed_release(3, 1)).error().code == errc::kSuperseded); // the floor survived too
    CHECK(m.restore().error().code == errc::kAlreadyLoaded);
}

TEST_CASE("a candidate that never gets confirmed is quarantined after its boot attempts", "[release][manager]") {
    fixture f;
    Rhp::release::release_id candidate{};
    {
        auto m = f.make();
        REQUIRE(m.apply(f.speed_release(1, 2)));
        const auto c = m.apply(f.speed_release(2, 9), confirm_mode::kManual);
        REQUIRE(c);
        candidate = c->id;
    }
    for (int boot = 1; boot <= 2; ++boot) { // max_boot_attempts = 2: it runs twice more
        auto m = f.make();
        const auto report = m.restore();
        REQUIRE(report.has_value());
        CHECK(fx::g_speed == 9);
        CHECK(status_of(m.status(), "game.balance")->attempts == static_cast<std::uint32_t>(boot));
    }
    auto m = f.make();
    const auto report = m.restore();
    REQUIRE(report.has_value());
    REQUIRE(report->quarantined.size() == 1);
    CHECK(report->quarantined[0].second == candidate);
    CHECK(fx::g_speed == 2);
    CHECK(m.apply(f.speed_release(2, 9)).error().code == errc::kSuperseded);
}

TEST_CASE("a torn state file is refused instead of trusted", "[release][manager]") {
    fixture f;
    {
        auto m = f.make();
        REQUIRE(m.apply(f.speed_release(1, 2)));
    }
    auto bytes = *f.store.read("state");
    bytes.back() = static_cast<std::byte>(std::to_integer<int>(bytes.back()) ^ 1);
    REQUIRE(f.store.write("state", bytes));
    auto m = f.make();
    CHECK(m.restore().error().code == errc::kIntegrity);
}

TEST_CASE("stored releases nobody names any more are removed", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    REQUIRE(m.apply(f.speed_release(2, 3)));
    REQUIRE(m.apply(f.speed_release(3, 4)));
    const auto keys = *f.store.keys();
    std::size_t releases = 0;
    for (const auto& k : keys) {
        releases += k.starts_with("releases/") ? 1 : 0;
    }
    CHECK(releases == 2); // active and previous
}

TEST_CASE("a revocation list stops a revoked release and raises floors", "[release][manager]") {
    fixture f;
    auto m = f.make();
    const auto first = m.apply(f.speed_release(1, 2));
    const auto second = m.apply(f.speed_release(2, 3));
    REQUIRE(first);
    REQUIRE(second);
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.releases = {second->id};
    list.floors = {{"game.balance", 10}, {"ui.menu", 5}};
    const auto changed = m.revoke(revocations(list, {&f.dev}));
    REQUIRE(changed.has_value());
    CHECK(*changed == 1);
    CHECK(fx::g_speed == 2); // back to the first
    CHECK(status_of(m.status(), "game.balance")->floor == 10);
    CHECK(status_of(m.status(), "ui.menu")->floor == 5);
    CHECK(m.apply(f.speed_release(9, 4)).error().code == errc::kSuperseded);
    CHECK(m.revoke(revocations(list, {&f.dev})).error().code == errc::kSuperseded); // not newer
}

TEST_CASE("revoking the signing key stops what it signed", "[release][manager]") {
    fixture f;
    const signer ops{"ops"};
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}, {&ops, {"*"}}}), f.options(), f.store};
    REQUIRE(m.install<fx::game_lib>());
    REQUIRE(m.apply(f.speed_release(1, 5)));
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.keys = {f.dev.secret.public_key()};
    REQUIRE(m.revoke(revocations(list, {&ops})));
    CHECK(fx::g_speed == 1);
    CHECK(status_of(m.status(), "game.balance")->running == slot::kEmpty);
    CHECK(m.apply(f.speed_release(2, 5)).error().code == errc::kBadSignature);
}

TEST_CASE("a release past not_after stops running", "[release][manager]") {
    fixture f;
    auto m = f.make();
    auto man = manifest_for("game.balance", 1, {{"tuning", "game.speed = 7"}});
    man.not_after = 1'760'000'100;
    REQUIRE(m.apply(envelope(man, {{"tuning", "game.speed = 7"}}, {&f.dev})));
    m.pump();
    CHECK(fx::g_speed == 7);
    f.clocks->wall += std::chrono::seconds{1000}; // past not_after plus the 300 s skew
    m.pump();
    CHECK(fx::g_speed == 1);
}

TEST_CASE("channels are separate sandboxes", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(envelope("game.a", 1, {{"x", "shared = 1 game.spawn(1)"}}, f.dev)));
    REQUIRE(m.apply(envelope("game.b", 1, {{"x", "game.spawn(2) return shared"}}, f.dev)));
    CHECK(fx::g_spawned == std::vector<int>{1, 2});
    REQUIRE(m.deactivate("game.a", true));
    CHECK(fx::g_spawned == std::vector<int>{2});
    CHECK(m.status().size() == 2);
}

TEST_CASE("a release asking to run as admin gets an admin sandbox when allowed", "[release][manager]") {
    fixture f;
    auto o = f.options();
    o.max_role = Rhp::role::kAdmin;
    auto m = f.make(std::move(o));
    auto man = manifest_for("game.balance", 1, {{"tuning", "result = type(io) == 'table'"}});
    man.run_as = Rhp::role::kAdmin;
    REQUIRE(m.apply(envelope(man, {{"tuning", "result = type(io) == 'table'"}}, {&f.dev})));
    auto* box = m.sandbox("game.balance");
    REQUIRE(box != nullptr);
    CHECK(*box->exec("return type(io)") == Rhp::value_list{Rhp::value{"table"}}); // only admin sandboxes have io
}

TEST_CASE("the directory store keeps releases across managers", "[release][store]") {
    const auto dir = std::filesystem::temp_directory_path() / "rhp_release_store_test";
    std::filesystem::remove_all(dir);
    fixture f;
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), Rhp::release::directory_store{dir}};
        REQUIRE(m.install<fx::game_lib>());
        REQUIRE(m.restore());
        REQUIRE(m.apply(f.speed_release(1, 4)));
    }
    CHECK(std::filesystem::exists(dir / "state.rhp"));
    Rhp::release::directory_store store{dir};
    const auto keys = store.keys();
    REQUIRE(keys.has_value());
    CHECK(keys->size() == 2); // releases/<id> and state
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
    REQUIRE(m.install<fx::game_lib>());
    REQUIRE(m.restore());
    CHECK(fx::g_speed == 4);
    std::filesystem::remove_all(dir);
}

TEST_CASE("store keys are checked", "[release][store]") {
    Rhp::release::memory_store store;
    const std::vector<std::byte> bytes{std::byte{1}};
    CHECK(store.write("state", bytes));
    CHECK(store.write("releases/ab12", bytes));
    for (const char* bad : {"", "/abs", "a/../b", "Upper", "end/", "sp ace"}) {
        CHECK(store.write(bad, bytes).error().code == errc::kInvalidArgument);
    }
    CHECK(store.read("missing").error().code == errc::kNotFound);
    CHECK(store.remove("missing"));
}
