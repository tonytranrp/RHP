#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>
#include <rhp_test/hardening.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/hardening.hpp>
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

// A storage that can be told to fail: reads of releases, every write, or writes after N state writes
// (a process that died there).
struct faulty_store {
    Rhp::release::memory_store inner;
    std::shared_ptr<int> state_writes_left = std::make_shared<int>(-1); // -1: no limit
    std::shared_ptr<bool> fail_release_reads = std::make_shared<bool>(false);
    std::shared_ptr<bool> fail_writes = std::make_shared<bool>(false);
    std::shared_ptr<bool> fail_state_writes = std::make_shared<bool>(false);

    Rhp::result<std::vector<std::byte>> read(std::string_view key) {
        if (*fail_release_reads && key.starts_with("releases/")) {
            return Rhp::fail(errc::kRuntime, "the file is locked", "test.store");
        }
        return inner.read(key);
    }
    Rhp::result<void> write(std::string_view key, std::span<const std::byte> bytes) {
        if (*fail_writes || *state_writes_left == 0 || (*fail_state_writes && key == "state")) {
            return Rhp::fail(errc::kRuntime, "the disk is full", "test.store");
        }
        if (key == "state" && *state_writes_left > 0) {
            --*state_writes_left;
        }
        return inner.write(key, bytes);
    }
    Rhp::result<void> remove(std::string_view key) {
        if (*fail_writes || *state_writes_left == 0) {
            return Rhp::fail(errc::kRuntime, "the disk is full", "test.store");
        }
        return inner.remove(key);
    }
    Rhp::result<std::vector<std::string>> keys() { return inner.keys(); }
};

std::size_t stored_releases(Rhp::release::memory_store& store) {
    std::size_t n = 0;
    for (const auto& k : *store.keys()) {
        n += k.starts_with("releases/") ? 1 : 0;
    }
    return n;
}

const Rhp::release::channel_status* status_of(const std::vector<Rhp::release::channel_status>& all, std::string_view channel) {
    for (const auto& s : all) {
        if (s.channel == channel) {
            return &s;
        }
    }
    return nullptr;
}

using event_kind = Rhp::release::release_event::kind;

constexpr std::uint64_t kNow = 1'760'000'000;                                 // fake_clocks::wall, in Unix seconds
constexpr std::uint64_t kJump = std::uint64_t{1} << 32;                       // the default max_seq_jump
constexpr std::uint64_t kMaxSeq = (std::numeric_limits<std::int64_t>::max)(); // the largest seq a manifest or list holds

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

TEST_CASE("release manager refuses releases out of scope or expired or too privileged or missing libs", "[release][manager]") {
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

TEST_CASE("a negative clock skew counts as none", "[release][manager]") {
    fixture f;
    auto o = f.options();
    o.clock_skew = std::chrono::seconds{-300};
    auto m = f.make(std::move(o));
    auto man = manifest_for("game.balance", 1, {{"a", "game.speed = 2"}});
    man.not_before = 1'760'000'000 - 100; // valid for 100 s already (the fake wall clock is 1'760'000'000)
    man.not_after = 1'760'000'000 + 100;  // and for 100 s more
    REQUIRE(m.apply(envelope(man, {{"a", "game.speed = 2"}}, {&f.dev})));
    m.pump();
    CHECK(fx::g_speed == 2);
    CHECK(status_of(m.status(), "game.balance")->running == slot::kActive);
    f.clocks->wall += std::chrono::seconds{101};
    m.pump();
    CHECK(fx::g_speed == 1);
    CHECK(status_of(m.status(), "game.balance")->running == slot::kEmpty);
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
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
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

TEST_CASE("a manual candidate is not health watched", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    const std::string source = "game.speed = 8 rhp.after(0, function() rhp.publish('game.desync') end) rhp.every_frame(function() error('bad frame') end)";
    auto man = manifest_for("game.balance", 2, {{"tuning", source}});
    man.health.fail_events = {"game.desync"};
    const auto cand = m.apply(envelope(man, {{"tuning", source}}, {&f.dev}), confirm_mode::kManual);
    REQUIRE(cand.has_value());
    for (int i = 0; i < 4; ++i) {
        m.pump();
    }
    f.clocks->steady += std::chrono::milliseconds{1500}; // past health_window
    m.pump();
    auto s = *status_of(m.status(), "game.balance");
    CHECK(s.running == slot::kCandidate); // neither rolled back nor confirmed by the health watch
    CHECK(s.handler_failures == 0);
    CHECK(fx::g_speed == 8);
    REQUIRE(m.confirm("game.balance", cand->id));
    s = *status_of(m.status(), "game.balance");
    CHECK(s.running == slot::kActive);
    CHECK(s.active->seq == 2);
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
    CHECK(m.apply(f.speed_release(2, 9)).error().code == errc::kRevoked); // quarantined here
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
    list.floors = {{"ui.menu", 5}};
    const auto changed = m.revoke(revocations(list, {&f.dev}));
    REQUIRE(changed.has_value());
    CHECK(*changed == 1);
    CHECK(fx::g_speed == 2); // back to the first
    CHECK(status_of(m.status(), "ui.menu")->floor == 5);
    CHECK(m.apply(envelope("ui.menu", 5, {{"m", "x = 1"}}, f.dev)).error().code == errc::kRevoked);
    CHECK(m.revoke(revocations(list, {&f.dev})).error().code == errc::kSuperseded); // not newer
}

TEST_CASE("a revoked floor stops what runs at or below it and its fallbacks", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(7, 2)));
    REQUIRE(m.apply(f.speed_release(8, 3)));
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.floors = {{"game.balance", 10}};
    REQUIRE(m.revoke(revocations(list, {&f.dev})));
    CHECK(fx::g_speed == 1); // seq 8 stopped, seq 7 isn't fallen back to
    const auto s = *status_of(m.status(), "game.balance");
    CHECK(s.running == slot::kEmpty);
    CHECK(s.floor == 10);
    CHECK(m.apply(f.speed_release(10, 4)).error().code == errc::kRevoked);
    REQUIRE(m.apply(f.speed_release(11, 4)));
    CHECK(fx::g_speed == 4);
}

TEST_CASE("a newer revocation list can't take back what an older one revoked", "[release][manager]") {
    fixture f;
    const signer ops{"ops"};
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}, {&ops, {"*"}}}), f.options(), f.store};
    REQUIRE(m.install<fx::game_lib>());
    const auto revoked = m.apply(f.speed_release(1, 5));
    REQUIRE(revoked);
    Rhp::release::revocation_list first;
    first.seq = 5;
    first.keys = {f.dev.secret.public_key()};
    first.releases = {revoked->id};
    REQUIRE(m.revoke(revocations(first, {&ops})));
    // dev signs a newer list that forgives itself: its key is revoked, so the list isn't trusted.
    Rhp::release::revocation_list forgive;
    forgive.seq = 6;
    CHECK(m.revoke(revocations(forgive, {&f.dev})).error().code == errc::kBadSignature);
    // ops signs a newer list that leaves the old entries out: they stay revoked.
    Rhp::release::revocation_list partial;
    partial.seq = 7;
    REQUIRE(m.revoke(revocations(partial, {&ops})));
    CHECK(m.apply(f.speed_release(2, 5)).error().code == errc::kBadSignature);
    CHECK(fx::g_speed == 1);
}

TEST_CASE("revocations survive a restart even when the list's signer is no longer trusted", "[release][manager]") {
    fixture f;
    const signer ops{"ops"};
    faulty_store store{f.store};
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}, {&ops, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        REQUIRE(m.restore());
        REQUIRE(m.apply(f.speed_release(1, 5)));
        Rhp::release::revocation_list list;
        list.seq = 3;
        list.keys = {f.dev.secret.public_key()};
        *store.fail_state_writes = true; // only the stored list will know
        const auto revoked = m.revoke(revocations(list, {&ops}));
        CHECK(revoked.error().code == errc::kRuntime); // in effect here, the state not saved
        CHECK(fx::g_speed == 1);
        CHECK(m.apply(f.speed_release(2, 5)).error().code == errc::kRuntime); // nothing changes until it saves
    }
    *store.fail_state_writes = false;
    // ops rotated out: its list no longer verifies, but what it revoked stays revoked.
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), f.store};
    REQUIRE(m.install<fx::game_lib>());
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(m.revocation_seq() == 3);
    CHECK(fx::g_speed == 1);
    CHECK(m.apply(f.speed_release(2, 5)).error().code == errc::kBadSignature);
    Rhp::release::revocation_list older;
    older.seq = 2;
    CHECK(m.revoke(revocations(older, {&f.dev})).error().code == errc::kSuperseded);
}

TEST_CASE("a restore that dies on a candidate keeps every other channel", "[release][manager]") {
    fixture f;
    faulty_store store{f.store};
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        REQUIRE(m.apply(envelope("a.cand", 1, {{"x", "game.spawn(1)"}}, f.dev)));
        REQUIRE(m.apply(envelope("a.cand", 2, {{"x", "game.spawn(2)"}}, f.dev), confirm_mode::kManual));
        REQUIRE(m.apply(envelope("b.live", 7, {{"y", "game.speed = 7"}}, f.dev)));
    }
    {
        *store.state_writes_left = 1; // the boot attempt is saved, then the process dies
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        (void)m.restore();
    }
    *store.state_writes_left = -1;
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
    REQUIRE(m.install<fx::game_lib>());
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(fx::g_speed == 7);
    const auto all = m.status();
    const auto* live = status_of(all, "b.live");
    REQUIRE(live != nullptr);
    CHECK(live->floor == 7);
    CHECK(status_of(all, "a.cand")->attempts == 2);
}

TEST_CASE("an unreadable release is kept for the next restore", "[release][manager]") {
    fixture f;
    faulty_store store{f.store};
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        REQUIRE(m.apply(f.speed_release(1, 3)));
        REQUIRE(m.apply(f.speed_release(2, 6)));
    }
    {
        *store.fail_release_reads = true;
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        const auto report = m.restore();
        REQUIRE(report.has_value());
        CHECK(report->deferred.size() == 1);
        CHECK(fx::g_speed == 1); // nothing runs this time
    }
    CHECK(stored_releases(f.store) == 2); // nothing was given up on
    *store.fail_release_reads = false;
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
    REQUIRE(m.install<fx::game_lib>());
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->restored == std::vector<std::string>{"game.balance"});
    CHECK(fx::g_speed == 6);
}

TEST_CASE("a release needing a lib installed after restore is kept", "[release][manager]") {
    fixture f;
    {
        auto m = f.make();
        auto man = manifest_for("game.balance", 1, {{"tuning", "game.speed = 4"}});
        man.libs = {"game"};
        REQUIRE(m.apply(envelope(man, {{"tuning", "game.speed = 4"}}, {&f.dev})));
    }
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), f.store}; // no install<>
        const auto report = m.restore();
        REQUIRE(report.has_value());
        CHECK(report->deferred.size() == 1);
    }
    auto m = f.make();
    REQUIRE(m.restore());
    CHECK(fx::g_speed == 4);
}

TEST_CASE("apply restores the store first and never overwrites one it can't read", "[release][manager]") {
    fixture f;
    {
        auto m = f.make();
        REQUIRE(m.apply(f.speed_release(5, 3, "game.a")));
    }
    {
        auto m = f.make(); // no restore(): apply restores
        REQUIRE(m.apply(f.speed_release(1, 4, "game.b")));
        CHECK(m.status().size() == 2);
        CHECK(m.apply(f.speed_release(4, 2, "game.a")).error().code == errc::kSuperseded);
        CHECK(stored_releases(f.store) == 2);
    }
    auto bytes = *f.store.read("state");
    bytes.back() = static_cast<std::byte>(std::to_integer<int>(bytes.back()) ^ 1);
    REQUIRE(f.store.write("state", bytes));
    auto m = f.make();
    CHECK(m.apply(f.speed_release(9, 9, "game.c")).error().code == errc::kIntegrity);
    CHECK(*f.store.read("state") == bytes); // untouched
    CHECK(stored_releases(f.store) == 2);
}

TEST_CASE("a release whose state can't be saved doesn't stay running", "[release][manager]") {
    fixture f;
    faulty_store store{f.store};
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
    REQUIRE(m.install<fx::game_lib>());
    REQUIRE(m.apply(f.speed_release(1, 3)));
    *store.fail_writes = true; // the envelope can't be kept
    CHECK(m.apply(f.speed_release(2, 8)).error().code == errc::kRuntime);
    *store.fail_writes = false;
    *store.fail_state_writes = true; // kept, swapped in, but the state can't be saved
    CHECK(m.apply(f.speed_release(2, 8)).error().code == errc::kRuntime);
    CHECK(fx::g_speed == 3);
    const auto s = *status_of(m.status(), "game.balance");
    CHECK(s.active->seq == 1);
    CHECK(s.floor == 1);
    *store.fail_state_writes = false;
    REQUIRE(m.apply(f.speed_release(2, 8)));
    CHECK(fx::g_speed == 8);
}

TEST_CASE("a change whose save failed is saved later and nothing is stacked on it meanwhile", "[release][manager]") {
    fixture f;
    faulty_store store{f.store};
    Rhp::release::release_id candidate{};
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        REQUIRE(m.apply(f.speed_release(1, 2, "game.x")));
        const auto c = m.apply(f.speed_release(2, 8, "game.x"), confirm_mode::kManual);
        REQUIRE(c);
        candidate = c->id;
        *store.fail_state_writes = true;
        CHECK(m.deactivate("game.x", true).error().code == errc::kRuntime); // held here, not saved yet
        CHECK(m.apply(f.speed_release(1, 4, "game.y")).error().code == errc::kRuntime);
        CHECK(status_of(m.status(), "game.y") == nullptr);
        CHECK(stored_releases(f.store) == 2); // nothing collected while the store holds an older state
        *store.fail_state_writes = false;
        f.clocks->steady += std::chrono::seconds{2};
        m.pump(); // the retry saves the hold
    }
    auto m = f.make();
    REQUIRE(m.restore());
    const auto all = m.status();
    REQUIRE(status_of(all, "game.x") != nullptr);
    CHECK(status_of(all, "game.x")->held);
    CHECK(fx::g_speed == 1);
}

TEST_CASE("a candidate that can't be read uses no boot attempt", "[release][manager]") {
    fixture f;
    faulty_store store{f.store};
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        REQUIRE(m.apply(f.speed_release(1, 2)));
        REQUIRE(m.apply(f.speed_release(2, 9), confirm_mode::kManual));
    }
    *store.fail_release_reads = true;
    for (int boot = 0; boot < 4; ++boot) { // more than max_boot_attempts
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        const auto report = m.restore();
        REQUIRE(report.has_value());
        CHECK(report->quarantined.empty());
        CHECK(report->deferred.size() == 1);
    }
    *store.fail_release_reads = false;
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
    REQUIRE(m.install<fx::game_lib>());
    REQUIRE(m.restore());
    CHECK(fx::g_speed == 9);
    CHECK(status_of(m.status(), "game.balance")->attempts == 1);
    REQUIRE(m.last_restore().has_value());
    CHECK(m.last_restore()->restored == std::vector<std::string>{"game.balance"});
}

TEST_CASE("a revocation list stops only what it revokes", "[release][manager]") {
    fixture f;
    auto o = f.options();
    o.expire_running = false;
    auto m = f.make(o);
    auto man = manifest_for("game.balance", 1, {{"tuning", "game.speed = 7"}});
    man.not_after = 1'760'000'100;
    REQUIRE(m.apply(envelope(man, {{"tuning", "game.speed = 7"}}, {&f.dev})));
    f.clocks->wall += std::chrono::seconds{1000}; // past not_after: it keeps running (expire_running off)
    m.pump();
    CHECK(fx::g_speed == 7);
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.floors = {{"other.channel", 3}};
    REQUIRE(m.revoke(revocations(list, {&f.dev})));
    CHECK(fx::g_speed == 7);
}

TEST_CASE("every revocation list is kept even when the state isn't saved", "[release][manager]") {
    fixture f;
    faulty_store store{f.store};
    Rhp::release::release_id first{};
    {
        Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), store};
        REQUIRE(m.install<fx::game_lib>());
        const auto r = m.apply(f.speed_release(1, 3, "game.other"));
        REQUIRE(r);
        first = r->id;
        *store.fail_state_writes = true;
        Rhp::release::revocation_list l1;
        l1.seq = 1;
        l1.releases = {first};
        CHECK_FALSE(m.revoke(revocations(l1, {&f.dev})).has_value());
        Rhp::release::revocation_list l2;
        l2.seq = 2;
        CHECK_FALSE(m.revoke(revocations(l2, {&f.dev})).has_value());
    }
    *store.fail_state_writes = false;
    auto m = f.make();
    REQUIRE(m.restore());
    CHECK(m.revocation_seq() == 2);
    CHECK(fx::g_speed == 1);
    CHECK(m.apply(f.speed_release(1, 3, "game.other")).error().code == errc::kRevoked);
}

TEST_CASE("a held channel falls back to what it held after the next release", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    REQUIRE(m.apply(f.speed_release(2, 3)));                        // active 2, previous 1
    REQUIRE(m.apply(f.speed_release(3, 9), confirm_mode::kManual)); // candidate 3
    REQUIRE(m.deactivate("game.balance", true));
    CHECK(fx::g_speed == 1);
    REQUIRE(m.apply(f.speed_release(4, 6)));
    CHECK(fx::g_speed == 6);
    REQUIRE(m.deactivate("game.balance"));
    CHECK(fx::g_speed == 3); // release 2, which the candidate stood on, not release 1
}

TEST_CASE("confirm and deactivate can be bound to a release", "[release][manager]") {
    fixture f;
    auto m = f.make();
    const auto first = m.apply(f.speed_release(1, 2));
    const auto cand = m.apply(f.speed_release(2, 7), confirm_mode::kManual);
    REQUIRE(first);
    REQUIRE(cand);
    CHECK(m.confirm("game.balance", first->id).error().code == errc::kSuperseded);
    CHECK(m.deactivate("game.balance", false, first->id).error().code == errc::kSuperseded);
    CHECK(fx::g_speed == 7);
    const auto confirmed = m.confirm("game.balance", cand->id);
    REQUIRE(confirmed.has_value());
    CHECK(*confirmed == cand->id);
    CHECK(status_of(m.status(), "game.balance")->confirm == confirm_mode::kNow);
    const auto stopped = m.deactivate("game.balance", false, cand->id);
    REQUIRE(stopped.has_value());
    CHECK(*stopped == cand->id);
    CHECK(fx::g_speed == 2);
}

TEST_CASE("a release envelope may carry a revocation list", "[release][manager]") {
    fixture f;
    auto m = f.make();
    const auto bad = m.apply(f.speed_release(1, 2, "game.other"));
    REQUIRE(bad);
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.releases = {bad->id};
    auto r = Rhp::release::make_release(manifest_for("game.balance", 1, {{"tuning", "game.speed = 5"}}), {"game.speed = 5"});
    REQUIRE(r.has_value());
    const auto rev = revocations(list, {&f.dev});
    r->revocations = rev;
    REQUIRE(Rhp::release::sign(*r, f.dev.key()));
    REQUIRE(m.apply(*Rhp::release::encode_release(*r)));
    CHECK(fx::g_speed == 5);
    CHECK(m.revocation_seq() == 1);
    CHECK(status_of(m.status(), "game.other")->running == slot::kEmpty);
}

TEST_CASE("seq may not jump past max_seq_jump", "[release][manager]") {
    fixture f;
    auto o = f.options();
    o.max_seq_jump = 10;
    auto m = f.make(std::move(o));
    REQUIRE(m.apply(f.speed_release(1, 2)));
    CHECK(m.apply(f.speed_release(20, 3)).error().code == errc::kOutOfRange);
    REQUIRE(m.apply(f.speed_release(11, 3)));
}

TEST_CASE("a channel's first release counts its seq cap from the host's clock", "[release][manager]") {
    fixture f;
    auto m = f.make();
    std::vector<Rhp::release::release_event> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    const auto huge = m.apply(f.speed_release(kMaxSeq, 2));
    REQUIRE_FALSE(huge.has_value());
    CHECK(huge.error().code == errc::kOutOfRange);
    CHECK(huge.error().message.find("this host's clock") != std::string::npos);
    CHECK(m.apply(f.speed_release(kNow + kJump + 1, 2)).error().code == errc::kOutOfRange);
    CHECK(m.status().empty()); // nothing refused is kept
    REQUIRE(events.size() == 2);
    CHECK(events[0].what == event_kind::kRefused);
    CHECK(events[0].err->code == errc::kOutOfRange);
    REQUIRE(m.apply(f.speed_release(kNow + kJump, 2)));
    CHECK(fx::g_speed == 2);
}

TEST_CASE("a revocation list can't fast-forward the revocation seq", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 5)));
    std::vector<Rhp::release::release_event> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    Rhp::release::revocation_list lockout; // one stolen key locking out every later list and release
    lockout.seq = kMaxSeq;
    lockout.floors = {{"game.balance", kMaxSeq}};
    const auto refused = m.revoke(revocations(lockout, {&f.dev}));
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().code == errc::kOutOfRange);
    CHECK(refused.error().message.find("this host's clock") != std::string::npos);
    CHECK(m.revocation_seq() == 0); // nothing of it applies
    CHECK(status_of(m.status(), "game.balance")->floor == 1);
    CHECK(fx::g_speed == 5);
    REQUIRE(events.size() == 1);
    CHECK(events[0].what == event_kind::kRefused);
    CHECK(events[0].seq == kMaxSeq);
    CHECK(events[0].err->code == errc::kOutOfRange);
    // A host's first list counts from its clock, every later one from the last list.
    Rhp::release::revocation_list first;
    first.seq = kNow + kJump + 1;
    CHECK(m.revoke(revocations(first, {&f.dev})).error().code == errc::kOutOfRange);
    first.seq = kNow + kJump;
    REQUIRE(m.revoke(revocations(first, {&f.dev})));
    Rhp::release::revocation_list next;
    next.seq = first.seq + kJump + 1;
    const auto too_far = m.revoke(revocations(next, {&f.dev}));
    CHECK(too_far.error().code == errc::kOutOfRange);
    CHECK(too_far.error().message.find("the highest seq this host has seen") != std::string::npos);
    next.seq = first.seq + kJump;
    REQUIRE(m.revoke(revocations(next, {&f.dev})));
    CHECK(m.revocation_seq() == next.seq);
}

TEST_CASE("a release carrying a revocation list past the seq cap is refused", "[release][manager]") {
    fixture f;
    auto m = f.make();
    std::vector<Rhp::release::release_event> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    Rhp::release::revocation_list list;
    list.seq = kMaxSeq;
    auto r = Rhp::release::make_release(manifest_for("game.balance", 1, {{"tuning", "game.speed = 5"}}), {"game.speed = 5"});
    REQUIRE(r.has_value());
    r->revocations = revocations(list, {&f.dev});
    REQUIRE(Rhp::release::sign(*r, f.dev.key()));
    CHECK(m.apply(*Rhp::release::encode_release(*r)).error().code == errc::kOutOfRange);
    CHECK(m.revocation_seq() == 0);
    CHECK(m.status().empty());
    CHECK(fx::g_speed == 1);
    REQUIRE(events.size() == 1); // the release's refusal (not a second one for its list)
    CHECK(events[0].channel == "game.balance");
}

TEST_CASE("the floors a revocation list raises are capped", "[release][manager]") {
    fixture f;
    auto m = f.make();
    const auto running = m.apply(f.speed_release(5, 3)); // a counter seq
    REQUIRE(running);
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.releases = {running->id};
    list.floors = {{"game.balance", 5 + kJump + 1}};
    const auto refused = m.revoke(revocations(list, {&f.dev}));
    CHECK(refused.error().code == errc::kOutOfRange);
    CHECK(refused.error().where == "release 'game.balance'");
    CHECK(m.revocation_seq() == 0); // refused whole: the release it names still runs
    CHECK(fx::g_speed == 3);
    CHECK(status_of(m.status(), "game.balance")->floor == 5);
    // A channel this host never saw counts from its clock.
    list.floors = {{"game.balance", 5 + kJump}, {"ui.menu", kNow + kJump + 1}};
    CHECK(m.revoke(revocations(list, {&f.dev})).error().code == errc::kOutOfRange);
    CHECK(status_of(m.status(), "ui.menu") == nullptr);
    list.floors = {{"game.balance", 5 + kJump}, {"ui.menu", kNow + kJump}};
    REQUIRE(m.revoke(revocations(list, {&f.dev})));
    CHECK(fx::g_speed == 1);
    CHECK(status_of(m.status(), "game.balance")->floor == 5 + kJump);
    CHECK(status_of(m.status(), "ui.menu")->floor == kNow + kJump);
    // A floor at or below what its channel has seen moves nothing: repeating one is fine.
    Rhp::release::revocation_list again;
    again.seq = 2;
    again.floors = {{"game.balance", 7}, {"ui.menu", kNow + kJump}};
    REQUIRE(m.revoke(revocations(again, {&f.dev})));
    // Releases go on from the raised floor, within the cap.
    CHECK(m.apply(f.speed_release(5 + (2 * kJump) + 1, 4)).error().code == errc::kOutOfRange);
    REQUIRE(m.apply(f.speed_release(5 + (2 * kJump), 4)));
    CHECK(fx::g_speed == 4);
}

TEST_CASE("counter and Unix-time seqs pass the seq caps", "[release][manager]") {
    fixture f;
    auto m = f.make();
    // Counters: releases 1 2 3, a list 1 with small floors (one for a channel never seen).
    REQUIRE(m.apply(f.speed_release(1, 2, "game.counter")));
    REQUIRE(m.apply(f.speed_release(2, 3, "game.counter")));
    Rhp::release::revocation_list list;
    list.seq = 1;
    list.floors = {{"game.counter", 1}, {"ui.counter", 4}};
    REQUIRE(m.revoke(revocations(list, {&f.dev})));
    REQUIRE(m.apply(f.speed_release(3, 4, "game.counter")));
    REQUIRE(m.apply(f.speed_release(5, 5, "ui.counter")));
    // Unix seconds (rhp-cli's --seq auto): a first release, the next one, a list after a counter list.
    REQUIRE(m.apply(f.speed_release(kNow, 6, "game.clock")));
    REQUIRE(m.apply(f.speed_release(kNow + 60, 7, "game.clock")));
    list.seq = kNow + 120;
    list.floors = {{"game.clock", kNow + 30}};
    REQUIRE(m.revoke(revocations(list, {&f.dev})));
    CHECK(m.revocation_seq() == kNow + 120);
    // A channel that counted switches to Unix time.
    REQUIRE(m.apply(f.speed_release(kNow + 180, 8, "game.counter")));
    CHECK(fx::g_speed == 8);
}

TEST_CASE("a clock at 1970 still passes Unix-time seqs", "[release][manager]") {
    fixture f;
    f.clocks->wall = std::chrono::system_clock::time_point{}; // a dead clock battery
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(kNow, 2))); // 0 + the default jump is past every Unix time before 2106
    Rhp::release::revocation_list list;
    list.seq = kNow;
    list.floors = {{"ui.menu", kNow}};
    REQUIRE(m.revoke(revocations(list, {&f.dev})));
    CHECK(fx::g_speed == 2);
}

TEST_CASE("a wrong clock only holds a first seq back", "[release][manager]") {
    fixture f;
    f.clocks->wall = std::chrono::system_clock::time_point{};
    auto o = f.options();
    o.max_seq_jump = 3600;
    auto m = f.make(std::move(o));
    CHECK(m.apply(f.speed_release(kNow, 2)).error().code == errc::kOutOfRange);
    CHECK(m.status().empty());
    REQUIRE(m.apply(f.speed_release(1, 3, "game.counter"))); // counters don't mind
    f.clocks->wall = fake_clocks{}.wall;                     // the clock is set (kNow)
    REQUIRE(m.apply(f.speed_release(kNow, 4)));
    CHECK(fx::g_speed == 4);
}

TEST_CASE("a restored host counts its seq caps from what it saw before", "[release][manager]") {
    fixture f;
    {
        auto m = f.make();
        REQUIRE(m.apply(f.speed_release(kNow, 4)));
        Rhp::release::revocation_list list;
        list.seq = 7;
        list.floors = {{"ui.menu", 9}};
        REQUIRE(m.revoke(revocations(list, {&f.dev})));
    }
    auto m = f.make();
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->failed.empty());
    CHECK(report->restored == std::vector<std::string>{"game.balance"});
    CHECK(fx::g_speed == 4);
    CHECK(m.revocation_seq() == 7);
    CHECK(status_of(m.status(), "ui.menu")->floor == 9);
    Rhp::release::revocation_list next;
    next.seq = 7 + kJump + 1;
    CHECK(m.revoke(revocations(next, {&f.dev})).error().code == errc::kOutOfRange);
    next.seq = 7 + kJump;
    next.floors = {{"ui.menu", 9 + kJump}};
    REQUIRE(m.revoke(revocations(next, {&f.dev})));
    CHECK(m.apply(f.speed_release(kNow + kJump + 1, 5)).error().code == errc::kOutOfRange);
    REQUIRE(m.apply(f.speed_release(kNow + kJump, 5)));
    CHECK(fx::g_speed == 5);
}

TEST_CASE("stored state past the seq caps still restores as it is", "[release][manager]") {
    fixture f;
    {
        auto o = f.options();
        o.max_seq_jump = kMaxSeq; // as uncapped as an older build
        auto m = f.make(std::move(o));
        REQUIRE(m.apply(f.speed_release(kMaxSeq - 10, 4)));
        Rhp::release::revocation_list list;
        list.seq = kMaxSeq - 1;
        list.floors = {{"ui.menu", kMaxSeq - 1}};
        REQUIRE(m.revoke(revocations(list, {&f.dev})));
    }
    auto m = f.make(); // the default cap
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->failed.empty());
    CHECK(fx::g_speed == 4); // nothing lowered, nothing refused
    CHECK(m.revocation_seq() == kMaxSeq - 1);
    CHECK(status_of(m.status(), "game.balance")->floor == kMaxSeq - 10);
    CHECK(status_of(m.status(), "ui.menu")->floor == kMaxSeq - 1);
    Rhp::release::revocation_list next; // later moves count from there
    next.seq = kMaxSeq;
    REQUIRE(m.revoke(revocations(next, {&f.dev})));
    REQUIRE(m.apply(f.speed_release(kMaxSeq - 9, 6)));
    CHECK(fx::g_speed == 6);
}

TEST_CASE("a role change swaps in a fresh sandbox and rolls back across it", "[release][manager]") {
    fixture f;
    auto o = f.options();
    o.max_role = Rhp::role::kAdmin;
    auto m = f.make(std::move(o));
    REQUIRE(m.apply(f.speed_release(1, 2)));
    auto man = manifest_for("game.balance", 2, {{"tuning", "game.speed = 9"}});
    man.run_as = Rhp::role::kAdmin;
    REQUIRE(m.apply(envelope(man, {{"tuning", "game.speed = 9"}}, {&f.dev})));
    CHECK(fx::g_speed == 9);
    CHECK(m.sandbox("game.balance")->caller_role() == Rhp::role::kAdmin);
    REQUIRE(m.deactivate("game.balance"));
    CHECK(fx::g_speed == 2);
    CHECK(m.sandbox("game.balance")->caller_role() != Rhp::role::kAdmin);
}

TEST_CASE("a candidate whose module faults is rolled back", "[release][manager]") {
    fixture f;
    auto m = f.make();
    REQUIRE(m.apply(f.speed_release(1, 2)));
    REQUIRE(m.apply(envelope("game.balance", 2, {{"tuning", "game.speed = 8 rhp.after(0, function() error('broken') end, {on_error = 'fault'})"}}, f.dev),
                    confirm_mode::kHealth));
    for (int i = 0; i < 4; ++i) {
        m.pump();
    }
    CHECK(fx::g_speed == 2);
    CHECK(status_of(m.status(), "game.balance")->running == slot::kActive);
}

TEST_CASE("max_boot_attempts 0 quarantines at the first restart and a huge one never", "[release][manager]") {
    for (const std::uint32_t attempts : {std::uint32_t{0}, (std::numeric_limits<std::uint32_t>::max)()}) {
        fixture f;
        auto o = f.options();
        o.max_boot_attempts = attempts;
        {
            auto m = f.make(o);
            REQUIRE(m.apply(f.speed_release(1, 2)));
            REQUIRE(m.apply(f.speed_release(2, 9), confirm_mode::kManual));
        }
        for (int boot = 0; boot < 3; ++boot) {
            auto m = f.make(o);
            const auto report = m.restore();
            REQUIRE(report.has_value());
            CHECK(fx::g_speed == (attempts == 0 ? 2 : 9));
        }
    }
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
    CHECK(box->caller_role() == Rhp::role::kAdmin);
    // Only admin sandboxes have io, and only in a dev build (RHP_HARDENING above dev leaves it out).
    CHECK(*box->exec("return type(io)") == Rhp::value_list{Rhp::value{Rhp::kBuildHardening == Rhp::hardening::kDev ? "table" : "nil"}});
}

TEST_CASE("the directory store keeps releases across managers", "[release][store]") {
    const auto dir = std::filesystem::temp_directory_path() / std::format("rhp_release_store_test_{}", std::random_device{}());
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
    CHECK(store.write("a.b/c-d_e", bytes));
    for (const char* bad : {"", "/abs", "a/../b", "Upper", "end/", "sp ace", "a//b", "./x", "a./b", "dot.", "nul", "con.rhp", "x/com1", "lpt9.a"}) {
        CHECK(store.write(bad, bytes).error().code == errc::kInvalidArgument);
    }
    CHECK(store.read("missing").error().code == errc::kNotFound);
    CHECK(store.remove("missing"));
}

TEST_CASE("an empty any_store reports errors instead of crashing", "[release][store]") {
    const Rhp::release::any_store empty;
    CHECK_FALSE(empty);
    const std::vector<std::byte> bytes{std::byte{1}};
    CHECK(empty.read("state").error().code == errc::kInvalidArgument);
    CHECK(empty.write("state", bytes).error().code == errc::kInvalidArgument);
    CHECK(empty.remove("state").error().code == errc::kInvalidArgument);
    CHECK(empty.keys().error().code == errc::kInvalidArgument);

    fixture f;
    Rhp::release::manager m{trust_of({{&f.dev, {"*"}}}), f.options(), empty};
    CHECK(m.restore().error().code == errc::kInvalidArgument);
    CHECK(m.apply(f.speed_release(1, 2)).error().code == errc::kInvalidArgument);
}

TEST_CASE("a manager runs at least at the build's hardening level and harden only raises it", "[release][manager][hardening]") {
    fixture f;
    auto m = f.make();
    CHECK(m.options().hardening == Rhp::kBuildHardening);
    REQUIRE(m.harden(Rhp::hardening::kLan));
    CHECK(m.options().hardening == Rhp::strictest(Rhp::hardening::kLan, Rhp::kBuildHardening));
    REQUIRE(m.harden(Rhp::hardening::kDev));
    CHECK(m.options().hardening == Rhp::strictest(Rhp::hardening::kLan, Rhp::kBuildHardening));
}

TEST_CASE("hardening above dev gives a running admin channel patch's libraries", "[release][manager][hardening]") {
    fixture f;
    auto o = f.options();
    o.max_role = Rhp::role::kAdmin;
    auto m = f.make(std::move(o));
    auto man = manifest_for("game.balance", 1, {{"tuning", "game.speed = 7"}});
    man.run_as = Rhp::role::kAdmin;
    REQUIRE(m.apply(envelope(man, {{"tuning", "game.speed = 7"}}, {&f.dev})));
    const auto has_io = [&] { return m.sandbox("game.balance")->exec<bool>("return io ~= nil"); };
    CHECK(has_io() == (Rhp::kBuildHardening == Rhp::hardening::kDev));

    std::vector<event_kind> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e.what); });
    REQUIRE(m.harden(Rhp::hardening::kLan));
    CHECK(has_io() == false); // a new sandbox, made at lan
    CHECK(m.sandbox("game.balance")->caller_role() == Rhp::role::kAdmin);
    CHECK(fx::g_speed == 7); // the release runs on in it
    const auto st = m.status();
    REQUIRE(status_of(st, "game.balance") != nullptr);
    CHECK(status_of(st, "game.balance")->running == slot::kActive);
    CHECK(events.empty());
}

TEST_CASE("a running release that can't load at the new hardening level stops", "[release][manager][hardening]") {
    rhp_test::needs(Rhp::hardening::kDev, "admin's full standard library");
    fixture f;
    auto o = f.options();
    o.max_role = Rhp::role::kAdmin;
    auto m = f.make(std::move(o));
    const std::vector<module_source> modules{{"tuning", "assert(io ~= nil); game.speed = 4"}};
    auto man = manifest_for("game.balance", 1, modules);
    man.run_as = Rhp::role::kAdmin;
    REQUIRE(m.apply(envelope(man, modules, {&f.dev})));
    CHECK(fx::g_speed == 4);

    std::vector<Rhp::release::release_event> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    REQUIRE(m.harden(Rhp::hardening::kLan));
    CHECK(m.sandbox("game.balance") == nullptr);
    CHECK(fx::g_speed == 1); // what it did is undone
    REQUIRE(events.size() == 1);
    CHECK(events[0].what == event_kind::kRolledBack);
    CHECK(events[0].reason.starts_with("hardening lan"));
    CHECK(events[0].err.has_value());
}

TEST_CASE("a production manager caps its channels' limits", "[release][manager][hardening]") {
    fixture f;
    auto o = f.options();
    o.clock = {}; // real time: the wall cap is measured on it
    o.limits.wall_ms = 60'000;
    auto m = f.make(std::move(o));
    REQUIRE(m.apply(f.speed_release(1, 3)));
    REQUIRE(m.harden(Rhp::hardening::kProduction));
    const auto started = std::chrono::steady_clock::now();
    const auto stopped = m.sandbox("game.balance")->exec("while true do end");
    REQUIRE_FALSE(stopped);
    CHECK(stopped.error().code == errc::kTimeout);
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds{30});
    CHECK(fx::g_speed == 3);
}
