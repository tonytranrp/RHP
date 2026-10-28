// The release manager with a root of trust (decision AL12): trust from the root's roles, rotations
// kept in the store, and the recover step for compromised keys.
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "release_support.hpp"
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/release/root_of_trust.hpp>
#include <rhp/release/store.hpp>
#include <rhp/script/lib.hpp>

using Rhp::errc;
using Rhp::release::root_role;
using namespace release_test;

namespace root_manager_fixture {

inline int g_level = 0;
using level_lib = Rhp::lib<"rootlevel">::var<"value", &g_level>;

constexpr std::uint64_t kRootNow = 1'760'000'000;
constexpr std::uint64_t kRootJump = std::uint64_t{1} << 32;

struct world {
    signer root_a{"root-a"}, root_b{"root-b"};
    signer rel{"release-1"}, rel2{"release-2"};
    signer rev{"revocation-1"}, rev2{"revocation-2"};
    Rhp::release::memory_store store;
    std::chrono::system_clock::time_point wall = std::chrono::system_clock::time_point{} + std::chrono::seconds{kRootNow};

    world() { g_level = 0; }

    static Rhp::release::root_key key(const signer& s, std::vector<std::string> channels = {}) {
        const auto pub_key = s.secret.public_key(); // bytes() views it: keep it alive
        const auto pub = pub_key.bytes();
        return Rhp::release::root_key{"ed25519", std::vector<std::byte>(pub.begin(), pub.end()), std::move(channels)};
    }

    // Version `v`: root keys a and b (threshold 2), `release` for game.*, `revocation`.
    Rhp::release::root_document doc(std::uint64_t v, const signer& release, const signer& revocation) const {
        Rhp::release::root_document d;
        d.version = v;
        d.expires = kRootNow + 86'400;
        for (const signer* s : {&root_a, &root_b}) {
            d.keys[s->name] = key(*s);
            d.role(root_role::kRoot).keys.push_back(s->name);
        }
        d.role(root_role::kRoot).threshold = 2;
        d.keys[release.name] = key(release, {"game.*"});
        d.role(root_role::kRelease).keys.push_back(release.name);
        d.keys[revocation.name] = key(revocation);
        d.role(root_role::kRevocation).keys.push_back(revocation.name);
        return d;
    }

    Rhp::release::signed_root sealed(Rhp::release::root_document d) const {
        auto r = Rhp::release::make_root(std::move(d));
        REQUIRE(r.has_value());
        REQUIRE(Rhp::release::sign(*r, root_a.key()));
        REQUIRE(Rhp::release::sign(*r, root_b.key()));
        return *r;
    }

    [[nodiscard]] Rhp::release::signed_root genesis() const { return sealed(doc(1, rel, rev)); }

    [[nodiscard]] Rhp::release::manager make(Rhp::release::signed_root anchor) const {
        Rhp::release::manager_options o;
        o.app = "rootgame";
        o.wall_clock = [w = wall] { return w; };
        o.output = [](std::string_view, std::string_view) {};
        Rhp::release::manager m{std::move(anchor), std::move(o), store};
        REQUIRE(m.install<level_lib>());
        return m;
    }

    [[nodiscard]] std::vector<std::byte> level_release(std::uint64_t seq, int level, const signer& by, std::string channel = "game.level") const {
        return envelope(std::move(channel), seq, {{"lvl", "rootlevel.value = " + std::to_string(level)}}, by);
    }
};

std::uint64_t floor_of(const Rhp::release::manager& m, std::string_view channel) {
    for (const auto& s : m.status()) {
        if (s.channel == channel) {
            return s.floor;
        }
    }
    return 0;
}

std::size_t stored_roots(Rhp::release::memory_store& store) {
    std::size_t n = 0;
    for (const auto& k : *store.keys()) {
        n += k.starts_with("trust/root/") ? 1 : 0;
    }
    return n;
}

} // namespace root_manager_fixture

using namespace root_manager_fixture;

TEST_CASE("a manager made with a root trusts its release and revocation roles", "[release][root][manager]") {
    world w;
    auto m = w.make(w.genesis());
    REQUIRE(m.restore());
    REQUIRE(m.root() != nullptr);
    CHECK(m.root()->body.version == 1);
    REQUIRE(m.apply(w.level_release(1, 5, w.rel)));
    CHECK(g_level == 5);
    // The release key may sign game.* only; root and revocation keys sign no releases.
    CHECK(m.apply(w.level_release(2, 6, w.rel, "ui.menu")).error().code == errc::kBadSignature);
    CHECK(m.apply(w.level_release(2, 6, w.root_a)).error().code == errc::kBadSignature);
    CHECK(m.apply(w.level_release(2, 6, w.rev)).error().code == errc::kBadSignature);
    // Revocation lists: the revocation role only.
    Rhp::release::revocation_list list;
    list.seq = 1;
    CHECK(m.revoke(revocations(list, {&w.rel})).error().code == errc::kBadSignature);
    REQUIRE(m.revoke(revocations(list, {&w.rev})));
    CHECK(m.trust_held().root_version == 1);
}

TEST_CASE("a manager without a root behaves as before and takes no root", "[release][root][manager]") {
    world w;
    Rhp::release::manager m{trust_of({{&w.rel, {"*"}}}), {}, w.store};
    REQUIRE(m.restore());
    CHECK(m.root() == nullptr);
    CHECK(m.trust_held().root_version == 0);
    const std::vector roots{w.genesis()};
    CHECK(m.update_root(roots).error().code == errc::kNotFound);
    // The trust it was given signs releases and lists, as in Stage 10.
    Rhp::release::revocation_list list;
    list.seq = 1;
    REQUIRE(m.revoke(revocations(list, {&w.rel})));
}

TEST_CASE("an anchor that doesn't verify stops the manager", "[release][root][manager]") {
    world w;
    auto unsigned_root = *Rhp::release::make_root(w.doc(1, w.rel, w.rev));
    REQUIRE(Rhp::release::sign(unsigned_root, w.root_a.key())); // one of two
    auto m = w.make(unsigned_root);
    CHECK(m.restore().error().code == errc::kBadSignature);
    CHECK(m.apply(w.level_release(1, 5, w.rel)).error().code == errc::kBadSignature);
}

TEST_CASE("a manager walks to a newer root and keeps it across a restart", "[release][root][manager]") {
    world w;
    {
        auto m = w.make(w.genesis());
        REQUIRE(m.apply(w.level_release(1, 5, w.rel)));
        // Version 2 retires release-1 for release-2; versions held are skipped when sent again.
        const std::vector chain{w.genesis(), w.sealed(w.doc(2, w.rel2, w.rev))};
        const auto held = m.update_root(chain);
        REQUIRE(held.has_value());
        CHECK(*held == 2);
        CHECK(stored_roots(w.store) == 1);
        CHECK(g_level == 5); // retired keys keep what they signed
        CHECK(m.apply(w.level_release(2, 6, w.rel)).error().code == errc::kBadSignature);
        REQUIRE(m.apply(w.level_release(2, 6, w.rel2)));
        CHECK(*m.update_root(chain) == 2); // nothing new
    }
    g_level = 0;
    auto m = w.make(w.genesis()); // the app still embeds version 1
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->failed.empty());
    CHECK(m.root()->body.version == 2);
    CHECK(g_level == 6);
    CHECK(m.apply(w.level_release(3, 7, w.rel)).error().code == errc::kBadSignature);
    REQUIRE(m.apply(w.level_release(3, 7, w.rel2)));
    // Releases a retired key signed still run as fallbacks; here the fallback is seq 2.
    REQUIRE(m.deactivate("game.level"));
    CHECK(g_level == 6);
}

TEST_CASE("a root update that doesn't verify changes nothing", "[release][root][manager]") {
    world w;
    auto m = w.make(w.genesis());
    REQUIRE(m.restore());
    const auto refused = [&](std::vector<Rhp::release::signed_root> roots) {
        const auto r = m.update_root(roots);
        REQUIRE_FALSE(r.has_value());
        CHECK(m.root()->body.version == 1);
        CHECK(stored_roots(w.store) == 0);
        return r.error().code;
    };
    CHECK(refused({w.sealed(w.doc(3, w.rel2, w.rev))}) == errc::kOutOfRange); // a skipped version
    auto only_a = *Rhp::release::make_root(w.doc(2, w.rel2, w.rev));
    REQUIRE(Rhp::release::sign(only_a, w.root_a.key()));
    CHECK(refused({only_a}) == errc::kBadSignature); // one of two root keys
    // New root keys signing alone: version 1's threshold is missing.
    signer c{"root-c"}, d{"root-d"};
    auto takeover = w.doc(2, w.rel2, w.rev);
    takeover.keys.erase("root-a");
    takeover.keys.erase("root-b");
    takeover.keys[c.name] = world::key(c);
    takeover.keys[d.name] = world::key(d);
    takeover.role(root_role::kRoot).keys = {c.name, d.name};
    auto by_new = *Rhp::release::make_root(takeover);
    REQUIRE(Rhp::release::sign(by_new, c.key()));
    REQUIRE(Rhp::release::sign(by_new, d.key()));
    CHECK(refused({by_new}) == errc::kBadSignature);
    // Expired: refused as an update.
    auto stale = w.doc(2, w.rel2, w.rev);
    stale.expires = kRootNow - 3600;
    CHECK(refused({w.sealed(stale)}) == errc::kExpired);
    CHECK(refused({w.genesis(), w.sealed(w.doc(1, w.rel2, w.rev))}) == errc::kSuperseded); // another version 1
}

TEST_CASE("a held root that expired still verifies releases", "[release][root][manager]") {
    world w;
    auto d = w.doc(1, w.rel, w.rev);
    d.expires = kRootNow - 10;
    auto m = w.make(w.sealed(d));
    REQUIRE(m.restore());
    REQUIRE(m.apply(w.level_release(1, 4, w.rel)));
    CHECK(g_level == 4);
}

TEST_CASE("a compromised revocation key's lists are dropped and its fast-forward undone", "[release][root][manager]") {
    world w;
    // Version 1: two revocation keys, either may sign a list.
    auto d1 = w.doc(1, w.rel, w.rev);
    d1.keys[w.rev2.name] = world::key(w.rev2);
    d1.role(root_role::kRevocation).keys.push_back(w.rev2.name);
    {
        auto m = w.make(w.sealed(d1));
        REQUIRE(m.apply(w.level_release(1, 5, w.rel)));
        // A list by the key that stays trusted: it stays.
        Rhp::release::revocation_list honest;
        honest.seq = 1;
        honest.floors = {{"ui.menu", 3}};
        REQUIRE(m.revoke(revocations(honest, {&w.rev2})));
        // The stolen key: as far as AL9 lets it go, locking game.level and revoking the release key.
        Rhp::release::revocation_list stolen;
        stolen.seq = 1 + kRootJump;
        stolen.floors = {{"game.level", 1 + kRootJump}};
        stolen.keys = {w.rel.secret.public_key()};
        REQUIRE(m.revoke(revocations(stolen, {&w.rev})));
        CHECK(g_level == 0); // the running release stopped
        CHECK(floor_of(m, "game.level") == 1 + kRootJump);
        CHECK(m.apply(w.level_release(2, 6, w.rel)).error().code == errc::kRevoked);
        // Past the cap it couldn't go at all.
        stolen.seq = 1 + kRootJump + kRootJump + 1;
        CHECK(m.revoke(revocations(stolen, {&w.rev})).error().code == errc::kOutOfRange);
    }
    // The operators mark revocation-1 compromised in version 2, which the app's next build embeds.
    auto d2 = w.doc(2, w.rel, w.rev2);
    d2.keys[w.rev.name] = world::key(w.rev);
    d2.compromised = {w.rev.name};
    auto m = w.make(w.sealed(d2));
    const auto report = m.restore();
    REQUIRE(report.has_value());
    CHECK(report->dropped.size() == 1);
    CHECK(m.revocation_seq() == 1);           // back to the honest list
    CHECK(floor_of(m, "game.level") == 1);    // back to what the trusted release key shipped there
    CHECK(floor_of(m, "ui.menu") == 3);       // the honest list's floor stays
    REQUIRE(m.apply(w.level_release(2, 6, w.rel))); // the release key is trusted again
    CHECK(g_level == 6);
    // The dropped list is gone from the store; a list by the compromised key is refused.
    Rhp::release::revocation_list again;
    again.seq = 2;
    CHECK(m.revoke(revocations(again, {&w.rev})).error().code == errc::kBadSignature);
    REQUIRE(m.revoke(revocations(again, {&w.rev2})));
}

TEST_CASE("a root update that marks a key compromised recovers at once", "[release][root][manager]") {
    world w;
    auto m = w.make(w.genesis());
    REQUIRE(m.apply(w.level_release(1, 5, w.rel)));
    Rhp::release::revocation_list stolen;
    stolen.seq = kRootNow + kRootJump;
    stolen.floors = {{"game.level", 1 + kRootJump}};
    REQUIRE(m.revoke(revocations(stolen, {&w.rev})));
    CHECK(floor_of(m, "game.level") == 1 + kRootJump);
    auto d2 = w.doc(2, w.rel, w.rev2);
    d2.keys[w.rev.name] = world::key(w.rev);
    d2.compromised = {w.rev.name};
    std::vector<Rhp::release::release_event> events;
    const auto sub = m.on_event([&](const Rhp::release::release_event& e) { events.push_back(e); });
    const std::vector chain{w.sealed(d2)};
    REQUIRE(m.update_root(chain));
    CHECK(m.revocation_seq() == 0);
    CHECK(floor_of(m, "game.level") == 1);
    REQUIRE_FALSE(events.empty());
    CHECK(events.back().what == Rhp::release::release_event::kind::kTrust);
    CHECK(events.back().seq == 2);
    REQUIRE(m.apply(w.level_release(2, 7, w.rel)));
    CHECK(g_level == 7);
}

TEST_CASE("releases signed only by a compromised key stop and their floor comes down", "[release][root][manager]") {
    world w;
    // Version 1 trusts release-1 and release-2; release-2 is stolen and fast-forwards game.level.
    auto d1 = w.doc(1, w.rel, w.rev);
    d1.keys[w.rel2.name] = world::key(w.rel2, {"game.*"});
    d1.role(root_role::kRelease).keys.push_back(w.rel2.name);
    auto m = w.make(w.sealed(d1));
    REQUIRE(m.apply(w.level_release(1, 5, w.rel)));
    REQUIRE(m.apply(w.level_release(1 + kRootJump, 9, w.rel2)));
    CHECK(g_level == 9);
    auto d2 = w.doc(2, w.rel, w.rev);
    d2.keys[w.rel2.name] = world::key(w.rel2);
    d2.compromised = {w.rel2.name};
    const std::vector chain{w.sealed(d2)};
    REQUIRE(m.update_root(chain));
    CHECK(g_level == 5); // back to what release-1 signed
    CHECK(floor_of(m, "game.level") == 1);
    REQUIRE(m.apply(w.level_release(2, 6, w.rel)));
    CHECK(g_level == 6);
}

TEST_CASE("trust documents arrive as envelopes", "[release][root][manager]") {
    world w;
    auto m = w.make(w.genesis());
    REQUIRE(m.restore());
    const std::vector<std::vector<std::byte>> docs{*Rhp::release::encode_root(w.sealed(w.doc(2, w.rel2, w.rev))),
                                                   *Rhp::release::encode_root(w.sealed(w.doc(3, w.rel2, w.rev2)))};
    const auto state = m.update_trust(docs);
    REQUIRE(state.has_value());
    CHECK(state->root_version == 3);
    const std::vector<std::vector<std::byte>> junk{std::vector<std::byte>{std::byte{0xc0}}};
    CHECK(m.update_trust(junk).error().code == errc::kInvalidArgument);
}
