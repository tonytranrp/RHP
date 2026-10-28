#include <array>
#include <cstddef>
#include <random>
#include <string>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/scopes.hpp>

using Rhp::scope_kind;
using Rhp::scope_set;

namespace {

scope_set parsed(std::string_view text) {
    auto s = scope_set::parse(text);
    REQUIRE(s);
    return *s;
}

} // namespace

TEST_CASE("scopes: name patterns match a name or the names below a prefix", "[core][scopes]") {
    STATIC_REQUIRE(Rhp::name_matches("*", "game"));
    STATIC_REQUIRE(Rhp::name_matches("game", "game"));
    STATIC_REQUIRE_FALSE(Rhp::name_matches("game", "game.ui"));
    STATIC_REQUIRE(Rhp::name_matches("game.*", "game.ui"));
    STATIC_REQUIRE(Rhp::name_matches("game.*", "game.ui.hud"));
    STATIC_REQUIRE_FALSE(Rhp::name_matches("game.*", "game"));
    STATIC_REQUIRE_FALSE(Rhp::name_matches("game.*", "gameplay"));

    STATIC_REQUIRE(Rhp::valid_name_pattern("*"));
    STATIC_REQUIRE(Rhp::valid_name_pattern("economy.write"));
    STATIC_REQUIRE(Rhp::valid_name_pattern("Game_2.*"));
    STATIC_REQUIRE(Rhp::valid_name_pattern("release_apply"));
    STATIC_REQUIRE_FALSE(Rhp::valid_name_pattern(""));
    STATIC_REQUIRE_FALSE(Rhp::valid_name_pattern(".*"));
    STATIC_REQUIRE_FALSE(Rhp::valid_name_pattern("game..ui"));
    STATIC_REQUIRE_FALSE(Rhp::valid_name_pattern("game.*.ui"));
    STATIC_REQUIRE_FALSE(Rhp::valid_name_pattern("ga me"));
    STATIC_REQUIRE_FALSE(Rhp::valid_name_pattern("game*"));
}

TEST_CASE("scopes: no patterns allow everything", "[core][scopes]") {
    const scope_set all;
    CHECK(all.unrestricted());
    CHECK(all.allows(scope_kind::kLib, "game"));
    CHECK(all.allows(scope_kind::kOp, "revert_all"));
    CHECK(all.to_string() == "*");
    CHECK(parsed("") == all);
    CHECK(parsed("  ") == all);
    CHECK(parsed("*") == all);
    CHECK(parsed("lib:*") == all);
    CHECK(parsed("lib:game,lib:*") == all);
}

TEST_CASE("scopes: allow patterns restrict their own kind only", "[core][scopes]") {
    const scope_set s = parsed("lib:game, lib:ui.*,op:exec");
    CHECK_FALSE(s.unrestricted());
    CHECK(s.allows(scope_kind::kLib, "game"));
    CHECK(s.allows(scope_kind::kLib, "ui.hud"));
    CHECK_FALSE(s.allows(scope_kind::kLib, "ui"));
    CHECK_FALSE(s.allows(scope_kind::kLib, "debug"));
    CHECK(s.allows(scope_kind::kOp, "exec"));
    CHECK_FALSE(s.allows(scope_kind::kOp, "load"));
    // kinds without allow patterns stay open
    CHECK(s.unrestricted(scope_kind::kCap));
    CHECK(s.allows(scope_kind::kCap, "economy.write"));
    CHECK(s.allows(scope_kind::kEvent, "game.round_over"));
    CHECK(s.allows(scope_kind::kPatch, "combat.damage"));
}

TEST_CASE("scopes: deny wins over every allow", "[core][scopes]") {
    const scope_set s = parsed("cap:economy.*,!cap:economy.write,cap:economy.write");
    CHECK(s.allows(scope_kind::kCap, "economy.read"));
    CHECK_FALSE(s.allows(scope_kind::kCap, "economy.write"));
    CHECK_FALSE(s.allows(scope_kind::kCap, "inventory.read"));

    CHECK(s.denies(scope_kind::kCap, "economy.write"));
    CHECK_FALSE(s.denies(scope_kind::kCap, "inventory.read")); // not allowed, but not denied either

    const scope_set only_denies = parsed("!event:admin.*,!patch:*");
    CHECK(only_denies.allows(scope_kind::kEvent, "game.tick"));
    CHECK_FALSE(only_denies.allows(scope_kind::kEvent, "admin.kick"));
    CHECK_FALSE(only_denies.allows(scope_kind::kPatch, "combat.damage"));
    CHECK(only_denies.allows(scope_kind::kLib, "game"));

    const scope_set nothing = parsed("!*,lib:game");
    for (std::size_t k = 0; k < Rhp::kScopeKinds; ++k) {
        CHECK_FALSE(nothing.allows(static_cast<scope_kind>(k), "game"));
    }
}

TEST_CASE("scopes: bad patterns are refused by name", "[core][scopes]") {
    for (const std::string_view text : {"game", "lib:", "lib:ga me", "file:x", "lib:game..x", "!", "lib:game,", ",lib:game", "lib:game*"}) {
        auto s = scope_set::parse(text);
        REQUIRE_FALSE(s);
        CHECK(s.error().code == Rhp::errc::kInvalidArgument);
        CHECK(s.error().where == "scopes");
    }
    auto s = scope_set::parse("lib:game,op:exec ,cap:x y");
    REQUIRE_FALSE(s);
    CHECK(s.error().message.starts_with("'cap:x y'"));
}

TEST_CASE("scopes: to_string reads back to the same set", "[core][scopes]") {
    for (const std::string_view text : {"*", "lib:game,lib:ui.*", "!cap:economy.write,cap:economy.*", "!*", "op:exec,op:call,!event:admin.*"}) {
        const scope_set s = parsed(text);
        CHECK(parsed(s.to_string()) == s);
    }
    CHECK(parsed("op:exec,lib:b,lib:a,lib:a").to_string() == "lib:a,lib:b,op:exec");
}

TEST_CASE("scopes: intersect allows what both allow", "[core][scopes]") {
    const scope_set a = parsed("lib:game.*,lib:ui,!cap:economy.write");
    const scope_set b = parsed("lib:game.economy.*,lib:debug,!op:revert_all");
    const scope_set both = scope_set::intersect(a, b);
    CHECK(both.allows(scope_kind::kLib, "game.economy.bank"));
    CHECK_FALSE(both.allows(scope_kind::kLib, "game.ui"));
    CHECK_FALSE(both.allows(scope_kind::kLib, "ui"));
    CHECK_FALSE(both.allows(scope_kind::kLib, "debug"));
    CHECK_FALSE(both.allows(scope_kind::kCap, "economy.write"));
    CHECK_FALSE(both.allows(scope_kind::kOp, "revert_all"));
    CHECK(both.allows(scope_kind::kOp, "exec"));

    CHECK(scope_set::intersect(scope_set{}, a) == a);
    CHECK(scope_set::intersect(a, scope_set{}) == a);
    // disjoint allow patterns leave nothing of that kind
    const scope_set none = scope_set::intersect(parsed("lib:game"), parsed("lib:ui"));
    CHECK_FALSE(none.allows(scope_kind::kLib, "game"));
    CHECK_FALSE(none.allows(scope_kind::kLib, "ui"));
    CHECK(none.to_string() == "!lib:*");
    CHECK_FALSE(parsed(none.to_string()).allows(scope_kind::kLib, "game"));
}

TEST_CASE("scopes: intersect agrees with both sets on random patterns", "[core][scopes]") {
    static constexpr std::array<std::string_view, 9> names{"a", "a.b", "a.b.c", "a.c", "b", "b.a", "ab", "a.bc", "c.a.b"};
    static constexpr std::array<std::string_view, 12> patterns{"*", "a", "a.*", "a.b", "a.b.*", "b.*", "b", "ab", "a.c", "c.*", "a.bc", "b.a"};
    std::mt19937 rng{20261027};
    const auto random_set = [&] {
        std::string text;
        const auto count = std::uniform_int_distribution<int>{0, 4}(rng);
        for (int i = 0; i < count; ++i) {
            if (!text.empty()) {
                text += ',';
            }
            if (std::uniform_int_distribution<int>{0, 3}(rng) == 0) {
                text += '!';
            }
            text += Rhp::to_string(static_cast<scope_kind>(std::uniform_int_distribution<int>{0, 1}(rng)));
            text += ':';
            text += patterns[std::uniform_int_distribution<std::size_t>{0, patterns.size() - 1}(rng)];
        }
        return parsed(text);
    };
    for (int round = 0; round < 2000; ++round) {
        const scope_set a = random_set();
        const scope_set b = random_set();
        const scope_set both = scope_set::intersect(a, b);
        const scope_set reread = parsed(both.to_string());
        for (const scope_kind k : {scope_kind::kLib, scope_kind::kCap}) {
            for (const std::string_view n : names) {
                const bool expected = a.allows(k, n) && b.allows(k, n);
                const bool denied = a.denies(k, n) || b.denies(k, n);
                if (both.allows(k, n) != expected || reread.allows(k, n) != expected || both.denies(k, n) != denied) {
                    FAIL("a = " << a.to_string() << " b = " << b.to_string() << " both = " << both.to_string() << " name = " << n);
                }
            }
        }
    }
}
