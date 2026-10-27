#include <string_view>
#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/fixed_string.hpp>

using Rhp::utils::fixed_string;

namespace {

template <fixed_string Name>
struct named {
    static constexpr std::string_view name = Name;
};

} // namespace

TEST_CASE("fixed_string works as a template argument", "[utils][fixed_string]") {
    STATIC_REQUIRE(named<"game">::name == "game");
    STATIC_REQUIRE(named<"">::name.empty());
    STATIC_REQUIRE(!std::is_same_v<named<"a">, named<"b">>);
    STATIC_REQUIRE(std::is_same_v<named<"a">, named<"a">>);
}

TEST_CASE("fixed_string size view and comparison", "[utils][fixed_string]") {
    constexpr fixed_string s{"combat.damage"};
    STATIC_REQUIRE(s.size() == 13);
    STATIC_REQUIRE(s.view() == "combat.damage");
    STATIC_REQUIRE(s == fixed_string{"combat.damage"});
    STATIC_REQUIRE(!(s == fixed_string{"combat"}));
    STATIC_REQUIRE(fixed_string{""}.empty());
    REQUIRE(std::string_view{s.c_str()} == "combat.damage");
}

TEST_CASE("is_dotted_name enforces dotted lowercase", "[utils][fixed_string]") {
    using Rhp::utils::is_dotted_name;
    STATIC_REQUIRE(is_dotted_name("combat"));
    STATIC_REQUIRE(is_dotted_name("combat.damage"));
    STATIC_REQUIRE(is_dotted_name("a.b2.c_d"));
    STATIC_REQUIRE(!is_dotted_name(""));
    STATIC_REQUIRE(!is_dotted_name("."));
    STATIC_REQUIRE(!is_dotted_name("combat."));
    STATIC_REQUIRE(!is_dotted_name(".combat"));
    STATIC_REQUIRE(!is_dotted_name("combat..damage"));
    STATIC_REQUIRE(!is_dotted_name("Combat.damage"));
    STATIC_REQUIRE(!is_dotted_name("combat.2nd"));
    STATIC_REQUIRE(!is_dotted_name("combat-damage"));
    STATIC_REQUIRE(!is_dotted_name("_private"));
}

TEST_CASE("is_identifier accepts Lua identifiers", "[utils][fixed_string]") {
    using Rhp::utils::is_identifier;
    STATIC_REQUIRE(is_identifier("spawn"));
    STATIC_REQUIRE(is_identifier("_tmp"));
    STATIC_REQUIRE(is_identifier("dumpState2"));
    STATIC_REQUIRE(!is_identifier(""));
    STATIC_REQUIRE(!is_identifier("2fast"));
    STATIC_REQUIRE(!is_identifier("a.b"));
    STATIC_REQUIRE(!is_identifier("a b"));
}
