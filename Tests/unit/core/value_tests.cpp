#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/value.hpp>

using Rhp::value;

TEST_CASE("value picks the right alternative", "[core][value]") {
    REQUIRE(value{}.is_nil());
    REQUIRE(value{Rhp::nil}.is_nil());
    REQUIRE(value{true}.is_bool());
    REQUIRE(value{42}.is_integer());
    REQUIRE(value{std::uint8_t{7}}.is_integer());
    REQUIRE(value{1.5}.is_number());
    REQUIRE(value{2.5f}.is_number());
    REQUIRE(value{"text"}.is_string());
    REQUIRE(value{std::string{"text"}}.is_string());
    REQUIRE(value{value::bytes{std::byte{1}}}.is_bytes());
    REQUIRE(value{value::array{1, 2}}.is_array());
    REQUIRE(value{value::map{{"k", 1}}}.is_map());
}

TEST_CASE("value string literals never become bool", "[core][value]") {
    const value v{"yes"};
    REQUIRE(v.is_string());
    REQUIRE(*v.get_if<std::string>() == "yes");
}

TEST_CASE("value nests and compares", "[core][value]") {
    const value tree{value::map{
        {"name", "crate"},
        {"pos", value::array{1.0, 2.0, 3.0}},
        {7, value::map{{"inner", true}}},
    }};
    const value same = tree;
    REQUIRE(tree == same);
    REQUIRE_FALSE(tree == value{value::map{}});

    REQUIRE(tree.find("name") != nullptr);
    REQUIRE(*tree.find("name") == value{"crate"});
    REQUIRE(tree.find(value{7})->find("inner")->is_bool());
    REQUIRE(tree.find("missing") == nullptr);
    REQUIRE(value{1}.find("x") == nullptr);
}

TEST_CASE("value kind names", "[core][value]") {
    REQUIRE(Rhp::to_string(value::kind::kInteger) == "integer");
    REQUIRE(Rhp::to_string(value{}.type()) == "nil");
}
