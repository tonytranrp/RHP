#include <format>
#include <type_traits>
#include <unordered_set>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/ids.hpp>

TEST_CASE("strong ids are distinct types", "[core][ids]") {
    STATIC_REQUIRE(!std::is_convertible_v<Rhp::module_id, Rhp::request_id>);
    STATIC_REQUIRE(!std::is_convertible_v<std::uint64_t, Rhp::module_id>);
    STATIC_REQUIRE(sizeof(Rhp::revision_id) == sizeof(std::uint32_t));
}

TEST_CASE("strong ids compare, hash and format", "[core][ids]") {
    constexpr Rhp::module_id none{};
    STATIC_REQUIRE(!none.valid());
    STATIC_REQUIRE(Rhp::module_id{1} < Rhp::module_id{2});

    std::unordered_set<Rhp::module_id> set{Rhp::module_id{3}, Rhp::module_id{3}, Rhp::module_id{4}};
    REQUIRE(set.size() == 2);
    REQUIRE(std::format("{}", Rhp::session_id{17}) == "17");
}

TEST_CASE("id_generator starts at 1 and never repeats", "[core][ids]") {
    Rhp::id_generator<Rhp::request_id> gen;
    REQUIRE_FALSE(gen.last().valid());
    REQUIRE(gen.next() == Rhp::request_id{1});
    REQUIRE(gen.next() == Rhp::request_id{2});
    REQUIRE(gen.last() == Rhp::request_id{2});
}
