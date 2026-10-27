#include <cstddef>
#include <string>
#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/type_list.hpp>

using namespace Rhp::utils;

namespace {

using empty = type_list<>;
using three = type_list<int, double, std::string>;

template <class T>
struct add_pointer {
    using type = T*;
};

template <class T>
struct is_arithmetic : std::is_arithmetic<T> {};

} // namespace

TEST_CASE("type_list size and membership", "[utils][type_list]") {
    STATIC_REQUIRE(size_v<empty> == 0);
    STATIC_REQUIRE(empty::empty());
    STATIC_REQUIRE(size_v<three> == 3);
    STATIC_REQUIRE(contains_v<three, double>);
    STATIC_REQUIRE(!contains_v<three, float>);
    STATIC_REQUIRE(!contains_v<empty, int>);
    STATIC_REQUIRE(index_of_v<three, int> == 0);
    STATIC_REQUIRE(index_of_v<three, std::string> == 2);
}

TEST_CASE("type_list at", "[utils][type_list]") {
    STATIC_REQUIRE(std::is_same_v<at_t<three, 0>, int>);
    STATIC_REQUIRE(std::is_same_v<at_t<three, 2>, std::string>);
    STATIC_REQUIRE(std::is_same_v<at_t<type_list<char>, 0>, char>);
}

TEST_CASE("type_list uniqueness", "[utils][type_list]") {
    STATIC_REQUIRE(is_unique_v<empty>);
    STATIC_REQUIRE(is_unique_v<three>);
    STATIC_REQUIRE(!is_unique_v<type_list<int, double, int>>);
}

TEST_CASE("type_list push concat transform and filter", "[utils][type_list]") {
    STATIC_REQUIRE(std::is_same_v<push_back_t<empty, int>, type_list<int>>);
    STATIC_REQUIRE(std::is_same_v<push_front_t<three, char>, type_list<char, int, double, std::string>>);
    STATIC_REQUIRE(std::is_same_v<concat_t<>, empty>);
    STATIC_REQUIRE(std::is_same_v<concat_t<empty, empty>, empty>);
    STATIC_REQUIRE(std::is_same_v<concat_t<type_list<int>, empty, type_list<char, bool>>, type_list<int, char, bool>>);
    STATIC_REQUIRE(std::is_same_v<transform_t<type_list<int, char>, add_pointer>, type_list<int*, char*>>);
    STATIC_REQUIRE(std::is_same_v<transform_t<empty, add_pointer>, empty>);
    STATIC_REQUIRE(std::is_same_v<filter_t<three, is_arithmetic>, type_list<int, double>>);
    STATIC_REQUIRE(std::is_same_v<filter_t<empty, is_arithmetic>, empty>);
}

TEST_CASE("for_each_type visits in order", "[utils][type_list]") {
    std::size_t total = 0;
    std::size_t order = 0;
    for_each_type<type_list<char, int, double>>([&]<class T>(type_tag<T>) {
        total += sizeof(T);
        order = order * 10 + sizeof(T);
    });
    REQUIRE(total == sizeof(char) + sizeof(int) + sizeof(double));
    REQUIRE(order == 148);

    std::size_t calls = 0;
    for_each_type<empty>([&](auto) { ++calls; });
    REQUIRE(calls == 0);
}
