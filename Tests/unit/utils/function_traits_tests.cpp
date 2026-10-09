#include <string>
#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/function_traits.hpp>

using namespace Rhp::utils;

// Declarations only (inspected through decltype, never called); external linkage keeps
// clang's unneeded-internal-declaration warning quiet.
namespace function_traits_fixtures {

int free_fn(float, const std::string&);
void noexcept_fn() noexcept;

struct widget {
    double method(int);
    bool const_method(char, char) const noexcept;
};

} // namespace function_traits_fixtures

using namespace function_traits_fixtures;

TEST_CASE("function_traits on free functions and pointers", "[utils][function_traits]") {
    using traits = function_traits<decltype(free_fn)>;
    STATIC_REQUIRE(std::is_same_v<traits::return_type, int>);
    STATIC_REQUIRE(std::is_same_v<traits::args, type_list<float, const std::string&>>);
    STATIC_REQUIRE(traits::arity == 2);
    STATIC_REQUIRE(!traits::is_noexcept);
    STATIC_REQUIRE(!traits::is_member);

    STATIC_REQUIRE(std::is_same_v<return_type_t<decltype(&free_fn)>, int>);
    STATIC_REQUIRE(function_traits<decltype(&noexcept_fn)>::is_noexcept);
    STATIC_REQUIRE(arity_v<decltype(&noexcept_fn)> == 0);
}

TEST_CASE("function_traits on member function pointers", "[utils][function_traits]") {
    using m = function_traits<decltype(&widget::method)>;
    STATIC_REQUIRE(std::is_same_v<m::return_type, double>);
    STATIC_REQUIRE(std::is_same_v<m::class_type, widget>);
    STATIC_REQUIRE(m::is_member);

    using c = function_traits<decltype(&widget::const_method)>;
    STATIC_REQUIRE(std::is_same_v<c::class_type, const widget>);
    STATIC_REQUIRE(std::is_same_v<c::args, type_list<char, char>>);
    STATIC_REQUIRE(c::is_noexcept);
}

TEST_CASE("function_traits on lambdas", "[utils][function_traits]") {
    auto lambda = [](int a, int b) { return a + b; };
    using l = function_traits<decltype(lambda)>;
    STATIC_REQUIRE(std::is_same_v<l::return_type, int>);
    STATIC_REQUIRE(l::arity == 2);
    STATIC_REQUIRE(!l::is_member);

    const auto& ref = lambda;
    STATIC_REQUIRE(function_traits<decltype(ref)>::arity == 2);
    STATIC_REQUIRE(has_function_traits<decltype(lambda)>);
    STATIC_REQUIRE(!has_function_traits<int>);
}
