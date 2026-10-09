#include <type_traits>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/errors_mode.hpp>

namespace {

// How front-end APIs use the policy: compute a result, let the mode decide the public shape.
template <Rhp::errors::mode Mode>
typename Mode::template return_t<int> lookup(bool ok) {
    Rhp::result<int> r = ok ? Rhp::result<int>{42} : Rhp::result<int>{Rhp::fail(Rhp::errc::kNotFound)};
    return Mode::finish(std::move(r));
}

} // namespace

TEST_CASE("expected mode returns Rhp::result", "[core][errors_mode]") {
    STATIC_REQUIRE(Rhp::errors::mode<Rhp::errors::expected>);
    STATIC_REQUIRE(std::is_same_v<decltype(lookup<Rhp::errors::expected>(true)), Rhp::result<int>>);
    REQUIRE(lookup<Rhp::errors::expected>(true) == 42);
    REQUIRE_FALSE(lookup<Rhp::errors::expected>(false).has_value());
}

TEST_CASE("throwing mode returns T and throws", "[core][errors_mode]") {
    STATIC_REQUIRE(Rhp::errors::mode<Rhp::errors::throwing>);
    STATIC_REQUIRE(std::is_same_v<decltype(lookup<Rhp::errors::throwing>(true)), int>);
    REQUIRE(lookup<Rhp::errors::throwing>(true) == 42);
    REQUIRE_THROWS_AS(lookup<Rhp::errors::throwing>(false), Rhp::exception);
}
