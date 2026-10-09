#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/scope_guard.hpp>

TEST_CASE("scope_guard runs on scope exit", "[utils][scope_guard]") {
    int calls = 0;
    {
        Rhp::utils::scope_guard guard{[&] { ++calls; }};
        REQUIRE(guard.active());
        REQUIRE(calls == 0);
    }
    REQUIRE(calls == 1);
}

TEST_CASE("scope_guard release cancels the callback", "[utils][scope_guard]") {
    int calls = 0;
    {
        Rhp::utils::scope_guard guard{[&] { ++calls; }};
        guard.release();
        REQUIRE_FALSE(guard.active());
    }
    REQUIRE(calls == 0);
}

TEST_CASE("scope_guard runs during exception unwinding", "[utils][scope_guard]") {
    int calls = 0;
    try {
        Rhp::utils::scope_guard guard{[&] { ++calls; }};
        throw 42;
    } catch (int) {
    }
    REQUIRE(calls == 1);
}
