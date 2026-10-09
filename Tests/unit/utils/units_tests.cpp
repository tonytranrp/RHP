#include <cstddef>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/units.hpp>

using namespace Rhp::literals;

TEST_CASE("size literals", "[utils][units]") {
    STATIC_REQUIRE(1_KiB == 1024);
    STATIC_REQUIRE(4_MiB == std::size_t{4} * 1024 * 1024);
    STATIC_REQUIRE(1_GiB == std::size_t{1024} * 1024 * 1024);
    STATIC_REQUIRE(0_MiB == 0);
}
