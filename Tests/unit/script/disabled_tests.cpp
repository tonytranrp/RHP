// Built only with RHP_ENABLE=OFF: the sandbox is an inert stub and patch points are direct calls.
#include <catch2/catch_test_macros.hpp>

#include <rhp/script/lib.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

namespace disabled_tests_fixtures {

inline int g_value = 1;

inline int triple(int x) {
    return 3 * x;
}

using lib = Rhp::lib<"off">::fn<"triple", &triple>::var<"value", &g_value>;

inline constexpr Rhp::patch_point<"tests.disabled.triple", &triple> point{};

} // namespace disabled_tests_fixtures

TEST_CASE("disabled patch points call the default directly", "[script][disabled]") {
    using namespace disabled_tests_fixtures;
    STATIC_REQUIRE(RHP_ENABLE == 0);
    REQUIRE(point(4) == 12);
    REQUIRE(decltype(point)::depth() == 0);
    REQUIRE_FALSE(decltype(point)::patched());
    REQUIRE(decltype(point)::off_thread_misses() == 0);
}

TEST_CASE("disabled sandbox reports kDisabled", "[script][disabled]") {
    Rhp::script::sandbox box;
    REQUIRE(box.install<disabled_tests_fixtures::lib>().error().code == Rhp::errc::kDisabled);
    REQUIRE(box.exec("return 1").error().code == Rhp::errc::kDisabled);
    REQUIRE(box.exec<int>("return 1").error().code == Rhp::errc::kDisabled);
    REQUIRE(box.load("mod", "").error().code == Rhp::errc::kDisabled);
    REQUIRE(box.list().empty());
    REQUIRE(box.revert_all().undone == 0);
    REQUIRE(box.memory_used() == 0);
}
