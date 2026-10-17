// Built only with RHP_ENABLE=OFF: the sandbox is an inert stub and patch points are direct calls.
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
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

TEST_CASE("disabled reload, rollback and unload report kDisabled", "[script][disabled]") {
    Rhp::script::sandbox box;
    const Rhp::module_id mod{1};
    REQUIRE(box.reload(mod, "return {}").error().code == Rhp::errc::kDisabled);
    REQUIRE(box.rollback(mod).error().code == Rhp::errc::kDisabled);
    REQUIRE(box.rollback(mod, 2).error().code == Rhp::errc::kDisabled);
    REQUIRE(box.unload(mod).error().code == Rhp::errc::kDisabled);
    REQUIRE(box.unload(mod, Rhp::script::force).error().code == Rhp::errc::kDisabled);
    REQUIRE(box.revert(mod).error().code == Rhp::errc::kDisabled);
    REQUIRE(box.call(mod, "f").error().code == Rhp::errc::kDisabled);
    REQUIRE(box.checkpoint("tag").error().code == Rhp::errc::kDisabled);
    REQUIRE(box.revert_to("tag").error().code == Rhp::errc::kDisabled);
    REQUIRE_FALSE(box.revert_all().deferred);
}

TEST_CASE("disabled scheduler is inert", "[script][disabled]") {
    Rhp::script::sandbox box;
    box.pump();
    box.cancel();
    box.cancel(Rhp::request_id{1});
    REQUIRE(box.frame() == 0);
    REQUIRE(box.suspended() == 0);
    REQUIRE_FALSE(box.last_request().valid());
    REQUIRE(box.stubs().empty());
    REQUIRE(box.effects().empty());
}

namespace disabled_tests_fixtures {

inline constexpr Rhp::lua_event<"tests.disabled.ping", int, std::string_view> ping{};

} // namespace disabled_tests_fixtures

TEST_CASE("disabled lua_event fire is a no-op", "[script][disabled]") {
    using namespace disabled_tests_fixtures;
    STATIC_REQUIRE(decltype(ping)::arity == 2);
    STATIC_REQUIRE(decltype(ping)::name == "tests.disabled.ping");
    ping.fire(1, "nobody");
    REQUIRE(decltype(ping)::listeners() == 0);
}

TEST_CASE("disabled sandbox stats are zero and on_script_event never fires", "[script][disabled]") {
    Rhp::script::sandbox box;
    int calls = 0;
    auto sub = box.on_script_event("*", [&](const Rhp::script::script_event&) { ++calls; });
    box.pump();
    CHECK(calls == 0);
    CHECK_FALSE(sub.active());
    const auto st = box.stats();
    CHECK(st.dropped_events == 0);
    CHECK(st.tasks == 0);
    CHECK(st.handler_failures == 0);
}
