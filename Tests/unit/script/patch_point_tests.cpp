#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

namespace patch_point_tests_fixtures {

inline float default_damage(float base, int target) {
    return base * static_cast<float>(target);
}

inline std::string default_greet(std::string name) {
    return "hello " + name;
}

inline constexpr Rhp::patch_point<"tests.patch.damage", &default_damage> damage{};
inline constexpr Rhp::patch_point<"tests.patch.greet", &default_greet> greet{};

using damage_point = Rhp::patch_point<"tests.patch.damage", &default_damage>;

} // namespace patch_point_tests_fixtures

namespace {

namespace fx = patch_point_tests_fixtures;

sandbox make_box() {
    sandbox_options options;
    options.output = [](std::string_view) {};
    return sandbox{std::move(options)};
}

constexpr std::string_view kDouble = R"lua(
    rhp.patch("tests.patch.damage", function(original, base, target) return original(base, target) * 2 end)
)lua";

constexpr std::string_view kPlusOne = R"lua(
    rhp.patch("tests.patch.damage", function(original, base, target) return original(base, target) + 1 end)
)lua";

} // namespace

TEST_CASE("patch point identity", "[script][patch_point]") {
    STATIC_REQUIRE(fx::damage_point::id == "tests.patch.damage");
    STATIC_REQUIRE(fx::damage_point::default_function == &fx::default_damage);
    STATIC_REQUIRE(std::same_as<fx::damage_point::signature, float(float, int)>);
}

TEST_CASE("unpatched points run the default", "[script][patch_point]") {
    CHECK(fx::damage(2.0f, 3) == 6.0f);
    CHECK(fx::greet("bob") == "hello bob");
    CHECK(fx::damage.depth() == 0);
    CHECK_FALSE(fx::damage.patched());
}

TEST_CASE("a module patches a point until it is reverted", "[script][patch_point]") {
    {
        sandbox box = make_box();
        const auto mod = box.load("tests.patch.replace", R"lua(
            rhp.patch("tests.patch.damage", function(original, base, target) return 100 end)
        )lua");
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 100.0f);
        CHECK(fx::damage.depth() == 1);
        CHECK(fx::damage.patched());
        CHECK(box.status(*mod)->effects == 1);

        const auto report = box.revert(*mod);
        REQUIRE(report.has_value());
        CHECK(report->undone == 1);
        CHECK(fx::damage(2.0f, 3) == 6.0f);
        CHECK(fx::damage.depth() == 0);
        CHECK_FALSE(fx::damage.patched());

        // From the scratch module too; strings cross both ways.
        REQUIRE(box.exec(R"lua(
            rhp.patch("tests.patch.greet", function(original, name) return original(name:upper()) .. "!" end)
        )lua"));
        CHECK(fx::greet("bob") == "hello BOB!");
        CHECK(fx::greet.depth() == 1);
    }
    CHECK(fx::greet("bob") == "hello bob");
    CHECK(fx::greet.depth() == 0);
}

TEST_CASE("patches stack and revert in any order", "[script][patch_point]") {
    {
        sandbox box = make_box();
        const auto a = box.load("tests.patch.stack.a", kDouble);
        const auto b = box.load("tests.patch.stack.b", kPlusOne);
        REQUIRE(a.has_value());
        REQUIRE(b.has_value());
        REQUIRE(fx::damage.depth() == 2);
        // b over a over the default: (2 * 3) * 2 + 1.
        CHECK(fx::damage(2.0f, 3) == 13.0f);

        SECTION("revert the lower layer first") {
            REQUIRE(box.revert(*a));
            CHECK(fx::damage.depth() == 1);
            CHECK(fx::damage(2.0f, 3) == 7.0f); // b's original reaches the default directly
            REQUIRE(box.revert(*b));
            CHECK(fx::damage(2.0f, 3) == 6.0f);
        }

        SECTION("revert the top layer first") {
            REQUIRE(box.revert(*b));
            CHECK(fx::damage(2.0f, 3) == 12.0f);
            REQUIRE(box.revert(*a));
            CHECK(fx::damage(2.0f, 3) == 6.0f);
        }

        CHECK(fx::damage.depth() == 0);
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("a failing handler falls back and its module is faulted on pump", "[script][patch_point]") {
    {
        sandbox box = make_box();

        SECTION("alone") {
            const auto bad = box.load("tests.patch.bad", R"lua(
                rhp.patch("tests.patch.damage", function(original, base, target) error("boom") end)
            )lua");
            REQUIRE(bad.has_value());
            CHECK(fx::damage(2.0f, 3) == 6.0f); // the default, no exception

            box.pump();
            const auto info = box.status(*bad);
            REQUIRE(info.has_value());
            CHECK(info->state == module_state::kFaulted);
            CHECK(info->fault.has_value());
            CHECK(fx::damage.depth() == 0);
            CHECK(fx::damage(2.0f, 3) == 6.0f);
        }

        SECTION("over another layer") {
            const auto good = box.load("tests.patch.good", kDouble);
            const auto bad = box.load("tests.patch.bad", R"lua(
                rhp.patch("tests.patch.damage", function(original, base, target) error("boom") end)
            )lua");
            REQUIRE(good.has_value());
            REQUIRE(bad.has_value());
            CHECK(fx::damage(2.0f, 3) == 12.0f); // falls back to the next layer

            box.pump();
            CHECK(box.status(*bad)->state == module_state::kFaulted);
            CHECK(box.status(*good)->state == module_state::kActive);
            CHECK(fx::damage.depth() == 1);
            CHECK(fx::damage(2.0f, 3) == 12.0f);
        }

        SECTION("pump with nothing failed changes nothing") {
            const auto good = box.load("tests.patch.good", kDouble);
            REQUIRE(good.has_value());
            CHECK(fx::damage(2.0f, 3) == 12.0f);
            box.pump();
            CHECK(box.status(*good)->state == module_state::kActive);
            CHECK(fx::damage.depth() == 1);
        }
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("rhp.patch validates its arguments", "[script][patch_point]") {
    {
        sandbox box = make_box();

        const auto unknown = box.exec("rhp.patch('tests.patch.nope', function(original) end)");
        REQUIRE_FALSE(unknown.has_value());
        CHECK(unknown.error().code == errc::kNotFound);

        const auto unknown_load = box.load("tests.patch.unknown", "rhp.patch('tests.patch.nope', function(original) end)");
        REQUIRE_FALSE(unknown_load.has_value());
        CHECK(unknown_load.error().code == errc::kNotFound);

        const auto not_function = box.exec("rhp.patch('tests.patch.damage', 5)");
        REQUIRE_FALSE(not_function.has_value());
        CHECK(not_function.error().code == errc::kTypeMismatch);

        CHECK(fx::damage.depth() == 0);
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("other threads run the default", "[script][patch_point]") {
    {
        sandbox box = make_box();
        REQUIRE(box.load("tests.patch.threaded", kDouble));
        REQUIRE(fx::damage(2.0f, 3) == 12.0f);

        const std::uint64_t misses_before = fx::damage.off_thread_misses();
        float off_thread = 0.0f;
        {
            std::jthread worker{[&off_thread] { off_thread = fx::damage(2.0f, 3); }};
        }
        CHECK(off_thread == 6.0f);
        CHECK(fx::damage.off_thread_misses() == misses_before + 1);

        // The owner thread still sees the patch.
        CHECK(fx::damage(2.0f, 3) == 12.0f);
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("original is only callable while its handler runs", "[script][patch_point]") {
    {
        sandbox box = make_box();
        const auto mod = box.load("tests.patch.escape", R"lua(
            rhp.patch("tests.patch.damage", function(original, base, target)
                saved = original
                return original(base, target)
            end)
            function try_saved() return (pcall(saved, 1, 1)) end
            function use_saved() return saved(1, 1) end
        )lua");
        REQUIRE(mod.has_value());
        REQUIRE(fx::damage(2.0f, 3) == 6.0f); // runs the handler, which leaks `original`

        const auto caught = box.call(*mod, "try_saved");
        REQUIRE(caught.has_value());
        REQUIRE(caught->size() == 1);
        CHECK((*caught)[0] == Rhp::value{false});

        const auto escaped = box.call(*mod, "use_saved");
        REQUIRE_FALSE(escaped.has_value());
        CHECK(escaped.error().code != errc::kOk);
    }
    CHECK(fx::damage.depth() == 0);
}
