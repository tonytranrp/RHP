#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/script_support.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::role;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace {

sandbox make_box(role caller = role::kPatch) {
    sandbox_options options;
    options.caller_role = caller;
    options.output = [](std::string_view) {};
    return sandbox{std::move(options)};
}

using rhp_test::code_of;

// A call's values, or one string describing its error (readable in a failed CHECK).
value_list values(const Rhp::result<value_list>& r) {
    return r ? *r : value_list{Rhp::value{"error: " + r.error().message}};
}

constexpr std::string_view kA = "return { n = 1, f = function() return 'a1' end }";

constexpr std::string_view kB = R"lua(
    local a = require("tests.req.a")
    function get() return a.n, a.f() end
    function same() return require("tests.req.a") == a, rawequal(require("tests.req.a"), a) end
    function name() return tostring(a) end
    function kind() return type(a) end
    function poke() a.n = 5 end
    function later() return a.n end
)lua";

} // namespace

TEST_CASE("require returns a cached read-only proxy of a loaded module", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    const auto b = box.load("tests.req.b", kB);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    CHECK(values(box.call(*b, "get")) == value_list{Rhp::value{1}, Rhp::value{"a1"}});
    CHECK(values(box.call(*b, "same")) == value_list{Rhp::value{true}, Rhp::value{true}});
    CHECK(values(box.call(*b, "name")) == value_list{Rhp::value{"module: tests.req.a"}});
    CHECK(values(box.call(*b, "kind")) == value_list{Rhp::value{"userdata"}});
    CHECK(box.exec<bool>("return require('tests.req.a') == require('tests.req.a')") == true);

    const auto poke = box.call(*b, "poke");
    REQUIRE_FALSE(poke.has_value());
    CHECK(poke.error().code == errc::kInvalidArgument);
    CHECK(box.status(*b)->state == module_state::kFaulted);
    CHECK(code_of(box.exec("require('tests.req.a').n = 2")) == errc::kInvalidArgument);
    CHECK(box.exec<int>("return require('tests.req.a').n") == 1);
    CHECK(code_of(box.exec("return getmetatable(require('tests.req.a'))")) == errc::kOk);
    CHECK(code_of(box.exec("setmetatable(require('tests.req.a'), {})")) != errc::kOk);
}

TEST_CASE("the proxy always reads the current revision", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    const auto b = box.load("tests.req.b", kB);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(box.reload(*a, "return { n = 2, f = function() return 'a2' end }"));
    CHECK(values(box.call(*b, "get")) == value_list{Rhp::value{2}, Rhp::value{"a2"}});
    REQUIRE(box.rollback(*a));
    CHECK(values(box.call(*b, "get")) == value_list{Rhp::value{1}, Rhp::value{"a1"}});

    // A module that returns nothing exports its environment.
    const auto env = box.load("tests.req.env", "value = 7 function get() return value end");
    REQUIRE(env.has_value());
    CHECK(box.exec<int>("local e = require('tests.req.env') return e.value + e.get()") == 14);
}

TEST_CASE("require only finds loaded modules of this identity", "[script][require]") {
    for (const role caller : {role::kObserve, role::kPatch, role::kAdmin}) {
        CAPTURE(caller);
        sandbox box = make_box(caller);
        CHECK(code_of(box.exec("return require('os')")) == errc::kNotFound);
        CHECK(code_of(box.exec("return require('string')")) == errc::kNotFound);
        CHECK(code_of(box.exec("return require('tests.req.nope')")) == errc::kNotFound);
        CHECK(code_of(box.exec("return require(5)")) == errc::kTypeMismatch);
    }

    sandbox other = make_box();
    REQUIRE(other.load("tests.req.elsewhere", "return { n = 1 }"));
    sandbox box = make_box();
    CHECK(code_of(box.exec("return require('tests.req.elsewhere')")) == errc::kNotFound);
}

TEST_CASE("a module can't require itself or a module that is still loading", "[script][require]") {
    sandbox box = make_box();
    const auto self = box.load("tests.req.self", "local me = require('tests.req.self') return {}");
    REQUIRE_FALSE(self.has_value());
    CHECK(self.error().code == errc::kInvalidArgument);

    const auto slow = box.load("tests.req.slow", "rhp.next_frame() return { n = 3 }");
    REQUIRE(slow.has_value());
    REQUIRE(box.status(*slow)->state == module_state::kLoading);
    const auto eager = box.load("tests.req.eager", "local s = require('tests.req.slow') return {}");
    REQUIRE_FALSE(eager.has_value());
    CHECK(eager.error().code == errc::kInvalidArgument);
    CHECK(code_of(box.exec("return require('tests.req.slow')")) == errc::kInvalidArgument);

    box.pump();
    REQUIRE(box.status(*slow)->state == module_state::kActive);
    const auto patient = box.load("tests.req.patient", "local s = require('tests.req.slow') function get() return s.n end");
    REQUIRE(patient.has_value());
    CHECK(values(box.call(*patient, "get")) == value_list{Rhp::value{3}});
}

TEST_CASE("require records dependencies and unload checks them", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    const auto b = box.load("tests.req.b", kB);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(box.status(*b)->dependencies == std::vector<Rhp::module_id>{*a});
    CHECK(box.status(*a)->dependencies.empty());

    const auto refused = box.unload(*a);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().code == errc::kHasDependents);
    CHECK(refused.error().message.find("tests.req.b") != std::string::npos);
    CHECK(box.status(*a)->state == module_state::kActive);

    // Reverting doesn't care about dependents.
    REQUIRE(box.revert(*a));

    REQUIRE(box.unload(*b));
    REQUIRE(box.unload(*a)); // nobody requires it any more
}

TEST_CASE("kUnloaded keeps its name and value after the release codes", "[script][require]") {
    STATIC_REQUIRE(Rhp::to_string(errc::kUnloaded) == "unloaded");
    STATIC_REQUIRE(static_cast<int>(errc::kUnloaded) + 4 == static_cast<int>(Rhp::kLastErrc));
    STATIC_REQUIRE(Rhp::kLastErrc == errc::kOutOfScope);
}

TEST_CASE("the scratch module records no dependencies", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    REQUIRE(a.has_value());
    CHECK(box.exec<int>("held = require('tests.req.a') return held.n") == 1);
    CHECK(box.status(box.scratch_module())->dependencies.empty());
    REQUIRE(box.unload(*a));
    CHECK(code_of(box.exec("return held.n")) == errc::kUnloaded);
}

TEST_CASE("force unload leaves dependents loaded; touching the module raises kUnloaded", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    const auto b = box.load("tests.req.b", kB);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    const auto report = box.unload(*a, Rhp::script::force);
    REQUIRE(report.has_value());
    CHECK_FALSE(report->deferred);
    CHECK_FALSE(box.find("tests.req.a").has_value());
    CHECK(box.status(*b)->state == module_state::kActive);
    CHECK(box.status(*b)->dependencies.empty());

    CHECK(values(box.call(*b, "name")) == value_list{Rhp::value{"module: tests.req.a"}}); // the name outlives it
    const auto later = box.call(*b, "later");
    REQUIRE_FALSE(later.has_value());
    CHECK(later.error().code == errc::kUnloaded);
    CHECK(box.status(*b)->state == module_state::kFaulted);
    CHECK(code_of(box.exec("return require('tests.req.a')")) == errc::kNotFound);

    // Reloading the dependent needs the module back; once it is, the dependent works again.
    CHECK(code_of(box.reload(*b, kB)) == errc::kNotFound);
    REQUIRE(box.load("tests.req.a", kA));
    REQUIRE(box.reload(*b, kB));
    CHECK(values(box.call(*b, "get")) == value_list{Rhp::value{1}, Rhp::value{"a1"}});
}

TEST_CASE("require cycles fail with the path", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    const auto b = box.load("tests.req.b", kB);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());

    SECTION("two modules") {
        const auto r = box.reload(*a, "local b = require('tests.req.b') return { n = 9 }");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kInvalidArgument);
        CHECK(r.error().message == "require cycle: tests.req.a -> tests.req.b -> tests.req.a");
    }

    SECTION("three modules") {
        const auto c = box.load("tests.req.c", "local b = require('tests.req.b') return {}");
        REQUIRE(c.has_value());
        const auto r = box.reload(*a, "local c = require('tests.req.c') return { n = 9 }");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kInvalidArgument);
        CHECK(r.error().message == "require cycle: tests.req.a -> tests.req.c -> tests.req.b -> tests.req.a");
    }

    SECTION("at run time") {
        REQUIRE(box.reload(*a, "return { n = 1, f = function() return 'a1' end, lazy = function() return require('tests.req.b') end }"));
        const auto r = box.call(*a, "lazy");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kInvalidArgument);
        CHECK(r.error().message.find("require cycle") != std::string::npos);
        CHECK(box.status(*a)->state == module_state::kFaulted);
        CHECK(box.status(*a)->dependencies.empty());
        return;
    }

    const auto info = box.status(*a);
    CHECK(info->state == module_state::kActive);
    CHECK(info->revision == Rhp::revision_id{1});
    CHECK(info->dependencies.empty());
    CHECK(values(box.call(*b, "get")) == value_list{Rhp::value{1}, Rhp::value{"a1"}});
}

TEST_CASE("dependencies belong to a revision", "[script][require]") {
    sandbox box = make_box();
    const auto a = box.load("tests.req.a", kA);
    const auto c = box.load("tests.req.c", "return { n = 3 }");
    const auto b = box.load("tests.req.b", kB);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(c.has_value());

    SECTION("a reload that drops the require drops the edge") {
        REQUIRE(box.reload(*b, "return {}"));
        CHECK(box.status(*b)->dependencies.empty());
        CHECK(box.unload(*a).has_value());
    }

    SECTION("a failed reload adds no edge") {
        REQUIRE_FALSE(box.reload(*b, "local c = require('tests.req.c') error('no')").has_value());
        CHECK(box.status(*b)->dependencies == std::vector<Rhp::module_id>{*a});
        CHECK(box.unload(*c).has_value());
    }

    SECTION("a reload in flight already counts as a dependent") {
        REQUIRE(box.reload(*b, "local c = require('tests.req.c') rhp.next_frame() return {}"));
        REQUIRE(box.status(*b)->reloading);
        CHECK(code_of(box.unload(*c)) == errc::kHasDependents);
        CHECK(code_of(box.unload(*a)) == errc::kHasDependents); // the live revision still requires a
        box.pump();
        CHECK(box.status(*b)->dependencies == std::vector<Rhp::module_id>{*c});
        CHECK(code_of(box.unload(*c)) == errc::kHasDependents);
        CHECK(box.unload(*a).has_value());
    }
}
