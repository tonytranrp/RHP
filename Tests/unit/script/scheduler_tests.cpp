#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

namespace scheduler_tests_fixtures {

inline int g_counter = 0;

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>;

inline constexpr Rhp::lua_event<"tests.sched.ping", int, std::string_view> ping{};

} // namespace scheduler_tests_fixtures

namespace {

namespace fx = scheduler_tests_fixtures;

struct capture {
    std::vector<std::string> lines;
    std::vector<std::pair<Rhp::request_id, Rhp::result<Rhp::script::value_list>>> results;
    std::vector<Rhp::value> emitted;
};

sandbox make_box(capture& out, Rhp::limits limits = {}) {
    fx::g_counter = 0;
    sandbox_options options;
    options.limits = limits;
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_result = [&out](Rhp::request_id id, const Rhp::result<Rhp::script::value_list>& r) { out.results.emplace_back(id, r); };
    options.on_emit = [&out](Rhp::request_id, Rhp::module_id, const Rhp::value& v) { out.emitted.push_back(v); };
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::counter_lib>());
    return box;
}

} // namespace

TEST_CASE("smoke: next_frame spreads work over pumps", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto r = box.exec("for i = 1, 3 do counter.value = counter.value + 1 rhp.next_frame() end return 'done'");
    REQUIRE(r.has_value());
    CHECK(r->empty());
    CHECK(fx::g_counter == 1);
    CHECK(box.suspended() == 1);
    box.pump();
    CHECK(fx::g_counter == 2);
    box.pump();
    CHECK(fx::g_counter == 3);
    box.pump();
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    REQUIRE(out.results[0].second.has_value());
    CHECK(out.results[0].second->at(0) == Rhp::value{"done"});
}

TEST_CASE("smoke: slicing keeps an infinite loop from blocking", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.slice_us = 2'000;
    sandbox box = make_box(out, limits);
    const auto started = std::chrono::steady_clock::now();
    const auto r = box.exec("while true do end");
    REQUIRE(r.has_value());
    for (int i = 0; i < 5; ++i) {
        box.pump();
    }
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds{2});
    CHECK(box.suspended() == 1);
    box.cancel(box.last_request());
    box.pump();
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    REQUIRE_FALSE(out.results[0].second.has_value());
    CHECK(out.results[0].second.error().code == errc::kCancelled);
}

TEST_CASE("smoke: reload keeps state through on_save / on_restore", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.reload", R"lua(
        local M = { hits = 0 }
        counter.value = 10
        function M.hit() M.hits = M.hits + 1 return M.hits end
        function M.on_save() return M.hits end
        return M
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "hit"));
    REQUIRE(box.call(*mod, "hit"));
    const auto rev = box.reload(*mod, R"lua(
        local M = { hits = 0 }
        counter.value = 20
        function M.hit() M.hits = M.hits + 100 return M.hits end
        function M.on_restore(saved) M.hits = saved end
        return M
    )lua");
    REQUIRE(rev.has_value());
    CHECK(*rev == Rhp::revision_id{2});
    CHECK(fx::g_counter == 20);
    const auto hit = box.call(*mod, "hit");
    REQUIRE(hit.has_value());
    CHECK(hit->at(0) == Rhp::value{102});
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_counter == 0);

    // A failing reload leaves the live revision alone.
    REQUIRE(box.reload(*mod, "counter.value = 5 return {}"));
    CHECK(fx::g_counter == 5);
    const auto bad = box.reload(*mod, "counter.value = 7 error('nope')");
    REQUIRE_FALSE(bad.has_value());
    CHECK(fx::g_counter == 5);
    CHECK(box.status(*mod)->state == module_state::kActive);
    const auto back = box.rollback(*mod, 1); // revision 2's source again
    REQUIRE(back.has_value());
    CHECK(fx::g_counter == 20);
}

TEST_CASE("smoke: require, cycles and force unload", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto a = box.load("tests.sched.a", "return { value = function() return 1 end }");
    REQUIRE(a.has_value());
    const auto b = box.load("tests.sched.b", "local a = require('tests.sched.a') return { get = function() return a.value() end }");
    REQUIRE(b.has_value());
    CHECK(box.call(*b, "get")->at(0) == Rhp::value{1});
    REQUIRE(box.reload(*a, "return { value = function() return 2 end }"));
    CHECK(box.call(*b, "get")->at(0) == Rhp::value{2});
    const auto cyc = box.reload(*a, "local b = require('tests.sched.b') return { value = function() return 3 end }");
    REQUIRE_FALSE(cyc.has_value());
    CHECK(cyc.error().message.find("cycle") != std::string::npos);
    const auto refused = box.unload(*a);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().code == errc::kHasDependents);
    REQUIRE(box.unload(*a, Rhp::script::force));
    const auto dead = box.call(*b, "get");
    REQUIRE_FALSE(dead.has_value());
    CHECK(dead.error().code == errc::kUnloaded);
}

TEST_CASE("smoke: events, timers, emit", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.events", R"lua(
        rhp.on("tests.sched.ping", function(n, text) counter.value = counter.value + n rhp.emit(text) end)
        rhp.timer(0, function() print("tick") end)
    )lua");
    REQUIRE(mod.has_value());
    fx::ping.fire(5, "hello");
    CHECK(fx::g_counter == 5);
    REQUIRE(out.emitted.size() == 1);
    CHECK(out.emitted[0] == Rhp::value{"hello"});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"tick"});
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_counter == 0);
    CHECK(fx::ping.listeners() == 0);
    fx::ping.fire(5, "again");
    CHECK(fx::g_counter == 0);
}
