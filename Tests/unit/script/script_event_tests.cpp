#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace script_event_tests_fixtures {

inline constexpr Rhp::lua_event<"tests.sevents.cpp", int> cpp_event{};

inline int base_value(int x) {
    return x;
}

inline constexpr Rhp::patch_point<"tests.sevents.value", &base_value> value_point{};

} // namespace script_event_tests_fixtures

namespace {

namespace fx = script_event_tests_fixtures;
using std::chrono::milliseconds;

struct manual_clock {
    std::chrono::steady_clock::time_point now = std::chrono::steady_clock::time_point{} + std::chrono::hours{1};

    void advance(milliseconds ms) { now += ms; }
    [[nodiscard]] Rhp::script::clock_fn fn() {
        return [this] { return now; };
    }
};

struct capture {
    std::vector<std::string> lines;
    std::vector<Rhp::script::handler_failure> failures;
};

sandbox make_box(capture& out, Rhp::limits limits = {}, Rhp::script::clock_fn clock = {}) {
    sandbox_options options;
    options.limits = limits;
    options.clock = std::move(clock);
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    return sandbox{std::move(options)};
}

template <class T>
errc code_of(const Rhp::result<T>& r) {
    return r ? errc::kOk : r.error().code;
}

std::vector<std::string> lines(std::initializer_list<const char*> items) {
    return {items.begin(), items.end()};
}

} // namespace

TEST_CASE("rhp.publish delivers to subscribers at the next pump", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.listener", "rhp.on('game.round_over', function(winner, score) print(winner .. ' ' .. score) end)"));
    const auto publisher = box.load("tests.sevents.publisher", "function finish() return rhp.publish('game.round_over', 'red', 3) end");
    REQUIRE(publisher.has_value());
    CHECK(*box.call(*publisher, "finish") == value_list{Rhp::value{true}});
    CHECK(out.lines.empty());
    box.pump();
    CHECK(out.lines == lines({"red 3"}));
    box.pump();
    CHECK(out.lines.size() == 1);
}

TEST_CASE("published values are copies", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.copy_listener", "rhp.on('game.state', function(t) print(t.hp) end)"));
    REQUIRE(box.exec("local t = {hp = 10} rhp.publish('game.state', t) t.hp = 0"));
    box.pump();
    CHECK(out.lines == lines({"10"}));
}

TEST_CASE("rhp.publish refuses C++ event names and the rhp prefix", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    fx::cpp_event.fire(0); // registers the name
    CHECK(code_of(box.exec("rhp.publish('tests.sevents.cpp', 1)")) == errc::kForbidden);
    CHECK(code_of(box.exec("rhp.publish('rhp.handler_failed', {})")) == errc::kForbidden);
    CHECK(code_of(box.exec("rhp.publish('Bad Name')")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.publish(5)")) == errc::kTypeMismatch);
}

TEST_CASE("rhp.publish refuses values that do not convert", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    CHECK(code_of(box.exec("rhp.publish('game.bad', function() end)")) == errc::kTypeMismatch);
    CHECK(code_of(box.exec("rhp.publish('game.bad', coroutine.create(function() end))")) == errc::kTypeMismatch);
    CHECK(box.stats().queued_events == 0);
}

TEST_CASE("events published during delivery wait for the next pump", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.ping", "rhp.on('game.ping', function(n) print('ping ' .. n) rhp.publish('game.pong', n + 1) end)"));
    REQUIRE(box.load("tests.sevents.pong", "rhp.on('game.pong', function(n) print('pong ' .. n) if n < 5 then rhp.publish('game.ping', n + 1) end end)"));
    REQUIRE(box.exec("rhp.publish('game.ping', 1)"));
    box.pump();
    CHECK(out.lines == lines({"ping 1"}));
    box.pump();
    CHECK(out.lines == lines({"ping 1", "pong 2"}));
    for (int i = 0; i < 5; ++i) {
        box.pump();
    }
    CHECK(out.lines == lines({"ping 1", "pong 2", "ping 3", "pong 4", "ping 5", "pong 6"}));
}

TEST_CASE("rhp.once delivers once and leaves the ledger", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sevents.once", R"lua(
        id = rhp.once("game.tick", function(n) print("once " .. n) end)
        function try_off() return (pcall(rhp.off, id)) end
    )lua");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->effects == 1);
    REQUIRE(box.exec("rhp.publish('game.tick', 1) rhp.publish('game.tick', 2)"));
    box.pump();
    CHECK(out.lines == lines({"once 1"}));
    CHECK(box.status(*mod)->effects == 0);
    CHECK(*box.call(*mod, "try_off") == value_list{Rhp::value{false}});
}

TEST_CASE("priority orders handlers and ties keep subscription order", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.prio_a", R"lua(
        rhp.on("game.order", function() print("a0") end)
        rhp.on("game.order", function() print("a5") end, {priority = 5})
    )lua"));
    REQUIRE(box.load("tests.sevents.prio_b", R"lua(
        rhp.on("game.order", function() print("b0") end)
        rhp.on("game.order", function() print("b-1") end, {priority = -1})
        rhp.on("game.order", function() print("b5") end, {priority = 5})
    )lua"));
    REQUIRE(box.exec("rhp.publish('game.order')"));
    box.pump();
    CHECK(out.lines == lines({"a5", "b5", "a0", "b0", "b-1"}));
}

TEST_CASE("the event queue cap drops events and counts them", "[script][script_events]") {
    capture out;
    Rhp::limits limits;
    limits.event_queue = 2;
    sandbox box = make_box(out, limits);
    REQUIRE(box.load("tests.sevents.capped", "rhp.on('tests.sevents.cpp', function(n) print('cpp ' .. n) end) rhp.on('game.capped', function(n) print('script ' .. n) end)"));
    const auto r = box.exec("return rhp.publish('game.capped', 1), rhp.publish('game.capped', 2), rhp.publish('game.capped', 3)");
    CHECK(*r == value_list{Rhp::value{true}, Rhp::value{true}, Rhp::value{false}});
    std::thread other{[] {
        for (int i = 0; i < 3; ++i) {
            fx::cpp_event.fire(i);
        }
    }};
    other.join();
    CHECK(box.stats().dropped_events == 2);
    CHECK(box.stats().queued_events == 4);
    box.pump();
    CHECK(out.lines == lines({"cpp 0", "cpp 1", "script 1", "script 2"}));
    const auto seen = box.exec("return rhp.stats().dropped_events");
    CHECK(*seen == value_list{Rhp::value{2}});
}

TEST_CASE("rhp.stats and sandbox stats agree", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.stats", R"lua(
        rhp.every_frame(function() end)
        rhp.on("game.any", function() end)
        rhp.spawn(function() rhp.wait_event("game.never") end)
    )lua"));
    box.pump();
    const auto st = box.stats();
    CHECK(st.schedule_entries == 1);
    CHECK(st.subscriptions == 1);
    CHECK(st.tasks == 1);
    CHECK(st.waiting == 1);
    const auto r = box.exec("local s = rhp.stats() return s.timers, s.subscriptions, s.tasks, s.waiting, s.memory > 0");
    CHECK(*r == value_list{Rhp::value{1}, Rhp::value{1}, Rhp::value{1}, Rhp::value{1}, Rhp::value{true}});
}

TEST_CASE("on_script_event receives publishes until the subscription dies", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.lua_side", "rhp.on('game.score', function() print('lua') end)"));
    struct seen_event {
        std::string name;
        std::string module;
        value_list args;
    };
    std::vector<seen_event> seen;
    Rhp::subscription sub = box.on_script_event("game.score", [&](const Rhp::script::script_event& e) {
        seen.push_back(seen_event{std::string{e.name}, std::string{e.module_name}, value_list{e.args.begin(), e.args.end()}});
        out.lines.emplace_back("cpp");
    });
    const auto publisher = box.load("tests.sevents.scorer", "function score(n) rhp.publish('game.score', n, 'pts') rhp.publish('game.other') end");
    REQUIRE(publisher.has_value());
    REQUIRE(box.call(*publisher, "score", 7));
    box.pump();
    REQUIRE(seen.size() == 1);
    CHECK(seen[0].name == "game.score");
    CHECK(seen[0].module == "tests.sevents.scorer");
    CHECK(seen[0].args == value_list{Rhp::value{7}, Rhp::value{"pts"}});
    CHECK(out.lines == lines({"lua", "cpp"}));
    sub.reset();
    REQUIRE(box.call(*publisher, "score", 8));
    box.pump();
    CHECK(seen.size() == 1);
}

TEST_CASE("on_script_event with a star receives every name", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    std::vector<std::string> names;
    auto sub = box.on_script_event("*", [&](const Rhp::script::script_event& e) { names.emplace_back(e.name); });
    REQUIRE(box.exec("rhp.publish('game.a') rhp.publish('game.b')"));
    box.pump();
    CHECK(names == lines({"game.a", "game.b"}));
}

TEST_CASE("a subscription may outlive its sandbox", "[script][script_events]") {
    capture out;
    Rhp::subscription sub;
    {
        sandbox box = make_box(out);
        sub = box.on_script_event("game.x", [](const Rhp::script::script_event&) {});
        CHECK(sub.active());
    }
    CHECK_FALSE(sub.active());
    sub.reset();
}

TEST_CASE("on_script_event may re-enter the sandbox", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    auto sub = box.on_script_event("game.reenter", [&](const Rhp::script::script_event&) { (void)box.exec("print('re-entered')"); });
    REQUIRE(box.exec("rhp.publish('game.reenter')"));
    box.pump();
    CHECK(out.lines == lines({"re-entered"}));
}

TEST_CASE("wait_event returns true and the arguments of the next delivery", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec(R"lua(
        rhp.spawn(function()
            local fired, a, b, c = rhp.wait_event("game.go")
            print(tostring(fired) .. " " .. a .. " " .. tostring(b) .. " " .. c)
        end)
    )lua"));
    box.pump();
    REQUIRE(box.exec("rhp.publish('game.go', 'x', nil, 'z')"));
    box.pump();
    CHECK(out.lines == lines({"true x nil z"}));
}

TEST_CASE("wait_event times out with false and timeout", "[script][script_events]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.exec("rhp.spawn(function() print(rhp.wait_event('game.late', 100)) end)"));
    box.pump();
    clock.advance(milliseconds{99});
    box.pump();
    CHECK(out.lines.empty());
    clock.advance(milliseconds{1});
    box.pump();
    CHECK(out.lines == lines({"false\ttimeout"}));
    CHECK(box.stats().waiting == 0);
    REQUIRE(box.exec("rhp.publish('game.late')"));
    box.pump();
    CHECK(out.lines.size() == 1);
}

TEST_CASE("wait_event works at the top level of exec and in timer handlers and tasks", "[script][script_events]") {
    capture out;
    std::vector<std::pair<Rhp::request_id, Rhp::result<value_list>>> results;
    sandbox_options options;
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_result = [&results](Rhp::request_id id, const Rhp::result<value_list>& r) { results.emplace_back(id, r); };
    sandbox box{std::move(options)};
    const auto started = box.exec("local ok, v = rhp.wait_event('game.top') return v * 2");
    CHECK(started.has_value());
    const Rhp::request_id top = box.last_request();
    REQUIRE(box.load("tests.sevents.timer_wait", "rhp.after(0, function() local _, v = rhp.wait_event('game.top') print('timer ' .. v) end)"));
    REQUIRE(box.exec("rhp.spawn(function() local _, v = rhp.wait_event('game.top') print('task ' .. v) end)"));
    box.pump();
    REQUIRE(box.exec("rhp.publish('game.top', 21)"));
    box.pump();
    CHECK(std::ranges::is_permutation(out.lines, lines({"timer 21", "task 21"}))); // resume order is round robin
    const auto mine = std::ranges::find(results, top, &std::pair<Rhp::request_id, Rhp::result<value_list>>::first);
    REQUIRE(mine != results.end());
    REQUIRE(mine->second.has_value());
    CHECK(*mine->second == value_list{Rhp::value{42}});
}

TEST_CASE("wait_event waits for C++ events without a subscription", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("rhp.spawn(function() local _, n = rhp.wait_event('tests.sevents.cpp') print('cpp ' .. n) end)"));
    box.pump();
    CHECK(fx::cpp_event.listeners() == 1);
    fx::cpp_event.fire(9);
    box.pump();
    CHECK(out.lines == lines({"cpp 9"}));
    CHECK(fx::cpp_event.listeners() == 0);
}

TEST_CASE("wait_event is refused outside a request thread", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.patcher", "rhp.patch('tests.sevents.value', function(original, x) return pcall(rhp.wait_event, 'game.x') and 1 or 2 end)"));
    CHECK(fx::value_point(0) == 2);
    const auto r = box.exec("local co = coroutine.create(function() return pcall(rhp.wait_event, 'game.x') end) local _, ok = coroutine.resume(co) return ok");
    CHECK(*r == value_list{Rhp::value{false}});
    CHECK(box.stats().waiting == 0);
}

TEST_CASE("a cancelled or reverted waiter leaves no listener behind", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sevents.waiter", "rhp.spawn(function() rhp.wait_event('tests.sevents.cpp') end)");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(fx::cpp_event.listeners() == 1);
    REQUIRE(box.revert(*mod));
    CHECK(fx::cpp_event.listeners() == 0);
    CHECK(box.stats().waiting == 0);
}

TEST_CASE("wait_event can sit inside pcall", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("rhp.spawn(function() print(pcall(rhp.wait_event, 'game.inside')) end)"));
    box.pump();
    REQUIRE(box.exec("rhp.publish('game.inside', 1)"));
    box.pump();
    CHECK(out.lines == lines({"true\ttrue\t1"}));
}

TEST_CASE("an event and a timeout in the same pump resolve as the event", "[script][script_events]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.exec("rhp.spawn(function() print(rhp.wait_event('game.race', 50)) end)"));
    box.pump();
    clock.advance(milliseconds{50});
    REQUIRE(box.exec("rhp.publish('game.race', 'won')"));
    box.pump();
    CHECK(out.lines == lines({"true\twon"}));
}

TEST_CASE("an event carries many values to handlers and waiters", "[script][script_events]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.sevents.many", "rhp.on('game.many', function(...) print('handler ' .. select('#', ...)) end)"));
    REQUIRE(box.exec("rhp.spawn(function() print('waiter ' .. (select('#', rhp.wait_event('game.many')) - 1)) end)"));
    box.pump();
    REQUIRE(box.exec("local t = {} for i = 1, 100 do t[i] = i end rhp.publish('game.many', table.unpack(t))"));
    box.pump();
    box.pump();
    CHECK(std::ranges::is_permutation(out.lines, lines({"handler 100", "waiter 100"})));
}

TEST_CASE("finalizers run by a closing sandbox schedule and subscribe nothing", "[script][script_events]") {
    capture out;
    {
        sandbox box = make_box(out);
        REQUIRE(box.exec(R"lua(
            _G.keep = setmetatable({}, {__gc = function()
                pcall(rhp.every, 1, print)
                pcall(rhp.on, "tests.sevents.cpp", print)
                pcall(rhp.spawn, print)
                pcall(rhp.every_frame, print)
            end})
        )lua"));
        fx::cpp_event.fire(0);
    }
    CHECK(fx::cpp_event.listeners() == 0);
    fx::cpp_event.fire(1); // nothing listens to a destroyed sandbox
}
