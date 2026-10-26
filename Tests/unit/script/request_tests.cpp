// Requests that never suspend stay out of the scheduler's map, and the handlers of one delivery
// share a record and a coroutine: what scripts and C++ see must not change.
#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::handler_kind;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace request_tests_fixtures {

inline int g_a = 0;
inline int g_b = 0;
inline int g_c = 0;
inline int g_d = 0;
inline sandbox* g_box = nullptr;

inline constexpr Rhp::lua_event<"tests.req.ping", int> ping{};
inline constexpr Rhp::lua_event<"tests.req.inner", int> inner{};

inline void fire_inner(int n) {
    inner.fire(n);
}

// Whether the request the last operation started is still pending (running or suspended).
inline bool last_pending() {
    return g_box != nullptr && g_box->pending(g_box->last_request());
}

// Cancels the request the last operation started (the call running it).
inline void cancel_last() {
    if (g_box != nullptr) {
        g_box->cancel(g_box->last_request());
    }
}

using req_lib = Rhp::lib<"req">::var<"a", &g_a>::var<"b", &g_b>::var<"c", &g_c>::var<"d", &g_d>::fn<"fire_inner", &fire_inner>::fn<"last_pending", &last_pending>::fn<"cancel_last", &cancel_last>;

struct capture {
    std::vector<Rhp::request_id> requests; // print()s, by request
    std::vector<std::string> lines;
    std::vector<Rhp::script::handler_failure> failures;
};

inline sandbox make_box(capture& out, Rhp::limits limits = {}) {
    g_a = g_b = g_c = g_d = 0;
    sandbox_options options;
    options.limits = limits;
    options.on_output = [&out](Rhp::request_id r, Rhp::module_id, std::string_view line) {
        out.requests.push_back(r);
        out.lines.emplace_back(line);
    };
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    sandbox box{std::move(options)};
    REQUIRE(box.install<req_lib>());
    return box;
}

} // namespace request_tests_fixtures

namespace fx = request_tests_fixtures;

TEST_CASE("the handlers of one delivery are requests of their own", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    const auto mod = box.load("tests.req.mixed", R"lua(
        rhp.on("tests.req.ping", function(n) print("a") req.a = n end)
        rhp.on("tests.req.ping", function(n) print("b") req.b = n error("b failed") end)
        rhp.on("tests.req.ping", function(n) print("c") req.c = n end)
        rhp.on("tests.req.ping", function(n) print("d") rhp.wait(1) req.d = n end)
        rhp.on("tests.req.ping", function(n) print("e") end)
    )lua");
    REQUIRE(mod.has_value());
    fx::ping.fire(5);
    CHECK(out.lines == std::vector<std::string>{"a", "b", "c", "d", "e"});
    // Five requests: every handler printed under an id of its own.
    std::vector<Rhp::request_id> ids = out.requests;
    std::ranges::sort(ids);
    CHECK(std::ranges::adjacent_find(ids) == ids.end());
    // The failure undid only the failing handler's write; the others kept theirs.
    CHECK(fx::g_a == 5);
    CHECK(fx::g_b == 0);
    CHECK(fx::g_c == 5);
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].kind == handler_kind::kEvent);
    CHECK(out.failures[0].request == out.requests[1]);
    CHECK(out.failures[0].err.message.find("b failed") != std::string::npos);
    CHECK_FALSE(out.failures[0].err.traceback.empty());
    // The suspended one waits as its own request and finishes later.
    CHECK(box.suspended() == 1);
    CHECK(box.pending(out.requests[3]));
    CHECK_FALSE(box.pending(out.requests[4]));
    CHECK(fx::g_d == 0);
    box.pump();
    box.pump();
    CHECK(fx::g_d == 5);
    CHECK(box.suspended() == 0);
    CHECK(box.status(*mod)->state == module_state::kActive);
    // A second delivery: the same handlers, new ids.
    out.lines.clear();
    out.requests.clear();
    fx::ping.fire(6);
    box.pump();
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a", "b", "c", "d", "e"});
    CHECK(fx::g_a == 6);
    CHECK(fx::g_d == 6);
    CHECK(out.failures.size() == 2);
}

TEST_CASE("a handler that removes a later one of the same delivery stops it", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    REQUIRE(box.load("tests.req.off", R"lua(
        local later
        rhp.on("tests.req.ping", function() print("first") rhp.off(later) end)
        later = rhp.on("tests.req.ping", function() print("removed") end)
        rhp.on("tests.req.ping", function() print("last") end)
    )lua"));
    fx::ping.fire(1);
    CHECK(out.lines == std::vector<std::string>{"first", "last"});
    out.lines.clear();
    fx::ping.fire(2);
    CHECK(out.lines == std::vector<std::string>{"first", "last"});
}

TEST_CASE("a delivery inside a handler runs its own handlers in between", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    REQUIRE(box.load("tests.req.nested", R"lua(
        rhp.on("tests.req.ping", function(n) print("outer 1") req.fire_inner(n + 1) print("outer 1 again") end)
        rhp.on("tests.req.ping", function(n) print("outer 2") req.a = n end)
        rhp.on("tests.req.inner", function(n) print("inner 1") req.b = n end)
        rhp.on("tests.req.inner", function(n) print("inner 2") error("inner failed") end)
        rhp.on("tests.req.inner", function(n) print("inner 3") req.c = n end)
    )lua"));
    fx::ping.fire(10);
    CHECK(out.lines == std::vector<std::string>{"outer 1", "inner 1", "inner 2", "inner 3", "outer 1 again", "outer 2"});
    CHECK(fx::g_a == 10);
    CHECK(fx::g_b == 11);
    CHECK(fx::g_c == 11);
    box.pump(); // the inner failure happened inside the outer handler's run: applied once runs end
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].source == "tests.req.inner");
    CHECK(box.suspended() == 0);
}

TEST_CASE("a handler stopped by a limit leaves the next one its own budget", "[script][requests]") {
    fx::capture out;
    Rhp::limits limits;
    limits.instructions = 50'000;
    sandbox box = fx::make_box(out, limits);
    REQUIRE(box.load("tests.req.budget", R"lua(
        rhp.on("tests.req.ping", function(n) req.a = n while true do end end)
        rhp.on("tests.req.ping", function(n) local s = 0 for i = 1, 5000 do s = s + i end req.b = n end)
        rhp.on("tests.req.ping", function(n) local s = 0 for i = 1, 5000 do s = s + i end req.c = n end)
    )lua"));
    fx::ping.fire(3);
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].err.code == errc::kBudgetExceeded);
    CHECK(fx::g_a == 0);
    CHECK(fx::g_b == 3);
    CHECK(fx::g_c == 3);
}

TEST_CASE("a call is pending while it runs and while it waits", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    fx::g_box = &box;
    const auto mod = box.load("tests.req.call", R"lua(
        local M = {}
        function M.probe() return req.last_pending() end
        function M.later() rhp.wait(1) return req.last_pending() end
        return M
    )lua");
    REQUIRE(mod.has_value());
    CHECK(*box.call(*mod, "probe") == value_list{Rhp::value{true}});
    CHECK_FALSE(box.pending(box.last_request()));
    auto later = box.call(*mod, "later");
    REQUIRE(later.has_value());
    CHECK(later->empty()); // suspended
    const Rhp::request_id id = box.last_request();
    CHECK(box.pending(id));
    CHECK(box.suspended() == 1);
    box.pump();
    box.pump();
    CHECK_FALSE(box.pending(id));
    CHECK(box.suspended() == 0);
    fx::g_box = nullptr;
}

// The first call of a function looks its name up protected; later ones may skip the protected setup.
// Every outcome must be the same either way, so each case runs a few times.
TEST_CASE("a call made again has the same results and failures", "[script][requests]") {
    fx::capture out;
    Rhp::limits limits;
    limits.instructions = 200'000;
    sandbox box = fx::make_box(out, limits);
    const auto mod = box.load("tests.req.again", R"lua(
        local M = {}
        function M.add(a, b) return a + b end
        function M.many(a, b, c) return a, b == true, c, nil, 2.5 end
        function M.text(s) return "got " .. tostring(s), {1, 2, x = 3} end
        function M.boom() local t = nil return t.x end
        function M.spin() while true do end end
        function M.wait(n) rhp.wait(1) return n * 2 end
        return M
    )lua");
    REQUIRE(mod.has_value());
    for (int round = 0; round < 3; ++round) {
        CAPTURE(round);
        CHECK(*box.call(*mod, "add", std::vector<Rhp::value>{Rhp::value{2}, Rhp::value{3}}) == value_list{Rhp::value{5}});
        CHECK(*box.call(*mod, "many", std::vector<Rhp::value>{Rhp::value{1.5}, Rhp::value{true}, Rhp::value{}}) ==
              value_list{Rhp::value{1.5}, Rhp::value{true}, Rhp::value{}, Rhp::value{}, Rhp::value{2.5}});
        const auto text = box.call(*mod, "text", std::vector<Rhp::value>{Rhp::value{7}});
        REQUIRE(text.has_value());
        REQUIRE(text->size() == 2);
        CHECK(text->at(0) == Rhp::value{"got 7"});
        CHECK(text->at(1).is_map());
        CHECK(*box.call(*mod, "text", std::vector<Rhp::value>{Rhp::value{"x"}}) != value_list{});
        CHECK(box.call(*mod, "nothing").error().code == errc::kNotFound);
        const auto waited = box.call(*mod, "wait", std::vector<Rhp::value>{Rhp::value{4}});
        REQUIRE(waited.has_value());
        CHECK(waited->empty());
        const Rhp::request_id id = box.last_request();
        CHECK(box.pending(id));
        box.pump();
        box.pump();
        CHECK_FALSE(box.pending(id));
        CHECK(box.suspended() == 0);
    }
    const auto spun = box.call(*mod, "spin");
    CHECK(spun.error().code == errc::kBudgetExceeded);
    CHECK(box.status(*mod)->state == module_state::kFaulted); // a failed call faults its module
    REQUIRE(box.reload(*mod, R"lua(
        local M = {}
        function M.boom() local t = nil return t.x end
        function M.ok() return 1 end
        return M
    )lua"));
    CHECK(*box.call(*mod, "ok") == value_list{Rhp::value{1}});
    CHECK(*box.call(*mod, "ok") == value_list{Rhp::value{1}});
    const auto boom = box.call(*mod, "boom");
    REQUIRE_FALSE(boom.has_value());
    CHECK(boom.error().where == "tests.req.again.boom");
    CHECK_FALSE(boom.error().traceback.empty());
    CHECK(box.status(*mod)->state == module_state::kFaulted);
}

TEST_CASE("a call through exports with an __index finds the function every time", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    const auto mod = box.load("tests.req.meta", R"lua(
        local base = {}
        function base.get(n) return n + 1 end
        return setmetatable({}, {__index = base})
    )lua");
    REQUIRE(mod.has_value());
    for (int i = 0; i < 3; ++i) {
        CHECK(*box.call(*mod, "get", std::vector<Rhp::value>{Rhp::value{i}}) == value_list{Rhp::value{i + 1}});
    }
}

TEST_CASE("a call that runs out of memory fails the same way when made again", "[script][requests]") {
    fx::capture out;
    Rhp::limits limits;
    limits.memory = 2u * 1024u * 1024u;
    sandbox box = fx::make_box(out, limits);
    constexpr std::string_view kHog = R"lua(
        local M = {}
        function M.small() return 1 end
        function M.hog() local t = {} for i = 1, 1e7 do t[i] = ("x"):rep(64) .. i end end
        return M
    )lua";
    const auto mod = box.load("tests.req.hog", kHog);
    REQUIRE(mod.has_value());
    for (int round = 0; round < 3; ++round) {
        CAPTURE(round);
        CHECK(*box.call(*mod, "small") == value_list{Rhp::value{1}});
        const auto hog = box.call(*mod, "hog");
        REQUIRE_FALSE(hog.has_value());
        CHECK(hog.error().code == errc::kMemoryExceeded);
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        REQUIRE(box.reload(*mod, kHog));
    }
}

// A call may run with the main state outside any protected run, so nothing a script does may raise
// there: rhp.spawn makes its coroutine on the spawning one.
TEST_CASE("a call that spawns until memory runs out fails cleanly when made again", "[script][requests]") {
    fx::capture out;
    Rhp::limits limits;
    limits.memory = 1024u * 1024u;
    sandbox box = fx::make_box(out, limits);
    constexpr std::string_view kSpawner = R"lua(
        local M = {}
        function M.small() return 1 end
        function M.spawn_all() for i = 1, 1e6 do rhp.spawn(function() end) end end
        return M
    )lua";
    const auto mod = box.load("tests.req.spawner", kSpawner);
    REQUIRE(mod.has_value());
    for (int round = 0; round < 3; ++round) {
        CAPTURE(round);
        CHECK(*box.call(*mod, "small") == value_list{Rhp::value{1}});
        const auto spawned = box.call(*mod, "spawn_all");
        REQUIRE_FALSE(spawned.has_value());
        CHECK(spawned.error().code == errc::kMemoryExceeded);
        box.pump();
        CHECK(box.stats().tasks == 0); // its module faulted: the tasks went with it
        REQUIRE(box.reload(*mod, kSpawner));
    }
}

constexpr std::string_view kCancelModule = R"lua(
    local M = {}
    function M.quick() return 1 end
    function M.stop() req.cancel_last() local i = 0 while true do i = i + 1 end end
    return M
)lua";

TEST_CASE("a call cancelled while it runs stops with the cancelled code", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    fx::g_box = &box;
    const auto mod = box.load("tests.req.cancel", kCancelModule);
    REQUIRE(mod.has_value());
    for (int round = 0; round < 3; ++round) {
        CAPTURE(round);
        CHECK(*box.call(*mod, "quick") == value_list{Rhp::value{1}});
        const auto stopped = box.call(*mod, "stop");
        REQUIRE_FALSE(stopped.has_value());
        CHECK(stopped.error().code == errc::kCancelled);
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        REQUIRE(box.reload(*mod, kCancelModule));
    }
    fx::g_box = nullptr;
}

TEST_CASE("rhp.timers sees a repeating timer running inside its own call", "[script][requests]") {
    fx::capture out;
    sandbox box = fx::make_box(out);
    REQUIRE(box.load("tests.req.timers", R"lua(
        rhp.every(0, function()
            for _, t in ipairs(rhp.timers()) do print(tostring(t.running)) end
        end, {times = 2})
    )lua"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"true"});
}
