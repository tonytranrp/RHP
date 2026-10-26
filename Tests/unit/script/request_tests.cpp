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

using req_lib = Rhp::lib<"req">::var<"a", &g_a>::var<"b", &g_b>::var<"c", &g_c>::var<"d", &g_d>::fn<"fire_inner", &fire_inner>::fn<"last_pending", &last_pending>;

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
        rhp.on("tests.req.ping", function(n) local s = 0 for i = 1, 20000 do s = s + i end req.b = n end)
        rhp.on("tests.req.ping", function(n) local s = 0 for i = 1, 20000 do s = s + i end req.c = n end)
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
