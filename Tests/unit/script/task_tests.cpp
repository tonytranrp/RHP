#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace task_tests_fixtures {

inline int g_counter = 0;
inline sandbox* g_box = nullptr;
inline Rhp::module_id g_unload{};

inline int base_value(int x) {
    return x;
}

inline constexpr Rhp::patch_point<"tests.tasks.value", &base_value> value_point{};

inline int read_value(int x) {
    return value_point(x);
}

// Unloads g_unload from inside a running script (a C++ binding re-entering the sandbox).
inline bool unload_marked() {
    return g_box != nullptr && g_box->unload(g_unload).has_value();
}

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>::fn<"read", &read_value>::fn<"unload_marked", &unload_marked>;

} // namespace task_tests_fixtures

namespace {

namespace fx = task_tests_fixtures;

struct capture {
    std::vector<std::string> lines;
    std::vector<std::pair<Rhp::request_id, std::string>> sources;
    std::vector<Rhp::script::handler_failure> failures;
};

sandbox make_box(capture& out, Rhp::limits limits = {}, Rhp::role role = Rhp::role::kPatch) {
    fx::g_counter = 0;
    sandbox_options options;
    options.limits = limits;
    options.caller_role = role;
    options.on_output = [&out](Rhp::request_id r, Rhp::module_id, std::string_view line) {
        out.lines.emplace_back(line);
        out.sources.emplace_back(r, std::string{line});
    };
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::counter_lib>());
    return box;
}

void pump(sandbox& box, int n) {
    for (int i = 0; i < n; ++i) {
        box.pump();
    }
}

std::string text(const Rhp::result<value_list>& r, std::size_t i = 0) {
    if (!r) {
        return "error: " + r.error().message;
    }
    if (i >= r->size()) {
        return "<none>";
    }
    const auto* s = r->at(i).get_if<std::string>();
    return s != nullptr ? *s : "<not a string>";
}

} // namespace

TEST_CASE("rhp.spawn starts the task at the next pump and returns a handle", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.start", R"lua(
        t = rhp.spawn(function(a, b) print("run " .. a .. b) end, "x", "y")
        function info() return math.type(t.id), tostring(t):match("^task %d+ %((%a+)%)$"), t:status() end
    )lua");
    REQUIRE(mod.has_value());
    CHECK(out.lines.empty());
    CHECK(*box.call(*mod, "info") == value_list{Rhp::value{"integer"}, Rhp::value{"suspended"}, Rhp::value{"suspended"}});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"run xy"});
    CHECK(text(box.call(*mod, "info"), 2) == "done");
}

TEST_CASE("a task outlives the request that spawned it", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto r = box.exec("rhp.spawn(function() for i = 1, 3 do print('step ' .. i) rhp.next_frame() end end) return 'answered'");
    CHECK(text(r) == "answered");
    CHECK(box.suspended() == 1);
    pump(box, 4);
    CHECK(out.lines == std::vector<std::string>{"step 1", "step 2", "step 3"});
    CHECK(box.suspended() == 0);
}

TEST_CASE("task output carries the task request", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("rhp.spawn(function() print('from task') end)"));
    const auto spawner = box.last_request();
    box.pump();
    REQUIRE(out.sources.size() == 1);
    CHECK(out.sources[0].first != spawner);
    CHECK(out.sources[0].first != Rhp::request_id{});
}

TEST_CASE("join returns the results of a finished task", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.results", R"lua(
        local shared = {}
        local fn = function() end
        t = rhp.spawn(function() return 1, "two", shared, fn end)
        function check()
            local a, b, c, d = t:join()
            return a, b, c == shared, d == fn
        end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(*box.call(*mod, "check") == value_list{Rhp::value{1}, Rhp::value{"two"}, Rhp::value{true}, Rhp::value{true}});
}

TEST_CASE("join suspends until the task finishes", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec(R"lua(
        local t = rhp.spawn(function() rhp.wait(3) return 42 end)
        rhp.spawn(function() print("joined " .. t:join()) end)
    )lua"));
    pump(box, 3);
    CHECK(out.lines.empty());
    pump(box, 2);
    CHECK(out.lines == std::vector<std::string>{"joined 42"});
}

TEST_CASE("join raises the error of a failed task", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.fails", R"lua(
        t = rhp.spawn(function() error("task broke") end)
        function check() local ok, err = pcall(t.join, t) return ok, tostring(err):find("task broke") ~= nil, t:status() end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(*box.call(*mod, "check") == value_list{Rhp::value{false}, Rhp::value{true}, Rhp::value{"failed"}});
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].kind == Rhp::script::handler_kind::kTask);
    CHECK(box.status(*mod)->state == module_state::kActive);
}

TEST_CASE("join raises kCancelled for a cancelled task", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.cancel_join", R"lua(
        t = rhp.spawn(function() rhp.wait(100) end)
        function stop() return t:cancel() end
        function check() local ok, err = pcall(t.join, t) return ok, tostring(err):match("%[([%w_]+)%]"), t:status() end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(*box.call(*mod, "stop") == value_list{Rhp::value{true}});
    CHECK(*box.call(*mod, "check") == value_list{Rhp::value{false}, Rhp::value{"cancelled"}, Rhp::value{"cancelled"}});
    CHECK(*box.call(*mod, "stop") == value_list{Rhp::value{false}});
    CHECK(out.failures.empty());
}

TEST_CASE("a task cannot join itself", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec(R"lua(
        local t
        t = rhp.spawn(function() local ok, err = pcall(function() return t:join() end) print(tostring(err):match("can't join itself")) end)
    )lua"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"can't join itself"});
}

TEST_CASE("a join cycle is refused", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec(R"lua(
        local a, b
        a = rhp.spawn(function() rhp.next_frame() local ok, err = pcall(b.join, b) print("a: " .. tostring(ok)) end)
        b = rhp.spawn(function() local ok, err = pcall(a.join, a) print("b: " .. tostring(ok)) end)
    )lua"));
    pump(box, 4);
    // b joins a first; when a then tries to join b, that is a cycle.
    CHECK(out.lines == std::vector<std::string>{"a: false", "b: true"});
}

TEST_CASE("join outside a request thread is refused", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.handler_join", R"lua(
        t = rhp.spawn(function() rhp.wait(10) end)
        rhp.patch("tests.tasks.value", function(original, x) local ok = pcall(t.join, t) return ok and 1 or 2 end)
        function in_coroutine()
            local co = coroutine.create(function() return pcall(t.join, t) end)
            local _, ok = coroutine.resume(co)
            return ok
        end
    )lua");
    REQUIRE(mod.has_value());
    CHECK(fx::read_value(5) == 2);
    CHECK(*box.call(*mod, "in_coroutine") == value_list{Rhp::value{false}});
}

TEST_CASE("cancel stops a suspended task and closes its variables", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.close", R"lua(
        t = rhp.spawn(function()
            local guard <close> = setmetatable({}, {__close = function() print("closed") end})
            rhp.wait(100)
        end)
        function stop() return t:cancel() end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(*box.call(*mod, "stop") == value_list{Rhp::value{true}});
    CHECK(out.lines == std::vector<std::string>{"closed"});
    CHECK(box.suspended() == 0);
}

TEST_CASE("a task can cancel itself", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.self_cancel", R"lua(
        t = rhp.spawn(function() print("before") t:cancel() for i = 1, 1e9 do end print("after") end)
        function status() return t:status() end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"before"});
    CHECK(text(box.call(*mod, "status")) == "cancelled");
    CHECK(out.failures.empty());
}

TEST_CASE("rhp.off with a task id cancels the task", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.tasks.off", R"lua(
        t = rhp.spawn(function() rhp.wait(100) end)
        function stop() rhp.off(t.id) return t:status() end
        function again() local ok = pcall(rhp.off, t.id) return ok end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(text(box.call(*mod, "stop")) == "cancelled");
    CHECK(*box.call(*mod, "again") == value_list{Rhp::value{false}});
}

TEST_CASE("revert unload and a reload swap cancel the module's tasks", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    constexpr std::string_view kLooping = "rhp.spawn(function() while true do counter.value = counter.value + 1 rhp.next_frame() end end)";
    const auto a = box.load("tests.tasks.rev_a", kLooping);
    const auto b = box.load("tests.tasks.rev_b", kLooping);
    const auto c = box.load("tests.tasks.rev_c", kLooping);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(c.has_value());
    box.pump();
    CHECK(box.stats().tasks == 3);
    REQUIRE(box.revert(*a));
    REQUIRE(box.unload(*b));
    REQUIRE(box.reload(*c, "-- no task now"));
    CHECK(box.stats().tasks == 0);
    CHECK(box.suspended() == 0);
    const int seen = fx::g_counter;
    pump(box, 3);
    CHECK(fx::g_counter == seen);
}

TEST_CASE("a failed exec cancels the tasks it spawned", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    CHECK_FALSE(box.exec("rhp.spawn(function() print('never') end) error('exec failed')"));
    box.pump();
    CHECK(out.lines.empty());
    CHECK(box.stats().tasks == 0);
}

TEST_CASE("unload from inside a task is deferred", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    fx::g_box = &box;
    const auto target = box.load("tests.tasks.target", "rhp.every_frame(function() print('target') end)");
    REQUIRE(target.has_value());
    fx::g_unload = *target;
    REQUIRE(box.exec("rhp.spawn(function() print(counter.unload_marked()) print('still running') end)"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"target", "true", "still running"});
    CHECK_FALSE(box.status(*target).has_value());
    fx::g_box = nullptr;
}

TEST_CASE("task budgets apply per resume", "[script][tasks]") {
    capture out;
    Rhp::limits limits;
    limits.instructions = 50'000;
    sandbox box = make_box(out, limits);
    REQUIRE(box.exec(R"lua(
        rhp.spawn(function()
            for round = 1, 20 do
                local s = 0
                for i = 1, 2000 do s = s + i end
                rhp.next_frame()
            end
            print("finished")
        end)
    )lua"));
    pump(box, 22);
    CHECK(out.lines == std::vector<std::string>{"finished"});
    CHECK(out.failures.empty());
}

TEST_CASE("a task without waits is sliced when slice_us is set", "[script][tasks]") {
    capture out;
    Rhp::limits limits;
    limits.slice_us = 1'000;
    sandbox box = make_box(out, limits);
    REQUIRE(box.exec("rhp.spawn(function() local t = os.clock() while os.clock() - t < 0.02 do end print('done') end)"));
    int pumps = 0;
    while (out.lines.empty() && pumps < 1'000) {
        box.pump();
        ++pumps;
    }
    CHECK(out.lines == std::vector<std::string>{"done"});
    CHECK(pumps > 2);
}

TEST_CASE("a collected handle releases a finished task", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out, {}, Rhp::role::kAdmin); // admin keeps collectgarbage
    REQUIRE(box.exec("rhp.spawn(function() return 1 end)"));
    box.pump();
    CHECK(box.stats().tasks == 0); // finished
    REQUIRE(box.exec("collectgarbage() collectgarbage()"));
    box.pump();
    REQUIRE(box.exec("local t = rhp.spawn(function() rhp.wait(2) end) t = nil collectgarbage() collectgarbage()"));
    CHECK(box.stats().tasks == 1); // unfinished tasks are kept without a handle
    pump(box, 4);
    CHECK(box.stats().tasks == 0);
}

TEST_CASE("tasks of a destroyed sandbox are cancelled", "[script][tasks]") {
    capture out;
    {
        sandbox box = make_box(out);
        REQUIRE(box.load("tests.tasks.destroyed", R"lua(
            counter.value = 7
            rhp.spawn(function() while true do rhp.next_frame() end end)
        )lua"));
        box.pump();
        CHECK(fx::g_counter == 7);
    }
    CHECK(fx::g_counter == 0);
}

TEST_CASE("rhp.tasks lists the module's unfinished tasks", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.tasks.elsewhere", "rhp.spawn(function() rhp.wait(10) end)"));
    const auto mod = box.load("tests.tasks.listing", R"lua(
        a = rhp.spawn(function() rhp.wait(10) end)
        b = rhp.spawn(function() end)
        function list() local all = rhp.tasks() return #all, all[1] and all[1].id == a.id end
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(*box.call(*mod, "list") == value_list{Rhp::value{1}, Rhp::value{true}});
}

TEST_CASE("a task spawned by a failed handler is cancelled under report", "[script][tasks]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.load("tests.tasks.handler_spawn", R"lua(
        rhp.after(0, function() rhp.spawn(function() print("orphan") end) error("handler failed") end)
    )lua"));
    pump(box, 3);
    CHECK(out.lines.empty());
    CHECK(out.failures.size() == 1);
    CHECK(box.stats().tasks == 0);
}
