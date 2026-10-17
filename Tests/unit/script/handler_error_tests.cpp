#include <format>
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
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::handler_error_policy;
using Rhp::script::handler_kind;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace handler_error_tests_fixtures {

inline int g_counter = 0;

inline constexpr Rhp::lua_event<"tests.herr.ping", int> ping{};

inline void fire_ping(int n) {
    ping.fire(n);
}

inline int base_value(int x) {
    return x;
}

inline constexpr Rhp::patch_point<"tests.herr.value", &base_value> value_point{};

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>::fn<"fire", &fire_ping>;

} // namespace handler_error_tests_fixtures

namespace {

namespace fx = handler_error_tests_fixtures;

struct capture {
    std::vector<std::string> lines;
    std::vector<Rhp::script::handler_failure> failures;
};

sandbox make_box(capture* out, handler_error_policy policy = handler_error_policy::kReport, Rhp::limits limits = {}, bool callback = true) {
    fx::g_counter = 0;
    sandbox_options options;
    options.limits = limits;
    options.handler_errors = policy;
    options.output = [out](std::string_view line) { out->lines.emplace_back(line); };
    if (callback) {
        options.on_handler_error = [out](const Rhp::script::handler_failure& f) { out->failures.push_back(f); };
    }
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::counter_lib>());
    return box;
}

} // namespace

TEST_CASE("a failing timer is reported and keeps firing by default", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.timer", "rhp.every_frame(function() error('frame boom') end) rhp.every(0, function() error('timer boom') end)");
    REQUIRE(mod.has_value());
    box.pump();
    box.pump();
    REQUIRE(out.failures.size() == 4);
    CHECK(out.failures[0].kind == handler_kind::kFrame);
    CHECK(out.failures[0].source == "frame");
    CHECK(out.failures[1].kind == handler_kind::kTimer);
    CHECK(out.failures[1].err.message.find("timer boom") != std::string::npos);
    CHECK(out.failures[1].module_name == "tests.herr.timer");
    CHECK(out.failures[1].action == handler_error_policy::kReport);
    CHECK(out.failures[1].handler != 0);
    CHECK(box.status(*mod)->state == module_state::kActive);
    CHECK(box.status(*mod)->effects == 2);
    CHECK(box.stats().handler_failures == 4);
}

TEST_CASE("a failing event handler is reported and its module stays active", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.event", "counter.value = 1 rhp.on('tests.herr.ping', function(n) error('event boom ' .. n) end)");
    REQUIRE(mod.has_value());
    fx::ping.fire(3);
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].kind == handler_kind::kEvent);
    CHECK(out.failures[0].source == "tests.herr.ping");
    CHECK(box.status(*mod)->state == module_state::kActive);
    CHECK(fx::g_counter == 1);
    CHECK(fx::ping.listeners() == 1);
}

TEST_CASE("report reverts only the failed run's effects", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.partial", R"lua(
        counter.value = 1
        rhp.after(0, function() counter.value = 99 rhp.every_frame(function() end) error("late") end)
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(fx::g_counter == 1);                // the handler's write is undone, the top level's kept
    CHECK(box.stats().schedule_entries == 0); // so is the frame callback the handler made
    CHECK(box.status(*mod)->state == module_state::kActive);
}

TEST_CASE("remove drops the failing handler", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.remove", "rhp.every_frame(function() error('once is enough') end, {on_error = 'remove'})");
    REQUIRE(mod.has_value());
    box.pump();
    box.pump();
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].action == handler_error_policy::kRemove);
    CHECK(box.status(*mod)->effects == 0);
    CHECK(box.status(*mod)->state == module_state::kActive);
}

TEST_CASE("fault on a handler keeps the module fault behavior", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.fault", "counter.value = 5 rhp.on('tests.herr.ping', function() error('fatal') end, {on_error = 'fault'})");
    REQUIRE(mod.has_value());
    fx::ping.fire(1);
    CHECK(box.status(*mod)->state == module_state::kFaulted);
    CHECK(fx::g_counter == 0);
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].action == handler_error_policy::kFault);
}

TEST_CASE("the sandbox default policy applies when a handler sets none", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out, handler_error_policy::kRemove);
    const auto mod = box.load("tests.herr.default", R"lua(
        rhp.every_frame(function() error("default") end)
        rhp.every_frame(function() error("kept") end, {on_error = "report"})
    )lua");
    REQUIRE(mod.has_value());
    box.pump();
    box.pump();
    CHECK(out.failures.size() == 3);
    CHECK(box.status(*mod)->effects == 1);
}

TEST_CASE("a memory stop in a handler faults the module whatever the policy", "[script][handler_errors]") {
    capture out;
    Rhp::limits limits;
    limits.memory = 2u * 1024u * 1024u;
    sandbox box = make_box(&out, handler_error_policy::kReport, limits);
    const auto mod = box.load("tests.herr.memory", "rhp.after(0, function() local t = {} for i = 1, 1e7 do t[i] = ('x'):rep(64) .. i end end)");
    REQUIRE(mod.has_value());
    box.pump();
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].err.code == errc::kMemoryExceeded);
    CHECK(out.failures[0].action == handler_error_policy::kFault);
    CHECK(box.status(*mod)->state == module_state::kFaulted);
}

TEST_CASE("an instruction stop in a handler is reported under report", "[script][handler_errors]") {
    capture out;
    Rhp::limits limits;
    limits.instructions = 20'000;
    sandbox box = make_box(&out, handler_error_policy::kReport, limits);
    const auto mod = box.load("tests.herr.budget", "rhp.after(0, function() while true do end end)");
    REQUIRE(mod.has_value());
    box.pump();
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].err.code == errc::kBudgetExceeded);
    CHECK(box.status(*mod)->state == module_state::kActive);
}

TEST_CASE("rhp.on_error receives failures at the next pump", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    REQUIRE(box.load("tests.herr.watcher", R"lua(
        rhp.on_error(function(f)
            print(f.module .. "|" .. f.kind .. "|" .. f.source .. "|" .. f.action .. "|" .. f.code .. "|" .. tostring(f.message:find("bad call") ~= nil) .. "|" .. math.type(f.id))
        end)
    )lua"));
    REQUIRE(box.load("tests.herr.failing", "rhp.after(0, function() error('bad call') end)"));
    box.pump();
    CHECK(out.lines.empty());
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"tests.herr.failing|timer|timer|report|runtime|true|integer"});
}

TEST_CASE("a failing error handler is not reported to Lua again", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    REQUIRE(box.load("tests.herr.bad_watcher", "rhp.on_error(function(f) print('seen ' .. f.source) error('watcher broke') end)"));
    REQUIRE(box.load("tests.herr.trigger", "rhp.after(0, function() error('first') end)"));
    for (int i = 0; i < 4; ++i) {
        box.pump();
    }
    CHECK(out.lines == std::vector<std::string>{"seen timer"});
    REQUIRE(out.failures.size() == 2);
    CHECK(out.failures[1].source == "rhp.handler_failed");
}

TEST_CASE("handler failures without a callback go to the output", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out, handler_error_policy::kReport, {}, false);
    REQUIRE(box.load("tests.herr.printed", "rhp.after(0, function() error('printed failure') end)"));
    box.pump();
    REQUIRE(out.lines.size() == 1);
    CHECK(out.lines[0].starts_with("[handler failed] tests.herr.printed (timer timer): "));
    CHECK(out.lines[0].find("printed failure") != std::string::npos);
    CHECK(out.lines[0].ends_with("(report)"));
}

TEST_CASE("on_handler_error may re-enter the sandbox", "[script][handler_errors]") {
    capture out;
    sandbox_options options;
    sandbox* self = nullptr;
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_handler_error = [&](const Rhp::script::handler_failure& f) { (void)self->exec(std::format("print('handled {}')", f.source)); };
    sandbox box{std::move(options)};
    self = &box;
    REQUIRE(box.load("tests.herr.reenter", "rhp.after(0, function() error('x') end)"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"handled timer"});
}

TEST_CASE("handler failures inside a run are processed when the run ends", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.nested", "rhp.on('tests.herr.ping', function() counter.value = 7 error('inner') end)");
    REQUIRE(mod.has_value());
    const auto r = box.exec("counter.fire(1) local during = counter.value return during");
    REQUIRE(r.has_value());
    CHECK(r->at(0) == Rhp::value{7}); // undone only once the run around it ended
    CHECK(fx::g_counter == 0);
    CHECK(out.failures.size() == 1);
}

TEST_CASE("patch handler errors still fault their module", "[script][handler_errors]") {
    capture out;
    sandbox box = make_box(&out);
    const auto mod = box.load("tests.herr.patch", "rhp.patch('tests.herr.value', function() error('patch broke') end)");
    REQUIRE(mod.has_value());
    CHECK(fx::value_point(4) == 4);
    box.pump();
    CHECK(box.status(*mod)->state == module_state::kFaulted);
    CHECK(out.failures.empty());
}

TEST_CASE("a cancelled handler request is reported with the cancelled code", "[script][handler_errors]") {
    capture out;
    std::vector<Rhp::request_id> requests;
    sandbox_options options;
    options.on_output = [&](Rhp::request_id r, Rhp::module_id, std::string_view) { requests.push_back(r); };
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    sandbox box{std::move(options)};
    const auto mod = box.load("tests.herr.cancelled", "rhp.after(0, function() print('waiting') rhp.wait(100) end)");
    REQUIRE(mod.has_value());
    box.pump();
    REQUIRE(requests.size() == 1);
    box.cancel(requests[0]);
    box.pump();
    REQUIRE(out.failures.size() == 1);
    CHECK(out.failures[0].err.code == errc::kCancelled);
    CHECK(box.status(*mod)->state == module_state::kActive);
}
