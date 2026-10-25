// Stage 11 tools over a sandbox: tunables, the profiler and the debugger.
#include <algorithm>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/debug.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/tunables.hpp>

using Rhp::errc;
using Rhp::value;
using Rhp::script::debug_scope;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::step_mode;
using Rhp::script::value_list;

namespace tools_tests_fixture {

inline double g_speed = 1.0;
inline int g_level = 3;
inline int g_frames = 7;
inline bool g_god = false;

using tt_lib = Rhp::lib<"tt">::var<"speed", &g_speed, Rhp::range<0.0, 10.0>, Rhp::step<0.5>, Rhp::unit<"m/s">, Rhp::doc<"how fast it goes">>::var<
    "god", &g_god>::ro<"frames", &g_frames, Rhp::doc<"frames so far">>::sub<Rhp::lib<"ai">::var<"level", &g_level, Rhp::range<1, 5>>>;

void reset() {
    g_speed = 1.0;
    g_level = 3;
    g_frames = 7;
    g_god = false;
}

} // namespace tools_tests_fixture

namespace {

namespace fx = tools_tests_fixture;

const Rhp::script::tunable_info* find(const std::vector<Rhp::script::tunable_info>& all, std::string_view path) {
    const auto it = std::ranges::find(all, path, &Rhp::script::tunable_info::path);
    return it != all.end() ? &*it : nullptr;
}

const Rhp::script::debug_variable* find(const std::vector<Rhp::script::debug_variable>& all, std::string_view name) {
    const auto it = std::ranges::find(all, name, &Rhp::script::debug_variable::name);
    return it != all.end() ? &*it : nullptr;
}

// A sandbox that keeps the final results of suspended requests and the "rhp.debug" events.
struct debug_box {
    std::vector<std::pair<Rhp::request_id, Rhp::result<value_list>>> results;
    std::vector<value> events;
    sandbox box;
    Rhp::subscription sub;

    explicit debug_box(sandbox_options o = {}) : box(with_results(std::move(o), results)) {
        sub = box.on_script_event("rhp.debug", [this](const Rhp::script::script_event& e) {
            if (!e.args.empty()) {
                events.push_back(e.args.front());
            }
        });
    }

    static sandbox_options with_results(sandbox_options o, std::vector<std::pair<Rhp::request_id, Rhp::result<value_list>>>& out) {
        o.on_result = [&out](Rhp::request_id id, const Rhp::result<value_list>& r) { out.emplace_back(id, r); };
        return o;
    }

    [[nodiscard]] std::string event_kind(std::size_t i) const {
        const value* k = events.at(i).find("kind");
        return k != nullptr && k->get_if<std::string>() != nullptr ? *k->get_if<std::string>() : std::string{};
    }
};

} // namespace

// ---- tunables --------------------------------------------------------------------------------------

TEST_CASE("tunables list a lib's variables with their tags and values", "[script][tunables]") {
    fx::reset();
    sandbox box;
    REQUIRE(box.install<fx::tt_lib>());
    const auto all = box.tunables();
    REQUIRE(all.has_value());
    CHECK(all->size() == 4);
    const auto* speed = find(*all, "tt.speed");
    REQUIRE(speed != nullptr);
    CHECK(speed->type == "number");
    CHECK(speed->writable);
    CHECK(speed->current == value{1.0});
    CHECK(speed->min == 0.0);
    CHECK(speed->max == 10.0);
    CHECK(speed->step == 0.5);
    CHECK(speed->unit == "m/s");
    CHECK(speed->doc == "how fast it goes");
    const auto* frames = find(*all, "tt.frames");
    REQUIRE(frames != nullptr);
    CHECK_FALSE(frames->writable);
    CHECK(frames->current == value{7});
    const auto* level = find(*all, "tt.ai.level");
    REQUIRE(level != nullptr);
    CHECK(level->type == "integer");
    CHECK(level->min == 1.0);
    CHECK_FALSE(find(*all, "tt.god")->min.has_value());

    CHECK(box.tunables("tt.ai")->size() == 1);
    CHECK(box.tunables("tt.speed")->size() == 1);
    CHECK(box.tunables("tt.sp").error().code == errc::kNotFound);
}

TEST_CASE("tune writes a variable as a script would and is journaled", "[script][tunables]") {
    fx::reset();
    sandbox box;
    REQUIRE(box.install<fx::tt_lib>());
    REQUIRE(box.tune("tt.speed", value{4.5}));
    CHECK(fx::g_speed == 4.5);
    CHECK(box.tunables("tt.speed")->front().current == value{4.5});
    REQUIRE(box.tune("tt.ai.level", value{5}));
    CHECK(fx::g_level == 5);
    CHECK(box.tune("tt.speed", value{11.0}).error().code == errc::kOutOfRange);
    CHECK(box.tune("tt.ai.level", value{0}).error().code == errc::kOutOfRange);
    CHECK(box.tune("tt.speed", value{"fast"}).error().code == errc::kTypeMismatch);
    CHECK(fx::g_speed == 4.5);
    CHECK(box.tune("tt.frames", value{1}).error().code == errc::kForbidden);
    CHECK(box.tune("tt.nope", value{1}).error().code == errc::kNotFound);
    (void)box.revert_all();
    CHECK(fx::g_speed == 1.0);
    CHECK(fx::g_level == 3);

    sandbox observer{sandbox_options{.caller_role = Rhp::role::kObserve}};
    REQUIRE(observer.install<fx::tt_lib>());
    CHECK_FALSE(observer.tunables("tt.speed")->front().writable);
    CHECK(observer.tune("tt.speed", value{2.0}).error().code == errc::kForbidden);
    CHECK(fx::g_speed == 1.0);
}

TEST_CASE("scripts see ranges and rhp.tunables", "[script][tunables]") {
    fx::reset();
    sandbox box;
    REQUIRE(box.install<fx::tt_lib>());
    CHECK(box.exec("tt.speed = 11").error().code == errc::kOutOfRange);
    CHECK(box.exec("tt.speed = 0/0").error().code == errc::kOutOfRange); // NaN is outside every range
    const auto t = box.exec("local t = rhp.tunables('tt.speed')[1] return #rhp.tunables(), t.min, t.max, t.step, t.value, t.unit, t.writable");
    REQUIRE(t.has_value());
    CHECK(*t == value_list{value{4}, value{0.0}, value{10.0}, value{0.5}, value{1.0}, value{"m/s"}, value{true}});
    CHECK(*box.exec("return rhp.tunables('tt.frames')[1].writable") == value_list{value{false}});
}

TEST_CASE("stubs describe tagged variables", "[script][tunables]") {
    sandbox box;
    REQUIRE(box.install<fx::tt_lib>());
    const std::string stubs = box.stubs();
    CHECK(stubs.find("---@field speed number [0, 10] m/s: how fast it goes") != std::string::npos);
    CHECK(stubs.find("---@field frames integer read-only frames so far") != std::string::npos);
    CHECK(stubs.find("function rhp.tunables(prefix) end") != std::string::npos);
}

// ---- profiler --------------------------------------------------------------------------------------

TEST_CASE("the profiler samples where scripts spend their instructions", "[script][profile]") {
    sandbox box;
    const auto mod = box.load("prof.work", "function hot()\n local s = 0\n for i = 1, 20000 do s = s + i end\n return s\n end\n function cold() return 1 end");
    REQUIRE(mod.has_value());
    REQUIRE(box.start_profile({.interval = 100}));
    CHECK(box.start_profile().error().code == errc::kAlreadyLoaded);
    for (int i = 0; i < 5; ++i) {
        REQUIRE(box.call(*mod, "hot"));
    }
    REQUIRE(box.call(*mod, "cold"));
    CHECK(box.profile().running);
    const auto report = box.stop_profile();
    CHECK_FALSE(report.running);
    CHECK(report.interval == 100);
    CHECK(report.samples > 100);
    REQUIRE_FALSE(report.stacks.empty());
    CHECK(report.stacks.front().stack.find("hot (prof.work:1)") != std::string::npos);
    std::uint64_t total = 0;
    for (const auto& s : report.stacks) {
        total += s.samples;
    }
    CHECK(total + report.dropped == report.samples);
    CHECK_FALSE(box.profile().running);
    CHECK(box.profile().stacks.empty());
}

TEST_CASE("profiling keeps results and instruction limits as they are", "[script][profile]") {
    for (const bool profiled : {false, true}) {
        sandbox box{sandbox_options{.limits = Rhp::limits{.instructions = 50'000}}};
        if (profiled) {
            REQUIRE(box.start_profile({.interval = 100}));
        }
        CHECK(*box.exec("local s = 0 for i = 1, 100 do s = s + i end return s") == value_list{value{5050}});
        CHECK(box.exec("local s = 0 for i = 1, 1000000 do s = s + i end return s").error().code == errc::kBudgetExceeded);
    }
}

TEST_CASE("the profiler samples at its own interval whatever the cancel checks", "[script][profile]") {
    // The hook fires every min(check interval, profile interval) instructions: a profile interval
    // longer or shorter than the check interval, or no checks at all, still gives a sample per interval.
    const auto samples = [](Rhp::limits l, std::uint32_t interval) {
        sandbox box{sandbox_options{.limits = l}};
        const auto mod = box.load("prof.rate", "function spin()\n local s = 0\n for i = 1, 200000 do s = s + i end\n return s\n end");
        REQUIRE(mod.has_value());
        REQUIRE(box.start_profile({.interval = interval}));
        REQUIRE(box.call(*mod, "spin"));
        return box.stop_profile().samples;
    };
    const std::uint64_t base = samples(Rhp::limits{}, 100); // checks every 1000 instructions
    CHECK(base > 1000);
    const std::uint64_t slow = samples(Rhp::limits{}, 5000); // longer than the check interval
    CHECK(slow > 0);
    CHECK(slow * 25 <= base);
    CHECK(slow * 75 >= base);
    const std::uint64_t sparse = samples(Rhp::limits{.cancel_check_instructions = 100'000}, 100); // shorter than it
    CHECK(sparse * 2 >= base);
    CHECK(sparse <= base * 2);
    const std::uint64_t unchecked = samples(Rhp::limits{.cancel_checks = Rhp::cancel_scope::kNone}, 100);
    CHECK(unchecked * 2 >= base);
    CHECK(unchecked <= base * 2);
}

TEST_CASE("instruction limits hold with a profile interval longer than the check interval", "[script][profile]") {
    sandbox box{sandbox_options{.limits = Rhp::limits{.instructions = 50'000}}};
    REQUIRE(box.start_profile({.interval = 5000}));
    CHECK(*box.exec("local s = 0 for i = 1, 100 do s = s + i end return s") == value_list{value{5050}});
    CHECK(box.exec("local s = 0 for i = 1, 1000000 do s = s + i end return s").error().code == errc::kBudgetExceeded);
}

TEST_CASE("a coroutine made before profiling starts is sampled and keeps its budget", "[script][profile]") {
    sandbox box{sandbox_options{.limits = Rhp::limits{.instructions = 200'000}}};
    constexpr std::string_view kSource = "co = coroutine.create(function()\n local s = 0\n while true do\n s = s + 1\n if s % 100 == 0 then coroutine.yield(s) end\n end\n end)\n"
                                         "function step(n)\n local v\n for i = 1, n do\n local _, got = coroutine.resume(co)\n v = got\n end\n return v\n end";
    const auto mod = box.load("prof.co", kSource);
    const auto later = box.load("prof.later", kSource); // its coroutine runs only after the profiler stops
    REQUIRE(mod.has_value());
    REQUIRE(later.has_value());
    REQUIRE(box.start_profile({.interval = 100}));
    const auto ten = box.call(*mod, "step", 10);
    REQUIRE(ten.has_value());
    CHECK(*ten == value_list{value{1000}});
    CHECK(box.call(*mod, "step", 100'000).error().code == errc::kBudgetExceeded); // the coroutine's instructions count
    const auto report = box.stop_profile();
    CHECK(report.samples > 0);
    CHECK(std::ranges::any_of(report.stacks, [](const auto& st) { return st.stack.find("prof.co:1") != std::string::npos; })); // the coroutine's function
    // With the profiler stopped, a coroutine made before it started still runs under the limit.
    REQUIRE(box.call(*later, "step", 10));
    CHECK(box.call(*later, "step", 100'000).error().code == errc::kBudgetExceeded);
}

// ---- debugger --------------------------------------------------------------------------------------

TEST_CASE("a breakpoint pauses a request until it is resumed", "[script][debug]") {
    debug_box d;
    const auto mod = d.box.load("dbg.mod", "function run(n)\n  local x = n * 2\n  local y = x + 1\n  return y\nend");
    REQUIRE(mod.has_value());
    CHECK(*d.box.set_breakpoints("dbg.mod", std::vector<std::uint32_t>{3, 3, 0}) == std::vector<std::uint32_t>{3});
    const auto first = d.box.call(*mod, "run", 5);
    REQUIRE(first.has_value());
    CHECK(first->empty()); // suspended at the breakpoint
    const Rhp::request_id req = d.box.last_request();
    CHECK(d.box.pending(req));
    d.box.pump(); // the event goes out; the program keeps running
    REQUIRE(d.events.size() == 1);
    CHECK(d.event_kind(0) == "paused");
    const auto paused = d.box.paused();
    REQUIRE(paused.size() == 1);
    CHECK(paused[0].request == req);
    CHECK(paused[0].reason == "breakpoint");
    CHECK(paused[0].source == "dbg.mod");
    CHECK(paused[0].line == 3);
    CHECK(d.box.stats().paused == 1);

    const auto frames = d.box.debug_stack(req);
    REQUIRE(frames.has_value());
    REQUIRE_FALSE(frames->empty());
    CHECK(frames->front().name == "run");
    CHECK(frames->front().line == 3);
    CHECK(frames->front().source == "dbg.mod");
    const auto locals = d.box.debug_variables(req, 0, debug_scope::kLocals);
    REQUIRE(locals.has_value());
    REQUIRE(find(*locals, "n") != nullptr);
    CHECK(find(*locals, "n")->text == "5");
    CHECK(find(*locals, "x")->text == "10");
    CHECK(d.box.debug_evaluate(req, 0, "x")->text == "10");

    for (int i = 0; i < 3; ++i) {
        d.box.pump();
    }
    CHECK(d.results.empty()); // still paused
    REQUIRE(d.box.debug_resume(req));
    CHECK(d.box.debug_resume(req).error().code == errc::kNotFound);
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(*d.results[0].second == value_list{value{11}});
    CHECK(d.box.paused().empty());
}

TEST_CASE("stepping over into and out of functions", "[script][debug]") {
    debug_box d;
    const auto mod = d.box.load("dbg.step", "local function inc(v)\n  return v + 1\nend\nfunction run()\n  local a = 1\n  a = inc(a)\n  a = inc(a)\n  return a\nend");
    REQUIRE(mod.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.step", std::vector<std::uint32_t>{6}));
    REQUIRE(d.box.call(*mod, "run"));
    const Rhp::request_id req = d.box.last_request();
    const auto at = [&] {
        const auto p = d.box.paused();
        return p.empty() ? 0u : p.front().line;
    };
    CHECK(at() == 6);
    REQUIRE(d.box.set_breakpoints("dbg.step", {}));
    REQUIRE(d.box.debug_resume(req, step_mode::kOver));
    d.box.pump();
    CHECK(at() == 7);
    CHECK(d.box.paused().front().reason == "step");
    REQUIRE(d.box.debug_resume(req, step_mode::kInto));
    d.box.pump();
    CHECK(at() == 2);
    CHECK(d.box.debug_stack(req)->front().name == "inc");
    REQUIRE(d.box.debug_resume(req, step_mode::kOut));
    d.box.pump();
    CHECK(at() >= 7);
    CHECK(d.box.debug_stack(req)->front().name == "run");
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(*d.results[0].second == value_list{value{3}});
}

TEST_CASE("pause stops the next line a request runs and debug_reset lets everything go", "[script][debug]") {
    debug_box d;
    REQUIRE(d.box.load("dbg.tick", "ticks = 0\nrhp.every_frame(function()\n  ticks = ticks + 1\nend)"));
    d.box.pump();
    d.box.debug_pause();
    d.box.pump(); // the frame callback pauses on its first line
    REQUIRE(d.box.paused().size() == 1);
    CHECK(d.box.paused().front().reason == "pause");
    d.box.pump();
    d.box.pump(); // a paused callback doesn't overlap itself: nothing else runs it
    CHECK(d.box.paused().size() == 1);
    d.box.debug_reset();
    CHECK(d.box.paused().empty());
    for (int i = 0; i < 3; ++i) {
        d.box.pump();
    }
    const auto mod = d.box.find("dbg.tick");
    CHECK(d.box.status(*mod)->state == Rhp::script::module_state::kActive);
}

TEST_CASE("a breakpoint where a request can't pause is reported once as a hit", "[script][debug]") {
    debug_box d;
    REQUIRE(d.box.set_breakpoints("exec", std::vector<std::uint32_t>{2}));
    const auto r = d.box.exec("local co = coroutine.create(function()\n  local z = 1\n  return z\nend)\nlocal _, a = coroutine.resume(co)\nlocal co2 = coroutine.create(function()\n  return 2\nend)\nreturn a");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{value{1}}); // ran through
    d.box.pump();
    REQUIRE(d.events.size() == 1);
    CHECK(d.event_kind(0) == "hit");
    REQUIRE(d.box.exec("local co = coroutine.create(function()\n  local z = 1\n  return z\nend)\ncoroutine.resume(co)"));
    d.box.pump();
    CHECK(d.events.size() == 1); // once per place
}

TEST_CASE("line events follow calls returns and resumes into functions with breakpoints", "[script][debug]") {
    // Breakpoints only: line events run in the functions that hold one. A coroutine resumed after a
    // yield (it continues inside its function: the yield's return event turns them on again), a
    // function reached after many calls without one, and a tail call all still stop.
    debug_box d;
    const auto mod = d.box.load("dbg.scope", "local function plain(x)\n"                // 1
                                             "  return x + 1\n"                         // 2
                                             "end\n"                                    // 3
                                             "local function marked(x)\n"               // 4
                                             "  local m = x * 2\n"                      // 5
                                             "  return m\n"                             // 6
                                             "end\n"                                    // 7
                                             "local function tail(x)\n"                 // 8
                                             "  return marked(x)\n"                     // 9
                                             "end\n"                                    // 10
                                             "function run()\n"                         // 11
                                             "  local s = 0\n"                          // 12
                                             "  for i = 1, 1000 do s = plain(s) end\n"  // 13
                                             "  local co = coroutine.wrap(function()\n" // 14
                                             "    coroutine.yield(1)\n"                 // 15
                                             "    local after = 2\n"                    // 16
                                             "    return after\n"                       // 17
                                             "  end)\n"                                 // 18
                                             "  co()\n"                                 // 19
                                             "  local resumed = co()\n"                 // 20
                                             "  return s + tail(resumed)\n"             // 21
                                             "end\n");
    REQUIRE(mod.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.scope", std::vector<std::uint32_t>{5, 16}));
    REQUIRE(d.box.call(*mod, "run"));
    const Rhp::request_id req = d.box.last_request();
    d.box.pump();
    // Line 16 runs in a coroutine the script made: it can't pause there, so it is reported as a hit.
    std::vector<std::string> kinds;
    for (std::size_t i = 0; i < d.events.size(); ++i) {
        kinds.push_back(d.event_kind(i));
    }
    CAPTURE(kinds);
    REQUIRE(std::ranges::count(kinds, std::string{"hit"}) == 1);
    const auto paused = d.box.paused();
    REQUIRE(paused.size() == 1); // then the tail call into marked() pauses at line 5
    CHECK(paused[0].line == 5);
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(*d.results[0].second == value_list{value{1004}});
}

TEST_CASE("inspecting tables upvalues globals and lib variables", "[script][debug]") {
    fx::reset();
    debug_box d;
    REQUIRE(d.box.install<fx::tt_lib>());
    const auto mod = d.box.load("dbg.look",
                                "config = {speed = 3, names = {'a', 'b'}}\nlocal hidden = 42\nfunction run()\n  local t = {x = 1, y = {z = 2}}\n  return hidden + t.x\nend");
    REQUIRE(mod.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.look", std::vector<std::uint32_t>{5}));
    REQUIRE(d.box.call(*mod, "run"));
    const Rhp::request_id req = d.box.last_request();
    REQUIRE(d.box.paused().size() == 1);

    const auto locals = *d.box.debug_variables(req, 0, debug_scope::kLocals);
    REQUIRE(find(locals, "t") != nullptr);
    CHECK(find(locals, "t")->expandable);
    const std::vector<std::string> t_path{"t"};
    const auto t = *d.box.debug_variables(req, 0, debug_scope::kLocals, t_path);
    CHECK(find(t, "x")->text == "1");
    CHECK(find(t, "y")->expandable);
    const std::vector<std::string> y_path{"t", "y"};
    CHECK(find(*d.box.debug_variables(req, 0, debug_scope::kLocals, y_path), "z")->text == "2");

    const auto ups = *d.box.debug_variables(req, 0, debug_scope::kUpvalues);
    REQUIRE(find(ups, "hidden") != nullptr);
    CHECK(find(ups, "hidden")->text == "42");
    const auto globals = *d.box.debug_variables(req, 0, debug_scope::kGlobals);
    REQUIRE(find(globals, "config") != nullptr);
    const std::vector<std::string> names_path{"config", "names"};
    const auto names = *d.box.debug_variables(req, 0, debug_scope::kGlobals, names_path);
    CHECK(find(names, "[2]")->text == "\"b\"");

    CHECK(d.box.debug_evaluate(req, 0, "t.y.z")->text == "2");
    CHECK(d.box.debug_evaluate(req, 0, "config.names[2]")->text == "\"b\"");
    CHECK(d.box.debug_evaluate(req, 0, "hidden")->text == "42");
    CHECK(d.box.debug_evaluate(req, 0, "tt.speed")->text == "1");
    CHECK(d.box.debug_evaluate(req, 0, "string")->type == "table");
    CHECK(d.box.debug_evaluate(req, 0, "nope").error().code == errc::kNotFound);
    CHECK(d.box.debug_evaluate(req, 0, "1x").error().code == errc::kInvalidArgument);
    CHECK(d.box.debug_variables(req, 9, debug_scope::kLocals).error().code == errc::kOutOfRange);
    CHECK(d.box.debug_variables(req, 0, debug_scope::kLocals, std::vector<std::string>{"t", "x"}).error().code == errc::kTypeMismatch);
    d.box.debug_reset();
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(*d.results[0].second == value_list{value{43}});
}

TEST_CASE("a paused request that is cancelled leaves the debugger", "[script][debug]") {
    debug_box d;
    const auto mod = d.box.load("dbg.cancel", "function run()\n  local a = 1\n  return a\nend");
    REQUIRE(mod.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.cancel", std::vector<std::uint32_t>{2}));
    REQUIRE(d.box.call(*mod, "run"));
    const Rhp::request_id req = d.box.last_request();
    REQUIRE(d.box.paused().size() == 1);
    d.box.cancel(req);
    d.box.pump();
    CHECK(d.box.paused().empty());
    CHECK_FALSE(d.box.pending(req));
    CHECK(d.box.debug_stack(req).error().code == errc::kNotFound);
}

TEST_CASE("breakpoints are found across modules and after a caught error", "[script][debug]") {
    debug_box d;
    REQUIRE(d.box.load("dbg.b", "local M = {}\nfunction M.f(v)\n  local w = v * 3\n  return w\nend\nfunction M.boom()\n  error('x')\nend\nreturn M"));
    const auto a = d.box.load("dbg.a",
                              "local b = require('dbg.b')\nfunction run()\n  local x = b.f(1)\n  local y = x + 1\n  local ok = pcall(b.boom)\n  local z = ok\n  return y\nend");
    REQUIRE(a.has_value());
    // Line events are on only inside functions of a source with breakpoints: calls, returns and the
    // return of a pcall that caught an error switch them.
    REQUIRE(d.box.set_breakpoints("dbg.b", std::vector<std::uint32_t>{3}));
    REQUIRE(d.box.set_breakpoints("dbg.a", std::vector<std::uint32_t>{4, 6}));
    REQUIRE(d.box.call(*a, "run"));
    const Rhp::request_id req = d.box.last_request();
    const auto at = [&] {
        const auto p = d.box.paused();
        return p.empty() ? std::string{} : std::format("{}:{}", p.front().source, p.front().line);
    };
    CHECK(at() == "dbg.b:3");
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    CHECK(at() == "dbg.a:4"); // back in dbg.a after the return
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    CHECK(at() == "dbg.a:6"); // after pcall caught an error raised in dbg.b
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(*d.results[0].second == value_list{value{4}});
}

TEST_CASE("evaluate reads no metamethods but a lib's", "[script][debug]") {
    debug_box d;
    // dbg.meta's exports read every missing field through __index, which records the key.
    REQUIRE(d.box.load("dbg.meta", "local seen = {}\nlocal M = setmetatable({seen = seen}, {__index = function(_, k) seen.key = k return 1 end})\nreturn M"));
    const auto mod = d.box.load("dbg.meta2",
                                "local m = require('dbg.meta')\nlocal t = setmetatable({}, {__index = function(_, k) touched = k return 2 end})\n"
                                "function run()\n  local x = (m ~= nil and t ~= nil) and 1 or 0\n  return x\nend\nfunction probe() return touched, m.seen.key end");
    REQUIRE(mod.has_value());
    const auto before = d.box.call(*mod, "probe"); // what loading read (the loader looks up on_load and the like)
    REQUIRE(before.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.meta2", std::vector<std::uint32_t>{5}));
    REQUIRE(d.box.call(*mod, "run"));
    const Rhp::request_id req = d.box.last_request();
    REQUIRE(d.box.paused().size() == 1);
    const auto m = d.box.debug_evaluate(req, 0, "m"); // an upvalue of run
    REQUIRE(m.has_value());
    CHECK(m->type == "module"); // a userdata named by its metatable
    const auto t = d.box.debug_evaluate(req, 0, "t");
    REQUIRE(t.has_value());
    CHECK(t->type == "table");
    const auto through_module = d.box.debug_evaluate(req, 0, "m.anything");
    REQUIRE_FALSE(through_module.has_value());
    CHECK(through_module.error().code == errc::kNotFound); // a module proxy: not read through
    const auto raw = d.box.debug_evaluate(req, 0, "t.anything");
    REQUIRE(raw.has_value());
    CHECK(raw->text == "nil"); // read raw: the table's __index isn't called
    d.box.debug_reset();
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(*d.results[0].second == value_list{value{1}});
    const auto touched = d.box.call(*mod, "probe");
    REQUIRE(touched.has_value());
    CHECK(*touched == *before); // the debugger ran no metamethod
}

TEST_CASE("at most 32 requests wait at breakpoints and the rest run through", "[script][debug]") {
    debug_box d;
    const auto mod = d.box.load("dbg.many", "function run(n)\n  local v = n + 1\n  return v\nend");
    REQUIRE(mod.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.many", std::vector<std::uint32_t>{2}));
    for (int i = 0; i < 32; ++i) {
        const auto r = d.box.call(*mod, "run", i);
        REQUIRE(r.has_value());
        CHECK(r->empty()); // paused
    }
    CHECK(d.box.paused().size() == 32);
    const auto extra = d.box.call(*mod, "run", 100);
    REQUIRE(extra.has_value());
    CHECK(*extra == value_list{value{101}}); // ran through, reported as a hit
    d.box.pump();
    CHECK(std::ranges::count_if(d.events, [](const value& e) { return e.find("kind") != nullptr && *e.find("kind") == value{"hit"}; }) == 1);
    CHECK(d.box.paused().size() == 32);
    d.box.debug_reset();
    d.box.pump();
    CHECK(d.results.size() == 32);
    CHECK(d.box.paused().empty());
}

TEST_CASE("rhp.debug events go to C++ only", "[script][debug]") {
    debug_box d;
    const auto ears = d.box.load("dbg.ears", "seen = 0\nrhp.on('rhp.debug', function() seen = seen + 1 end)\nfunction count() return seen end");
    REQUIRE(ears.has_value());
    const auto mod = d.box.load("dbg.loud", "function run()\n  local a = 1\n  return a\nend");
    REQUIRE(mod.has_value());
    REQUIRE(d.box.set_breakpoints("dbg.loud", std::vector<std::uint32_t>{2}));
    REQUIRE(d.box.call(*mod, "run"));
    const Rhp::request_id req = d.box.last_request();
    d.box.pump();
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    d.box.pump();
    CHECK(d.events.size() == 1);
    CHECK(d.results.size() == 1);
    CHECK(*d.box.call(*ears, "count") == value_list{value{0}}); // the script's listener never heard it
}

TEST_CASE("instruction limits stop a tight loop while the debugger watches lines", "[script][debug]") {
    debug_box d{sandbox_options{.limits = Rhp::limits{.instructions = 100'000}}};
    REQUIRE(d.box.load("dbg.elsewhere", "function f()\n  return 1\nend"));
    REQUIRE(d.box.set_breakpoints("dbg.elsewhere", std::vector<std::uint32_t>{2}));
    CHECK(d.box.exec("local s = 0\nfor i = 1, 10000000 do s = s + math.abs(i) end\nreturn s").error().code == errc::kBudgetExceeded);
    REQUIRE(d.box.set_breakpoints("exec", std::vector<std::uint32_t>{99}));
    CHECK(d.box.exec("local s = 0\nfor i = 1, 10000000 do s = s + math.abs(i) end\nreturn s").error().code == errc::kBudgetExceeded);
    d.box.debug_pause(); // stops the next line: a pause, then the limit once resumed
    const auto paused = d.box.exec("local s = 0\nfor i = 1, 10000000 do s = s + math.abs(i) end\nreturn s");
    REQUIRE(paused.has_value());
    CHECK(paused->empty());
    const Rhp::request_id req = d.box.last_request();
    REQUIRE(d.box.debug_resume(req));
    d.box.pump();
    REQUIRE(d.results.size() == 1);
    CHECK(d.results[0].second.error().code == errc::kBudgetExceeded);
}
