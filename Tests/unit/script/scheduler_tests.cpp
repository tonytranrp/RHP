#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <stop_token>
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
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stubs.hpp>

using Rhp::errc;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

namespace scheduler_tests_fixtures {

inline int g_counter = 0;
inline bool g_stop = false; // spin loops in scripts end once C++ sets it
inline Rhp::script::sandbox* g_box = nullptr;

inline float default_damage(float base, int target) {
    return base * static_cast<float>(target);
}

inline constexpr Rhp::patch_point<"tests.sched.damage", &default_damage> damage{};

// Bindings that re-enter the sandbox (through g_box) from inside a running script.
inline Rhp::module_id find_module(std::string_view name) {
    const auto id = g_box->find(name);
    return id ? *id : Rhp::module_id{};
}

inline bool host_revert(std::string_view name) {
    const auto r = g_box->revert(find_module(name));
    return r && r->deferred;
}

inline bool host_unload(std::string_view name) {
    const auto r = g_box->unload(find_module(name));
    return r && r->deferred;
}

inline std::int64_t host_reload(std::string_view name, std::string_view source) {
    const auto r = g_box->reload(find_module(name), source);
    return r ? static_cast<std::int64_t>(r->value()) : -1;
}

inline std::int64_t host_rollback(std::string_view name) {
    const auto r = g_box->rollback(find_module(name), 1);
    return r ? static_cast<std::int64_t>(r->value()) : -1;
}

inline bool host_revert_to(std::string_view tag) {
    const auto r = g_box->revert_to(tag);
    return r && r->deferred;
}

inline bool host_revert_all() {
    return g_box->revert_all().deferred;
}

inline std::string host_state(std::string_view name) {
    const auto id = g_box->find(name);
    if (!id) {
        return "missing";
    }
    return std::string{to_string(g_box->status(*id)->state)};
}

inline float host_hit(float base) {
    return damage(base, 1);
}

inline std::uint64_t g_cancel_target = 0;

inline void host_cancel_target() {
    g_box->cancel(Rhp::request_id{g_cancel_target});
}

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>;

using host_lib = Rhp::lib<"host">        //
    ::ro<"stop", &g_stop>                //
    ::fn<"revert", &host_revert>         //
    ::fn<"unload", &host_unload>         //
    ::fn<"reload", &host_reload>         //
    ::fn<"rollback", &host_rollback>     //
    ::fn<"revert_to", &host_revert_to>   //
    ::fn<"revert_all", &host_revert_all> //
    ::fn<"state", &host_state>           //
    ::fn<"hit", &host_hit>               //
    ::fn<"cancel_target", &host_cancel_target>;

inline constexpr Rhp::lua_event<"tests.sched.ping", int, std::string_view> ping{};

} // namespace scheduler_tests_fixtures

namespace {

namespace fx = scheduler_tests_fixtures;

using clock_type = std::chrono::steady_clock;
using std::chrono::milliseconds;

struct capture {
    std::vector<std::string> lines;
    std::vector<std::pair<Rhp::request_id, Rhp::result<Rhp::script::value_list>>> results;
    std::vector<Rhp::value> emitted;
    std::vector<std::pair<Rhp::request_id, Rhp::module_id>> emit_sources;
    std::vector<std::string> log; // print and emit, interleaved as they happened
};

// Script time the test moves by hand.
struct manual_clock {
    clock_type::time_point now = clock_type::time_point{} + std::chrono::hours{1};

    void advance(milliseconds ms) { now += ms; }
    [[nodiscard]] Rhp::script::clock_fn fn() {
        return [this] { return now; };
    }
};

sandbox make_box(capture& out, Rhp::limits limits = {}, Rhp::script::clock_fn clock = {}) {
    fx::g_counter = 0;
    fx::g_stop = false;
    sandbox_options options;
    options.limits = limits;
    options.clock = std::move(clock);
    options.output = [&out](std::string_view line) {
        out.lines.emplace_back(line);
        out.log.push_back("print " + std::string{line});
    };
    options.on_result = [&out](Rhp::request_id id, const Rhp::result<Rhp::script::value_list>& r) { out.results.emplace_back(id, r); };
    options.on_emit = [&out](Rhp::request_id request, Rhp::module_id mod, const Rhp::value& v) {
        out.emitted.push_back(v);
        out.emit_sources.emplace_back(request, mod);
        out.log.emplace_back("emit");
    };
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::counter_lib>());
    REQUIRE(box.install<fx::host_lib>());
    return box;
}

// Points the host_lib bindings at a sandbox for one test.
struct bind_box {
    explicit bind_box(sandbox& box) { fx::g_box = &box; }
    bind_box(const bind_box&) = delete;
    bind_box& operator=(const bind_box&) = delete;
    ~bind_box() { fx::g_box = nullptr; }
};

Rhp::error error_of(const Rhp::result<Rhp::script::value_list>& r) {
    return r ? Rhp::make_error(errc::kOk, "unexpected success") : r.error();
}

Rhp::script::value_list values_or_error(const Rhp::result<Rhp::script::value_list>& r) {
    return r ? *r : Rhp::script::value_list{Rhp::value{"error: " + r.error().message}};
}

// Pumps until `out` has `count` results (at most `max_pumps` pumps); returns the pumps used.
int pump_until_results(sandbox& box, const capture& out, std::size_t count, int max_pumps) {
    int pumps = 0;
    while (out.results.size() < count && pumps < max_pumps) {
        box.pump();
        ++pumps;
    }
    return pumps;
}

// Keeps cancelling a request id from another thread (first after ~20 ms) while fn runs.
template <class Fn>
auto with_canceller(sandbox& box, std::optional<Rhp::request_id> request, Fn&& fn) {
    std::jthread canceller{[&box, request](const std::stop_token& stop) {
        while (!stop.stop_requested()) {
            std::this_thread::sleep_for(milliseconds{20});
            if (request) {
                box.cancel(*request);
            } else {
                box.cancel();
            }
        }
    }};
    auto r = fn();
    canceller.request_stop();
    canceller.join();
    return r;
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

// ---- requests and on_result ---------------------------------------------------------------------------

TEST_CASE("requests that finish at once never reach on_result", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    CHECK(box.exec<int>("return 7") == 7);
    const Rhp::request_id first = box.last_request();
    CHECK(first.valid());

    const auto failed = box.exec("error('sync')");
    REQUIRE_FALSE(failed.has_value());
    CHECK(box.last_request() > first);

    const auto mod = box.load("tests.sched.plain", "function f() return 1 end");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "f"));
    box.pump();
    CHECK(out.results.empty());
    CHECK(box.suspended() == 0);
}

TEST_CASE("a suspended exec returns early and reports through on_result", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto r = box.exec("counter.value = 1 rhp.next_frame() counter.value = 2 return 'a', 2");
    REQUIRE(r.has_value());
    CHECK(r->empty());
    const Rhp::request_id id = box.last_request();
    CHECK(box.suspended() == 1);
    CHECK(fx::g_counter == 1);

    box.pump();
    CHECK(box.suspended() == 0);
    CHECK(fx::g_counter == 2); // a finished exec keeps its effects
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == id);
    REQUIRE(out.results[0].second.has_value());
    CHECK(*out.results[0].second == Rhp::script::value_list{Rhp::value{"a"}, Rhp::value{2}});
}

TEST_CASE("a suspended exec that fails reverts only its own effects", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("counter.value = 5"));
    REQUIRE(box.exec("counter.value = 9 rhp.next_frame() error('late failure')"));
    CHECK(fx::g_counter == 9);
    box.pump();
    REQUIRE(out.results.size() == 1);
    REQUIRE_FALSE(out.results[0].second.has_value());
    CHECK(out.results[0].second.error().code == errc::kRuntime);
    CHECK(out.results[0].second.error().message.find("late failure") != std::string::npos);
    CHECK(fx::g_counter == 5);
}

TEST_CASE("a suspended load leaves the module loading until it finishes", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.slow_load", R"lua(
        counter.value = 1
        rhp.wait(2)
        function get() return counter.value end
        function on_load() counter.value = counter.value + 10 end
    )lua");
    REQUIRE(mod.has_value());
    const Rhp::request_id id = box.last_request();
    CHECK(box.status(*mod)->state == module_state::kLoading);
    CHECK(box.suspended() == 1);

    const auto early = box.call(*mod, "get");
    REQUIRE_FALSE(early.has_value());
    CHECK(early.error().code == errc::kInvalidArgument);

    box.pump();
    CHECK(box.status(*mod)->state == module_state::kLoading);
    box.pump();
    CHECK(box.status(*mod)->state == module_state::kActive);
    CHECK(fx::g_counter == 11);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == id);
    CHECK(out.results[0].second.has_value());
    CHECK(box.call(*mod, "get")->at(0) == Rhp::value{11});
}

TEST_CASE("a suspended call returns early; its values arrive through on_result", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.slow_call", "function twice(x) rhp.next_frame() return x * 2 end");
    REQUIRE(mod.has_value());
    const auto r = box.call(*mod, "twice", 21);
    REQUIRE(r.has_value());
    CHECK(r->empty());
    const Rhp::request_id id = box.last_request();
    box.pump();
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == id);
    REQUIRE(out.results[0].second.has_value());
    CHECK(out.results[0].second->at(0) == Rhp::value{42});
}

TEST_CASE("suspended() counts every suspended request", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("rhp.wait(1)"));
    REQUIRE(box.exec("rhp.wait(2)"));
    REQUIRE(box.exec("rhp.wait(3)"));
    CHECK(box.suspended() == 3);
    box.pump();
    CHECK(box.suspended() == 2);
    box.pump();
    CHECK(box.suspended() == 1);
    box.pump();
    CHECK(box.suspended() == 0);
    CHECK(out.results.size() == 3);
}

// ---- waits ------------------------------------------------------------------------------------------------

TEST_CASE("rhp.wait(n) wakes on the nth pump; frame counts pumps", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    CHECK(box.frame() == 0);
    CHECK(box.exec<int>("return rhp.frame()") == 0);
    REQUIRE(box.exec("rhp.wait(3) counter.value = 1 return rhp.frame()"));
    box.pump();
    box.pump();
    CHECK(fx::g_counter == 0);
    CHECK(box.frame() == 2);
    box.pump();
    CHECK(fx::g_counter == 1);
    CHECK(box.frame() == 3);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].second->at(0) == Rhp::value{3});
    CHECK(box.exec<int>("return rhp.frame()") == 3);
}

TEST_CASE("rhp.wait clamps to one frame and rejects non-integers", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    for (const std::string_view source : {"rhp.wait(0)", "rhp.wait(-7)", "rhp.wait()", "rhp.wait(nil)", "rhp.next_frame()"}) {
        CAPTURE(source);
        out.results.clear();
        REQUIRE(box.exec(std::string{source} + " counter.value = counter.value + 1"));
        const int before = fx::g_counter;
        CHECK(box.suspended() == 1);
        box.pump();
        CHECK(box.suspended() == 0);
        CHECK(fx::g_counter == before + 1);
        CHECK(out.results.size() == 1);
    }

    REQUIRE(box.exec("rhp.wait(2.0) counter.value = 100")); // an integral float is a frame count
    box.pump();
    CHECK(fx::g_counter != 100);
    box.pump();
    CHECK(fx::g_counter == 100);

    for (const std::string_view source : {"rhp.wait(1.5)", "rhp.wait('2')", "rhp.wait({})"}) {
        CAPTURE(source);
        const auto r = box.exec(source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kTypeMismatch);
    }
    CHECK(box.suspended() == 0);
}

TEST_CASE("a pump resumes only requests that were ready when it started", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.exec("rhp.next_frame() print('one') rhp.next_frame() print('two')"));
    REQUIRE(box.load("tests.sched.ready", "rhp.timer(0, function() print('timer') rhp.next_frame() print('timer again') end)"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"timer", "one"});
    box.pump();
    // Round robin: the pump starts after the request it resumed last (the exec), so the timer's goes first.
    CHECK(out.lines == std::vector<std::string>{"timer", "one", "timer again", "two"});
}

TEST_CASE("coroutine.yield at the top level suspends until the next pump", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto r = box.exec("local got = coroutine.yield(1, 2) counter.value = 5 return got == nil");
    REQUIRE(r.has_value());
    CHECK(r->empty());
    CHECK(box.suspended() == 1);
    box.pump();
    CHECK(fx::g_counter == 5);
    REQUIRE(out.results.size() == 1);
    REQUIRE(out.results[0].second.has_value());
    CHECK(out.results[0].second->at(0) == Rhp::value{true});

    // Coroutines the script creates still work normally.
    const auto own = box.exec("local co = coroutine.create(function(x) local y = coroutine.yield(x + 1) return y * 2 end) "
                              "local _, a = coroutine.resume(co, 1) local _, b = coroutine.resume(co, 10) return a, b");
    REQUIRE(own.has_value());
    CHECK(*own == Rhp::script::value_list{Rhp::value{2}, Rhp::value{20}});
}

// ---- sleep and the script clock --------------------------------------------------------------------------

TEST_CASE("rhp.sleep follows the script clock", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.exec("rhp.sleep(100) counter.value = 1"));
    box.pump();
    CHECK(fx::g_counter == 0);
    clock.advance(milliseconds{99});
    box.pump();
    box.pump();
    CHECK(fx::g_counter == 0);
    clock.advance(milliseconds{1});
    box.pump();
    CHECK(fx::g_counter == 1);
    CHECK(out.results.size() == 1);

    // Frames don't matter, only the clock: a long jump wakes it on the first pump.
    REQUIRE(box.exec("rhp.sleep(5000) counter.value = 2"));
    clock.advance(milliseconds{60'000});
    box.pump();
    CHECK(fx::g_counter == 2);

    // sleep(0) wakes at the next pump.
    REQUIRE(box.exec("rhp.sleep(0) counter.value = 3"));
    CHECK(fx::g_counter == 2);
    box.pump();
    CHECK(fx::g_counter == 3);

    // Fractions of a millisecond are fine.
    REQUIRE(box.exec("rhp.sleep(0.5) counter.value = 4"));
    box.pump();
    CHECK(fx::g_counter == 3);
    clock.advance(milliseconds{1});
    box.pump();
    CHECK(fx::g_counter == 4);
}

TEST_CASE("rhp.sleep rejects negative and non-number durations", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    for (const std::string_view source : {"rhp.sleep(-1)", "rhp.sleep('5')", "rhp.sleep()", "rhp.sleep(0/0)"}) {
        CAPTURE(source);
        const auto r = box.exec(source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kInvalidArgument);
    }
    CHECK(box.suspended() == 0);
}

// ---- who may suspend ---------------------------------------------------------------------------------------

TEST_CASE("only a request's own thread can suspend", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);

    SECTION("a coroutine the script created") {
        for (const std::string_view source : {"local co = coroutine.wrap(function() rhp.wait(1) end) co()",
                                              "local co = coroutine.wrap(function() rhp.next_frame() end) co()",
                                              "local co = coroutine.wrap(function() rhp.sleep(1) end) co()"}) {
            CAPTURE(source);
            const auto r = box.exec(source);
            REQUIRE_FALSE(r.has_value());
            CHECK(r.error().code == errc::kInvalidArgument);
        }
    }

    SECTION("a callback of a C function") {
        const auto r = box.exec("table.sort({3, 1, 2}, function(a, b) rhp.next_frame() return a < b end)");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kInvalidArgument);
    }

    SECTION("a patch handler game code triggers") {
        const auto mod = box.load("tests.sched.patch_wait", R"lua(
            rhp.patch("tests.sched.damage", function(original, base, target) rhp.wait(1) return 0 end)
        )lua");
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 6.0f); // the handler failed: the default ran
        box.pump();
        const auto info = box.status(*mod);
        REQUIRE(info.has_value());
        CHECK(info->state == module_state::kFaulted);
        REQUIRE(info->fault.has_value());
        CHECK(info->fault->code == errc::kInvalidArgument);
        CHECK(fx::damage.depth() == 0);
    }

    SECTION("a patch handler inside a run faults its module when the run ends") {
        bind_box bound{box};
        const auto mod = box.load("tests.sched.patch_wait", R"lua(
            rhp.patch("tests.sched.damage", function(original, base, target) rhp.wait(1) return 0 end)
        )lua");
        REQUIRE(mod.has_value());
        const auto r = box.exec("local hit = host.hit(2) return hit, host.state('tests.sched.patch_wait')");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{2.0}, Rhp::value{"active"}});
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->code == errc::kInvalidArgument);
    }
    CHECK(box.suspended() == 0);
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("request coroutines can't be resumed or closed by scripts", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("held = coroutine.running() rhp.next_frame() counter.value = 1"));
    REQUIRE(box.suspended() == 1);

    for (const std::string_view source : {"return coroutine.resume(held)", "return coroutine.close(held)"}) {
        CAPTURE(source);
        const auto r = box.exec(source);
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().code == errc::kInvalidArgument);
    }
    CHECK(box.exec<std::string>("return coroutine.status(held)") == "suspended");

    // A request can't resume itself either.
    const auto self = box.exec("return coroutine.resume(coroutine.running())");
    REQUIRE_FALSE(self.has_value());
    CHECK(self.error().code == errc::kInvalidArgument);

    box.pump();
    CHECK(fx::g_counter == 1);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].second.has_value());
}

// ---- time slicing --------------------------------------------------------------------------------------------

TEST_CASE("a time slice yields a long request; it continues at the next pump", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.slice_us = 2'000;
    sandbox box = make_box(out, limits);
    const auto started = clock_type::now();
    const auto r = box.exec("local n = 0 while not host.stop do n = n + 1 end return n");
    REQUIRE(r.has_value());
    CHECK(r->empty());
    for (int i = 0; i < 3; ++i) {
        box.pump();
        CHECK(box.suspended() == 1);
    }
    CHECK(clock_type::now() - started < std::chrono::seconds{5});
    CHECK(out.results.empty());

    fx::g_stop = true;
    box.pump();
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    REQUIRE(out.results[0].second.has_value());
    const auto* n = out.results[0].second->at(0).get_if<std::int64_t>();
    REQUIRE(n != nullptr);
    CHECK(*n > 0);
}

TEST_CASE("loads, calls and game-code events each get a time slice", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.slice_us = 2'000;
    sandbox box = make_box(out, limits);

    const auto mod = box.load("tests.sched.sliced", R"lua(
        while not host.stop do end
        function spin() while not host.stop do end return "spun" end
        rhp.on("tests.sched.ping", function(n) while not host.stop do end counter.value = n end)
    )lua");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->state == module_state::kLoading);
    fx::g_stop = true;
    // One pump gives each ready request its slice; a busy machine can preempt us mid-slice, so
    // pump (boundedly) until the work is done rather than assuming one pump is enough.
    for (int i = 0; i < 50 && box.status(*mod)->state != module_state::kActive; ++i) {
        box.pump();
    }
    REQUIRE(box.status(*mod)->state == module_state::kActive);

    fx::g_stop = false;
    const auto r = box.call(*mod, "spin");
    REQUIRE(r.has_value());
    CHECK(r->empty());
    CHECK(box.suspended() == 1);

    fx::ping.fire(4, "x"); // a synchronous delivery from game code: its own slice
    CHECK(box.suspended() == 2);
    CHECK(fx::g_counter == 0);

    fx::g_stop = true;
    for (int i = 0; i < 50 && box.suspended() != 0; ++i) {
        box.pump();
    }
    CHECK(box.suspended() == 0);
    CHECK(fx::g_counter == 4);
    REQUIRE(out.results.size() == 3);
    CHECK(out.results[1].second->at(0) == Rhp::value{"spun"});
}

TEST_CASE("time slices never yield a coroutine the script created or a C callback", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.slice_us = 1'000;
    sandbox box = make_box(out, limits);
    const auto r = box.exec(R"lua(
        local function busy(seconds) local t = os.clock() while os.clock() - t < seconds do end end
        local co = coroutine.wrap(function() busy(0.02) return "inner" end)
        local inner = co()
        local sorted = { 3, 1, 2 }
        table.sort(sorted, function(a, b) busy(0.005) return a < b end)
        return inner, sorted[1], sorted[3]
    )lua");
    REQUIRE(r.has_value());
    Rhp::script::value_list values = *r;
    if (values.empty()) {
        pump_until_results(box, out, 1, 1'000);
        REQUIRE(out.results.size() == 1);
        REQUIRE(out.results[0].second.has_value());
        values = *out.results[0].second;
    }
    CHECK(values == Rhp::script::value_list{Rhp::value{"inner"}, Rhp::value{1}, Rhp::value{3}});
}

TEST_CASE("pump stops at the end of its slice and shares slices round robin", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.slice_us = 2'000;
    sandbox box = make_box(out, limits);
    REQUIRE(box.exec("while not host.stop do end return 'hog'")); // eats any slice it gets
    REQUIRE(box.exec("rhp.next_frame() counter.value = 1 return 'patient'"));
    CHECK(box.suspended() == 2);
    box.pump(); // the hog is resumed first and uses up the whole slice
    CHECK(fx::g_counter == 0);
    box.pump(); // round robin: the other request goes first this time
    CHECK(fx::g_counter == 1);
    fx::g_stop = true;
    box.pump();
    CHECK(box.suspended() == 0);
    CHECK(out.results.size() == 2);
}

// ---- cancel ----------------------------------------------------------------------------------------------------

TEST_CASE("cancel(request) ends a suspended request at the next pump", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("counter.value = 3"));
    REQUIRE(box.exec("counter.value = 4 rhp.wait(100) counter.value = 5"));
    const Rhp::request_id id = box.last_request();
    box.cancel(id);
    CHECK(box.suspended() == 1); // not before the next operation or pump
    box.pump();
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == id);
    REQUIRE_FALSE(out.results[0].second.has_value());
    CHECK(out.results[0].second.error().code == errc::kCancelled);
    CHECK(fx::g_counter == 3); // only the cancelled request's effects were reverted
}

TEST_CASE("cancel(request) is applied by the next operation too", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("rhp.wait(100)"));
    box.cancel(box.last_request());
    CHECK(box.exec<int>("return 1") == 1);
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(error_of(out.results[0].second).code == errc::kCancelled);
}

TEST_CASE("cancelling a module's request faults the module", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.cancel_call", "counter.value = 1 function slow() counter.value = 2 rhp.wait(100) end");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "slow"));
    CHECK(fx::g_counter == 2);
    box.cancel(box.last_request());
    box.pump();
    const auto info = box.status(*mod);
    REQUIRE(info.has_value());
    CHECK(info->state == module_state::kFaulted);
    REQUIRE(info->fault.has_value());
    CHECK(info->fault->code == errc::kCancelled);
    CHECK(fx::g_counter == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(error_of(out.results[0].second).code == errc::kCancelled);
}

TEST_CASE("cancel(request) stops a running request from another thread", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("return 0"));
    const Rhp::request_id next{box.last_request().value() + 1};
    const auto r = with_canceller(box, next, [&box] { return box.exec("while true do end"); });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kCancelled);
    CHECK(box.last_request() == next);
    CHECK(box.exec<int>("return 2") == 2);
}

TEST_CASE("cancel() leaves suspended requests alone; unknown ids are harmless", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("rhp.next_frame() counter.value = 1"));
    box.cancel();
    box.cancel(Rhp::request_id{987'654});
    box.pump();
    CHECK(fx::g_counter == 1);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].second.has_value());
    CHECK(box.exec<int>("return 3") == 3);
}

// ---- limits across resumes ---------------------------------------------------------------------------------------

TEST_CASE("wall_ms stops a request with kTimeout", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.wall_ms = 50;
    sandbox box = make_box(out, limits);
    const auto r = box.exec("while true do end");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kTimeout);
    const auto stubborn = box.exec("while true do pcall(function() while true do end end) end");
    REQUIRE_FALSE(stubborn.has_value());
    CHECK(stubborn.error().code == errc::kTimeout);
    CHECK(box.exec<int>("return 1") == 1);
}

TEST_CASE("wall time is summed over a request's resumes; suspended time is free", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.wall_ms = 300;
    limits.slice_us = 20'000;
    sandbox box = make_box(out, limits);

    REQUIRE(box.exec("while true do end"));
    const int pumps = pump_until_results(box, out, 1, 400);
    REQUIRE(out.results.size() == 1);
    CHECK(error_of(out.results[0].second).code == errc::kTimeout);
    CHECK(pumps >= 3); // ~15 slices of 20 ms; no single resume reaches 300 ms

    out.results.clear();
    REQUIRE(box.exec("rhp.next_frame() return 'idle'"));
    std::this_thread::sleep_for(milliseconds{400});
    box.pump();
    REQUIRE(out.results.size() == 1);
    REQUIRE(out.results[0].second.has_value());
    CHECK(out.results[0].second->at(0) == Rhp::value{"idle"});
}

TEST_CASE("instruction budgets are per request, summed over resumes", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.instructions = 60'000;
    sandbox box = make_box(out, limits);

    // Three requests of ~30k instructions each: their total is over the limit, each one isn't.
    constexpr std::string_view kModest = "for i = 1, 12 do local s = 0 for j = 1, 1000 do s = s + j end rhp.next_frame() end return 'ok'";
    REQUIRE(box.exec(kModest));
    REQUIRE(box.exec(kModest));
    REQUIRE(box.exec(kModest));
    pump_until_results(box, out, 3, 50);
    REQUIRE(out.results.size() == 3);
    for (const auto& [id, r] : out.results) {
        CHECK(r.has_value());
    }

    // One request whose resumes each fit but whose sum doesn't.
    out.results.clear();
    REQUIRE(box.exec("for i = 1, 60 do local s = 0 for j = 1, 1000 do s = s + j end rhp.next_frame() end return 'never'"));
    pump_until_results(box, out, 1, 100);
    REQUIRE(out.results.size() == 1);
    CHECK(error_of(out.results[0].second).code == errc::kBudgetExceeded);
}

TEST_CASE("a handler fault from game code is applied by the next operation too", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    {
        const auto mod = box.load("tests.sched.fail_patch", R"lua(
            counter.value = 1
            rhp.patch("tests.sched.damage", function(original, base, target) error("handler broke") end)
        )lua");
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 6.0f);
        CHECK(box.status(*mod)->state == module_state::kActive);
        CHECK(box.exec<int>("return counter.value") == 0); // the fault was applied first
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->message.find("handler broke") != std::string::npos);
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("patch handlers game code triggers run with fresh budgets", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.instructions = 50'000;
    sandbox box = make_box(out, limits);
    {
        const auto mod = box.load("tests.sched.busy_patch", R"lua(
            rhp.patch("tests.sched.damage", function(original, base, target)
                local s = 0 for i = 1, 5000 do s = s + i end
                return original(base, target) + 1
            end)
        )lua");
        REQUIRE(mod.has_value());
        for (int i = 0; i < 30; ++i) { // ~30 x 10k instructions in total
            CHECK(fx::damage(2.0f, 3) == 7.0f);
        }
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kActive);
        REQUIRE(box.unload(*mod));
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("a stopped patch handler falls back and faults its module at the next pump", "[script][scheduler]") {
    capture out;
    constexpr std::string_view kSpin = R"lua(
        counter.value = 1
        rhp.patch("tests.sched.damage", function(original, base, target) while true do end end)
    )lua";

    SECTION("instruction budget") {
        Rhp::limits limits;
        limits.instructions = 50'000;
        sandbox box = make_box(out, limits);
        const auto mod = box.load("tests.sched.spin_patch", kSpin);
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 6.0f);
        CHECK(box.status(*mod)->state == module_state::kActive);
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->code == errc::kBudgetExceeded);
        CHECK(fx::g_counter == 0);
    }

    SECTION("wall time") {
        Rhp::limits limits;
        limits.wall_ms = 50;
        sandbox box = make_box(out, limits);
        const auto mod = box.load("tests.sched.spin_patch", kSpin);
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 6.0f);
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->code == errc::kTimeout);
    }

    SECTION("cancel from another thread") {
        sandbox box = make_box(out);
        const auto mod = box.load("tests.sched.spin_patch", kSpin);
        REQUIRE(mod.has_value());
        const float hit = with_canceller(box, std::nullopt, [] { return fx::damage(2.0f, 3); });
        CHECK(hit == 6.0f);
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->code == errc::kCancelled);
    }
    CHECK(fx::damage.depth() == 0);
}

// ---- timers ---------------------------------------------------------------------------------------------------------

TEST_CASE("a one-shot timer fires once when the script clock reaches it", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    const auto mod = box.load("tests.sched.timer_once", R"lua(
        id = rhp.timer(100, function() print("fired") end)
        function get_id() return id end
        function try_off() local ok, err = pcall(rhp.off, id) return ok, tostring(err) end
    )lua");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->effects == 1);
    const auto id = box.call(*mod, "get_id");
    REQUIRE(id.has_value());
    CHECK(id->at(0).is_integer());

    box.pump();
    clock.advance(milliseconds{99});
    box.pump();
    CHECK(out.lines.empty());
    clock.advance(milliseconds{1});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"fired"});
    CHECK(box.status(*mod)->effects == 0); // a spent one-shot leaves the ledger
    clock.advance(milliseconds{1'000});
    box.pump();
    CHECK(out.lines.size() == 1);

    const auto off = box.call(*mod, "try_off");
    REQUIRE(off.has_value());
    CHECK(off->at(0) == Rhp::value{false});
    CHECK(box.status(*mod)->state == module_state::kActive);
}

TEST_CASE("a repeating timer fires at most once per pump", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    const auto mod = box.load("tests.sched.timer_repeat", "rhp.timer(10, function() print('tick') end, true)");
    REQUIRE(mod.has_value());
    box.pump();
    CHECK(out.lines.empty());
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines.size() == 1);
    clock.advance(milliseconds{35}); // three intervals behind: one call, no burst
    box.pump();
    CHECK(out.lines.size() == 2);
    box.pump();
    CHECK(out.lines.size() == 2);
    clock.advance(milliseconds{9}); // the next one is due 10 ms after the late call
    box.pump();
    CHECK(out.lines.size() == 2);
    clock.advance(milliseconds{1});
    box.pump();
    CHECK(out.lines.size() == 3);
    CHECK(box.status(*mod)->effects == 1); // a repeating timer stays in the ledger
}

TEST_CASE("timers due in the same pump fire in due order", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.load("tests.sched.timer_order", R"lua(
        rhp.timer(30, function() print("c") end)
        rhp.timer(10, function() print("a") end)
        rhp.timer(20, function() print("b") end)
    )lua"));
    clock.advance(milliseconds{100});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a", "b", "c"});
}

TEST_CASE("revert, unload and a reload swap remove timers", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    const auto mod = box.load("tests.sched.timer_gone", "rhp.timer(10, function() print('a') end, true)");
    REQUIRE(mod.has_value());
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a"});

    REQUIRE(box.revert(*mod));
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a"});

    REQUIRE(box.reload(*mod, "rhp.timer(10, function() print('b') end, true)"));
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a", "b"});

    REQUIRE(box.reload(*mod, "rhp.timer(10, function() print('c') end, true)")); // swap: 'b' goes
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a", "b", "c"});

    REQUIRE(box.unload(*mod));
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a", "b", "c"});

    // Scratch timers go with a scratch revert.
    REQUIRE(box.exec("rhp.timer(0, function() print('scratch') end)"));
    REQUIRE(box.revert(box.scratch_module()));
    box.pump();
    CHECK(out.lines.size() == 3);
}

TEST_CASE("rhp.off removes a timer; foreign and unknown ids give kNotFound", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    const auto mod = box.load("tests.sched.timer_off", R"lua(
        t = rhp.timer(10, function() print("x") end, true)
        function id() return t end
        function stop() rhp.off(t) end
    )lua");
    REQUIRE(mod.has_value());
    const auto id = box.call(*mod, "id");
    REQUIRE(id.has_value());
    const std::int64_t timer_id = *id->at(0).get_if<std::int64_t>();

    // Another module (here: scratch) can't remove it.
    const auto foreign = box.exec(std::format("rhp.off({})", timer_id));
    REQUIRE_FALSE(foreign.has_value());
    CHECK(foreign.error().code == errc::kNotFound);
    const auto unknown = box.exec("rhp.off(123456789)");
    REQUIRE_FALSE(unknown.has_value());
    CHECK(unknown.error().code == errc::kNotFound);
    for (const std::string_view source : {"rhp.off(0)", "rhp.off('1')", "rhp.off()"}) {
        CAPTURE(source);
        const auto bad = box.exec(source);
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kTypeMismatch);
    }

    REQUIRE(box.call(*mod, "stop"));
    CHECK(box.status(*mod)->effects == 0);
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines.empty());

    // A second off is an unknown id now; the failing call faults the module.
    const auto again = box.call(*mod, "stop");
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().code == errc::kNotFound);
    CHECK(box.status(*mod)->state == module_state::kFaulted);
}

TEST_CASE("rhp.timer validates its arguments", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto negative = box.exec("rhp.timer(-1, function() end)");
    REQUIRE_FALSE(negative.has_value());
    CHECK(negative.error().code == errc::kInvalidArgument);
    const auto not_function = box.exec("rhp.timer(10, 5)");
    REQUIRE_FALSE(not_function.has_value());
    CHECK(not_function.error().code == errc::kTypeMismatch);
    CHECK(box.effects().empty());
}

TEST_CASE("a failing timer callback faults its module", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    const auto mod = box.load("tests.sched.timer_boom", "counter.value = 1 rhp.timer(0, function() error('timer boom') end, true)");
    REQUIRE(mod.has_value());
    CHECK(fx::g_counter == 1);
    box.pump();
    const auto info = box.status(*mod);
    REQUIRE(info.has_value());
    CHECK(info->state == module_state::kFaulted);
    REQUIRE(info->fault.has_value());
    CHECK(info->fault->message.find("timer boom") != std::string::npos);
    CHECK(info->effects == 0);
    CHECK(fx::g_counter == 0);
    box.pump(); // the repeating timer went with the fault
    CHECK(box.status(*mod)->state == module_state::kFaulted);
}

TEST_CASE("timer callbacks are requests and may wait", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.load("tests.sched.timer_wait", "rhp.timer(0, function() print('start') rhp.next_frame() print('end') return 1 end)"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"start"});
    CHECK(box.suspended() == 1);
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"start", "end"});
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1); // it suspended, so its end is reported
    CHECK(out.results[0].second.has_value());
}

// ---- emit ---------------------------------------------------------------------------------------------------------------

TEST_CASE("rhp.emit streams values in order with print", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto r = box.exec("print('a') rhp.emit(1) print('b') rhp.emit({ 1, 2 }) rhp.emit({ k = 'v' }) rhp.emit(nil) return 'ret'");
    REQUIRE(r.has_value());
    CHECK(*r == Rhp::script::value_list{Rhp::value{"ret"}}); // emitted values are not results
    CHECK(out.log == std::vector<std::string>{"print a", "emit", "print b", "emit", "emit", "emit"});
    REQUIRE(out.emitted.size() == 4);
    CHECK(out.emitted[0] == Rhp::value{1});
    CHECK(out.emitted[1] == Rhp::value{Rhp::value::array{Rhp::value{1}, Rhp::value{2}}});
    CHECK(out.emitted[2].is_map());
    CHECK(out.emitted[3].is_nil());
    for (const auto& [request, mod] : out.emit_sources) {
        CHECK(request == box.last_request());
        CHECK(mod == box.scratch_module());
    }
}

TEST_CASE("rhp.emit names the request and module that emitted", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.emitter", "function go(x) rhp.emit(x) rhp.next_frame() rhp.emit(x + 1) end");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "go", 10));
    const Rhp::request_id id = box.last_request();
    box.pump();
    REQUIRE(out.emitted.size() == 2);
    CHECK(out.emitted[0] == Rhp::value{10});
    CHECK(out.emitted[1] == Rhp::value{11});
    for (const auto& [request, source] : out.emit_sources) {
        CHECK(request == id);
        CHECK(source == *mod);
    }
}

TEST_CASE("rhp.emit refuses values that don't convert; no callback is fine", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto bad = box.exec("rhp.emit(function() end)");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().code == errc::kTypeMismatch);
    CHECK(out.emitted.empty());

    sandbox quiet{sandbox_options{.output = [](std::string_view) {}}};
    CHECK(quiet.exec<int>("rhp.emit(1) rhp.emit({ 2 }) return 3") == 3);
}

// ---- lifecycle operations from inside a run -------------------------------------------------------------------------------

TEST_CASE("lifecycle operations called from a running script are deferred", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    bind_box bound{box};
    REQUIRE(box.checkpoint("before"));
    const auto mod = box.load("tests.sched.victim", "counter.value = 1 return {}");
    REQUIRE(mod.has_value());
    REQUIRE(fx::g_counter == 1);

    SECTION("revert") {
        const auto r = box.exec("local deferred = host.revert('tests.sched.victim') return deferred, counter.value, host.state('tests.sched.victim')");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{true}, Rhp::value{1}, Rhp::value{"active"}});
        CHECK(box.status(*mod)->state == module_state::kReverted);
        CHECK(fx::g_counter == 0);
    }

    SECTION("unload") {
        const auto r = box.exec("local deferred = host.unload('tests.sched.victim') return deferred, host.state('tests.sched.victim')");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{true}, Rhp::value{"active"}});
        CHECK_FALSE(box.find("tests.sched.victim").has_value());
        CHECK(fx::g_counter == 0);
    }

    SECTION("reload") {
        const auto r = box.exec("return host.reload('tests.sched.victim', 'counter.value = 2 return {}'), counter.value");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{0}, Rhp::value{1}});
        CHECK(box.status(*mod)->revision == Rhp::revision_id{2});
        CHECK(fx::g_counter == 2);
    }

    SECTION("rollback") {
        REQUIRE(box.reload(*mod, "counter.value = 2 return {}"));
        REQUIRE(fx::g_counter == 2);
        const auto r = box.exec("return host.rollback('tests.sched.victim'), counter.value");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{0}, Rhp::value{2}});
        CHECK(box.status(*mod)->revision == Rhp::revision_id{3});
        CHECK(fx::g_counter == 1);
    }

    SECTION("revert_to") {
        const auto r = box.exec("return host.revert_to('before'), counter.value");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{true}, Rhp::value{1}});
        CHECK(fx::g_counter == 0);
    }

    SECTION("revert_all") {
        const auto r = box.exec("return host.revert_all(), host.state('tests.sched.victim')");
        REQUIRE(r.has_value());
        CHECK(*r == Rhp::script::value_list{Rhp::value{true}, Rhp::value{"active"}});
        CHECK_FALSE(box.find("tests.sched.victim").has_value());
        CHECK(fx::g_counter == 0);
    }
}

TEST_CASE("lifecycle operations from a handler game code triggers wait for the next pump", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    bind_box bound{box};
    {
        const auto mod = box.load("tests.sched.self_revert", R"lua(
            counter.value = 1
            rhp.patch("tests.sched.damage", function(original, base, target)
                host.revert("tests.sched.self_revert")
                return original(base, target) + 1
            end)
        )lua");
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 7.0f);
        CHECK(box.status(*mod)->state == module_state::kActive);
        CHECK(fx::damage.depth() == 1);
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kReverted);
        CHECK(fx::damage.depth() == 0);
        CHECK(fx::g_counter == 0);
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("lifecycle operations outside a run are not deferred", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.direct", "counter.value = 1");
    REQUIRE(mod.has_value());
    const auto report = box.revert(*mod);
    REQUIRE(report.has_value());
    CHECK_FALSE(report->deferred);
    CHECK(report->undone == 1);
    const auto rev = box.reload(*mod, "counter.value = 2");
    REQUIRE(rev.has_value());
    CHECK(*rev == Rhp::revision_id{2});
    CHECK_FALSE(box.revert_all().deferred);
}

// ---- stubs ---------------------------------------------------------------------------------------------------------------

TEST_CASE("sandbox stubs: the rhp API, then every installed lib, for the caller's role", "[script][scheduler]") {
    namespace stubs = Rhp::script::stubs;
    for (const Rhp::role caller : {Rhp::role::kObserve, Rhp::role::kPatch, Rhp::role::kAdmin}) {
        CAPTURE(caller);
        sandbox_options options;
        options.caller_role = caller;
        options.output = [](std::string_view) {};
        sandbox box{std::move(options)};
        CHECK(box.stubs() == stubs::rhp_api(caller));
        REQUIRE(box.install<fx::counter_lib>());
        REQUIRE(box.install<fx::host_lib>());
        const std::string all = box.stubs();
        const std::string api = stubs::rhp_api(caller);
        const std::string counter = stubs::generate<fx::counter_lib>(caller);
        const std::string host = stubs::generate<fx::host_lib>(caller);
        CHECK(all.starts_with(api));
        const auto at_counter = all.find(counter, api.size());
        const auto at_host = all.find(host, api.size());
        REQUIRE(at_counter != std::string::npos);
        REQUIRE(at_host != std::string::npos);
        CHECK(at_counter < at_host); // install order
        CHECK(all.ends_with(host));
        CHECK(all.size() <= api.size() + counter.size() + host.size() + 4); // nothing but separators
        CHECK((all.find("function rhp.patch") != std::string::npos) == (caller != Rhp::role::kObserve));
        CHECK((counter.find("read-only") != std::string::npos) == (caller == Rhp::role::kObserve));
    }
}

// ---- more request edge cases ---------------------------------------------------------------------------------------

TEST_CASE("cancel(request) of a suspended request made inside a run is not lost", "[script][scheduler]") {
    capture out;
    Rhp::limits limits;
    limits.wall_ms = 2'000; // the safety net if the cancel is lost: kTimeout instead of a hang
    sandbox box = make_box(out, limits);
    bind_box bound{box};

    // B is resumed first in the pump and cancels A, which is still suspended at that moment.
    REQUIRE(box.exec("rhp.next_frame() host.cancel_target() local s = 0 for i = 1, 20000 do s = s + i end return 'b'"));
    const Rhp::request_id b = box.last_request();
    REQUIRE(box.exec("rhp.next_frame() while true do end"));
    const Rhp::request_id a = box.last_request();
    REQUIRE(b < a);
    fx::g_cancel_target = a.value();

    box.pump();
    pump_until_results(box, out, 2, 5);
    REQUIRE(out.results.size() == 2);
    for (const auto& [id, r] : out.results) {
        if (id == a) {
            CHECK(error_of(r).code == errc::kCancelled);
        } else {
            CHECK(r.has_value());
        }
    }
    CHECK(box.suspended() == 0);
}

TEST_CASE("cancelling a timer or event request faults its module", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());

    SECTION("event handler") {
        const auto mod = box.load("tests.sched.cancel_event", R"lua(
            counter.value = 1
            rhp.on("tests.sched.ping", function() rhp.emit("waiting") rhp.wait(100) end)
        )lua");
        REQUIRE(mod.has_value());
        fx::ping.fire(1, "");
        REQUIRE(out.emit_sources.size() == 1);
        box.cancel(out.emit_sources[0].first);
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->code == errc::kCancelled);
        CHECK(fx::ping.listeners() == 0);
    }

    SECTION("timer callback") {
        const auto mod = box.load("tests.sched.cancel_timer", R"lua(
            counter.value = 1
            rhp.timer(0, function() rhp.emit("waiting") rhp.wait(100) end)
        )lua");
        REQUIRE(mod.has_value());
        box.pump();
        REQUIRE(out.emit_sources.size() == 1);
        CHECK(out.emit_sources[0].second == *mod);
        box.cancel(out.emit_sources[0].first);
        box.pump();
        CHECK(box.status(*mod)->state == module_state::kFaulted);
        CHECK(box.status(*mod)->fault->code == errc::kCancelled);
    }
    CHECK(fx::g_counter == 0);
    CHECK(box.suspended() == 0);
}

TEST_CASE("a wait can sit inside pcall and xpcall", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("local ok = pcall(rhp.wait, 1) local ok2 = xpcall(rhp.next_frame, debug and debug.traceback or print) "
                     "counter.value = 1 return ok, ok2"));
    box.pump();
    CHECK(fx::g_counter == 0);
    box.pump();
    CHECK(fx::g_counter == 1);
    REQUIRE(out.results.size() == 1);
    CHECK(values_or_error(out.results[0].second) == Rhp::script::value_list{Rhp::value{true}, Rhp::value{true}});
}

TEST_CASE("rhp.frame inside a pump is that pump's number", "[script][scheduler]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, clock.fn());
    REQUIRE(box.load("tests.sched.frame", "rhp.timer(0, function() print(rhp.frame()) end, true)"));
    box.pump();
    box.pump();
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"1", "2", "3"});
}

TEST_CASE("on_result may re-enter the sandbox", "[script][scheduler]") {
    fx::g_counter = 0;
    sandbox* self = nullptr;
    std::vector<std::int64_t> seen;
    sandbox_options options;
    options.output = [](std::string_view) {};
    options.on_result = [&self, &seen](Rhp::request_id, const Rhp::result<Rhp::script::value_list>&) {
        const auto again = self->exec("counter.value = counter.value + 1 return counter.value");
        seen.push_back(again && !again->empty() ? *again->front().get_if<std::int64_t>() : -1);
    };
    sandbox box{std::move(options)};
    self = &box;
    REQUIRE(box.install<fx::counter_lib>());
    REQUIRE(box.exec("rhp.next_frame()"));
    REQUIRE(box.exec("rhp.next_frame()"));
    box.pump();
    CHECK(seen == std::vector<std::int64_t>{1, 2});
    CHECK(fx::g_counter == 2);
}

TEST_CASE("a fault abandons the module's other suspended requests", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.abandon", "function waiter() rhp.wait(100) end function boom() error('boom') end");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "waiter"));
    const Rhp::request_id waiter = box.last_request();
    REQUIRE(box.suspended() == 1);
    REQUIRE_FALSE(box.call(*mod, "boom").has_value());
    CHECK(box.status(*mod)->state == module_state::kFaulted);
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == waiter);
    CHECK(error_of(out.results[0].second).code == errc::kCancelled);
}

TEST_CASE("reverting the scratch module abandons suspended exec requests", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    REQUIRE(box.exec("counter.value = 1 rhp.wait(100) counter.value = 2"));
    REQUIRE(box.revert(box.scratch_module()));
    CHECK(fx::g_counter == 0);
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(error_of(out.results[0].second).code == errc::kCancelled);
    box.pump();
    CHECK(fx::g_counter == 0);
}

TEST_CASE("to-be-closed variables of a request that ends early are closed", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    constexpr std::string_view kGuard = "local guard <close> = setmetatable({}, { __close = function() print('closed') end }) ";

    SECTION("failed") {
        REQUIRE_FALSE(box.exec(std::string{kGuard} + "error('boom')").has_value());
    }
    SECTION("failed after a resume") {
        REQUIRE(box.exec(std::string{kGuard} + "rhp.next_frame() error('boom')"));
        box.pump();
    }
    SECTION("cancelled while suspended") {
        REQUIRE(box.exec(std::string{kGuard} + "rhp.wait(100)"));
        box.cancel(box.last_request());
        box.pump();
    }
    SECTION("abandoned by a revert") {
        REQUIRE(box.exec(std::string{kGuard} + "rhp.wait(100)"));
        REQUIRE(box.revert(box.scratch_module()));
    }
    SECTION("finished normally") {
        REQUIRE(box.exec(std::string{kGuard} + "rhp.next_frame()"));
        box.pump();
    }
    CHECK(out.lines == std::vector<std::string>{"closed"});
    CHECK(box.suspended() == 0);
}

TEST_CASE("a suspended first load that fails later faults the module", "[script][scheduler]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.sched.late_fail", "counter.value = 1 rhp.next_frame() error('late load')");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->state == module_state::kLoading);
    CHECK(fx::g_counter == 1);
    box.pump();
    const auto info = box.status(*mod);
    REQUIRE(info.has_value());
    CHECK(info->state == module_state::kFaulted);
    CHECK(fx::g_counter == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(error_of(out.results[0].second).message.find("late load") != std::string::npos);
}

TEST_CASE("destroying a sandbox with suspended requests reverts their effects", "[script][scheduler]") {
    capture out;
    {
        sandbox box = make_box(out);
        REQUIRE(box.exec("counter.value = 1 rhp.wait(10)"));
        const auto mod = box.load("tests.sched.dying", "function waiter() counter.value = 2 rhp.wait(10) end");
        REQUIRE(mod.has_value());
        REQUIRE(box.call(*mod, "waiter"));
        REQUIRE(box.load("tests.sched.dying_load", "rhp.next_frame()"));
        CHECK(box.suspended() == 3);
        CHECK(fx::g_counter == 2);
    }
    CHECK(fx::g_counter == 0);
    CHECK(fx::ping.listeners() == 0);
}
