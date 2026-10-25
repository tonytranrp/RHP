// The sandbox's test tools: the meter (checked against a plain Lua state counting every
// instruction), allocation counters, coverage, garbage collection, and the `__rhp_test` bridge.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/testing.hpp>

using Rhp::errc;
using Rhp::value;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace testing_tests_fixture {

inline int g_spawned = 0;
inline double g_speed = 1.0;

struct mob {
    int id = 0;
    bool operator==(const mob&) const = default;
};

inline int spawn(int n) {
    g_spawned += n;
    return g_spawned;
}
inline void despawn(int n) {
    g_spawned -= n;
}
inline bool mob_alive(mob) {
    return true;
}
inline mob make_mob(int id) {
    return mob{id};
}
inline int mob_hp(mob m) {
    return m.id * 10;
}
inline int mob_hit(mob m, int damage) {
    return m.id * 10 - damage;
}

using tt_lib = Rhp::lib<"ttest">::fn<"spawn", &spawn, Rhp::undo<&despawn>>::var<"speed", &g_speed>::handle<"mob", mob, &mob_alive>::fn<
    "make", &make_mob>::method<"hit", &mob_hit>::property<"hp", &mob_hp>;

inline int double_it(int v) {
    return v * 2;
}
inline constexpr Rhp::patch_point<"ttest.double", &double_it> double_point{};
inline constexpr Rhp::lua_event<"ttest.tick", int> tick_event{};

// A manual script clock.
struct manual_clock {
    std::chrono::steady_clock::time_point now{};
    Rhp::script::clock_fn fn() {
        return [this] { return now; };
    }
};

// Instructions a plain Lua state runs for `source`, counted one by one by a count hook.
std::uint64_t raw_instructions(std::string_view source) {
    static std::uint64_t counted = 0;
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);
    counted = 0;
    lua_sethook(L, [](lua_State*, lua_Debug*) { ++counted; }, LUA_MASKCOUNT, 1);
    REQUIRE(luaL_loadbufferx(L, source.data(), source.size(), "=raw", "t") == LUA_OK);
    const std::uint64_t before = counted;
    REQUIRE(lua_pcall(L, 0, LUA_MULTRET, 0) == LUA_OK);
    const std::uint64_t ran = counted - before;
    lua_close(L);
    return ran;
}

std::uint64_t metered_instructions(sandbox& box, std::string_view source) {
    const auto before = box.meter().instructions;
    const auto r = box.exec(source);
    REQUIRE(r.has_value());
    return box.meter().instructions - before;
}

} // namespace testing_tests_fixture

using namespace testing_tests_fixture;

TEST_CASE("the meter counts exactly the instructions a plain Lua state runs", "[script][testing]") {
    sandbox box;
    box.start_metering();
    const char* sources[] = {
        "local s = 0 for i = 1, 1000 do s = s + i end return s",
        "local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end return fib(15)",
        "local t = {} for i = 1, 300 do t[#t + 1] = tostring(i) end table.sort(t, function(a, b) return a > b end) return #t",
        "local co = coroutine.create(function(a) for i = 1, 50 do a = a + coroutine.yield(i) end return a end) "
        "local ok, v = coroutine.resume(co, 1) while coroutine.status(co) ~= 'dead' do ok, v = coroutine.resume(co, 2) end return v",
        "local gen = coroutine.wrap(function() for i = 1, 40 do coroutine.yield(i * i) end end) local s = 0 for i = 1, 40 do s = s + gen() end return s",
        "local ok = pcall(function() local x = nil; return x.y end) local mt = {__index = function(t, k) return k * 2 end} "
        "local p = setmetatable({}, mt) local s = 0 for i = 1, 20 do s = s + p[i] end return s",
        "local parts = {} for w in ('a b c d e f g h'):gmatch('%a') do parts[#parts + 1] = w:upper() end return table.concat(parts)",
    };
    for (const char* source : sources) {
        INFO(source);
        CHECK(metered_instructions(box, source) == raw_instructions(source));
    }
    // Twice: the counts don't drift between runs.
    CHECK(metered_instructions(box, sources[0]) == raw_instructions(sources[0]));
    box.stop_metering();
    const auto before = box.meter().instructions;
    REQUIRE(box.exec(sources[0]));
    CHECK(box.meter().instructions == before); // stopped
}

TEST_CASE("metering keeps instruction limits seeing coroutine work", "[script][testing]") {
    // Each resume runs under a thousand instructions, so the coroutine's own count hook never fires;
    // what the meter folds in at every resume must still reach the limit.
    sandbox box{sandbox_options{.limits = Rhp::limits{.instructions = 200'000}}};
    box.start_metering();
    const auto r = box.exec("local co = coroutine.wrap(function() while true do local s = 0 for i = 1, 120 do s = s + i end coroutine.yield() end end) "
                            "for i = 1, 3000 do co() end return 1");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kBudgetExceeded);
}

TEST_CASE("allocation counters track blocks bytes peak and object kinds", "[script][testing]") {
    sandbox box;
    REQUIRE(box.collect_garbage());
    box.reset_peak();
    const auto before = box.meter();
    REQUIRE(box.exec("big = {} for i = 1, 20000 do big[i] = {i} end"));
    const auto during = box.meter();
    CHECK(during.allocations - before.allocations >= 20000);
    CHECK(during.objects[static_cast<std::size_t>(Rhp::script::alloc_kind::kTable)] -
              before.objects[static_cast<std::size_t>(Rhp::script::alloc_kind::kTable)] >=
          20000);
    CHECK(during.bytes_allocated - before.bytes_allocated > 20000 * 32);
    CHECK(during.peak >= during.memory);
    CHECK(during.peak > before.memory + 20000 * 32);
    REQUIRE(box.exec("big = nil"));
    REQUIRE(box.collect_garbage());
    const auto after = box.meter();
    CHECK(after.memory < during.memory / 2);
    CHECK(after.frees > during.frees);
    CHECK(after.peak >= during.peak); // the peak never falls until reset
    box.reset_peak();
    CHECK(box.meter().peak == after.memory);
    REQUIRE(box.set_gc_mode(Rhp::script::gc_mode::kIncremental));
    REQUIRE(box.set_gc_mode(Rhp::script::gc_mode::kGenerational));
}

TEST_CASE("coverage knows every executable line and counts the ones that ran", "[script][testing]") {
    sandbox box;
    REQUIRE(box.start_coverage());
    const auto mod = box.load("cov.mod", "local M = {}\n"       // 1
                                         "function M.f(x)\n"    // 2
                                         "  if x > 0 then\n"    // 3
                                         "    return 'pos'\n"   // 4
                                         "  end\n"              // 5
                                         "  return 'neg'\n"     // 6
                                         "end\n"                // 7
                                         "function M.never()\n" // 8
                                         "  return 1\n"         // 9
                                         "end\n"                // 10
                                         "return M\n");         // 11
    REQUIRE(mod.has_value());
    for (int i = 0; i < 3; ++i) {
        REQUIRE(box.call(*mod, "f", 1));
    }
    const auto report = box.coverage();
    const auto* c = report.find("cov.mod");
    REQUIRE(c != nullptr);
    CHECK(c->lines == std::vector<std::uint32_t>{1, 2, 3, 4, 6, 7, 8, 9, 10, 11});
    const auto hits = [&](std::uint32_t line) -> std::uint64_t {
        const auto it = std::ranges::find(c->lines, line);
        return it == c->lines.end() ? ~std::uint64_t{0} : c->hits[static_cast<std::size_t>(it - c->lines.begin())];
    };
    CHECK(hits(1) == 1);
    CHECK(hits(3) == 3);
    CHECK(hits(4) == 3);
    CHECK(hits(6) == 0);
    CHECK(hits(9) == 0);
    CHECK(c->extra.empty());
    const auto stopped = box.stop_coverage();
    CHECK(stopped.find("cov.mod") != nullptr);
    REQUIRE(box.call(*mod, "f", -1));
    CHECK(box.coverage().chunks.empty());
}

TEST_CASE("the test bridge lives only in the scratch environment", "[script][testing]") {
    sandbox box;
    REQUIRE(box.enable_testing());
    CHECK(*box.exec("return type(__rhp_test)") == value_list{value{"table"}});
    REQUIRE(box.load("tt.peek", "seen = type(__rhp_test)\nfunction get() return seen end"));
    CHECK(*box.call(*box.find("tt.peek"), "get") == value_list{value{"nil"}});
    CHECK(box.enable_testing().error().code == errc::kAlreadyLoaded);
}

TEST_CASE("swapped lib members module exports and handle members come back with the checkpoint", "[script][testing]") {
    g_spawned = 0;
    g_speed = 1.0;
    sandbox box;
    REQUIRE(box.install<tt_lib>());
    REQUIRE(box.enable_testing());
    REQUIRE(box.load("tt.exports", "local M = {}\nfunction M.greet() return 'hi' end\nreturn M"));
    REQUIRE(box.checkpoint("before"));
    // A lib function.
    CHECK(*box.exec("local orig = __rhp_test.swap(ttest, 'spawn', function(n) return -n end) return ttest.spawn(4), type(orig), orig(2)") ==
          value_list{value{-4}, value{"function"}, value{2}});
    CHECK(g_spawned == 2);
    // A module export, through its require() proxy.
    CHECK(*box.exec("local m = require('tt.exports') __rhp_test.swap(m, 'greet', function() return 'stubbed' end) return m.greet()") ==
          value_list{value{"stubbed"}});
    // A handle's method and property (every handle of the type).
    CHECK(*box.exec("local e = ttest.make(3) __rhp_test.swap(e, 'hit', function(self, d) return 99 end) "
                    "__rhp_test.swap(e, 'hp', function(self) return -1 end) return e:hit(1), e.hp") == value_list{value{99}, value{-1}});
    // A variable: a getter and a setter of our own.
    CHECK(*box.exec("local store = 5 __rhp_test.swap_var(ttest, 'speed', function() return store end, function(v) store = v * 10 end) "
                    "ttest.speed = 2 return ttest.speed") == value_list{value{20}});
    CHECK(g_speed == 1.0); // the real variable never saw it
    CHECK(box.exec("__rhp_test.swap(ttest, 'speed', 1)").error().code == errc::kInvalidArgument);
    CHECK(*box.exec("return __rhp_test.kind(ttest), __rhp_test.kind(require('tt.exports')), __rhp_test.kind(ttest.make(1)), __rhp_test.kind({})") ==
          value_list{value{"lib"}, value{"module"}, value{"handle"}, value{"table"}});
    CHECK(*box.exec("local m = __rhp_test.members(ttest) return m.spawn, m.speed, m.make") == value_list{value{"function"}, value{"variable"}, value{"function"}});
    CHECK(*box.exec("local m = __rhp_test.members(ttest.make(1)) return m.hit, m.hp") == value_list{value{"method"}, value{"property"}});

    REQUIRE(box.revert_to("before"));
    CHECK(*box.exec("return ttest.spawn(1), require('tt.exports').greet(), ttest.make(3):hit(1), ttest.make(3).hp, ttest.speed") ==
          value_list{value{1}, value{"hi"}, value{29}, value{30}, value{1.0}}); // the swapped call's spawn(2) was undone too
    (void)box.revert_all();
    CHECK(g_spawned == 0);
}

TEST_CASE("next_due follows the earliest timer and sleeping request", "[script][testing]") {
    manual_clock clock;
    sandbox box{sandbox_options{.clock = clock.fn()}};
    CHECK_FALSE(box.next_due().has_value());
    REQUIRE(box.exec("rhp.after(500, function() end) rhp.after(200, function() end)"));
    REQUIRE(box.next_due().has_value());
    CHECK(*box.next_due() - clock.now == std::chrono::milliseconds{200});
    REQUIRE(box.exec("rhp.sleep(50)"));
    CHECK(*box.next_due() - clock.now == std::chrono::milliseconds{50});
    clock.now += std::chrono::milliseconds{60};
    box.pump();
    CHECK(*box.next_due() - clock.now == std::chrono::milliseconds{140});
    REQUIRE(box.exec("local id = rhp.every_frame(function() end)"));
    CHECK(*box.next_due() - clock.now == std::chrono::milliseconds{140}); // frames don't wait for time
}

TEST_CASE("events and patch points are fired and called by name", "[script][testing]") {
    sandbox box;
    REQUIRE(box.enable_testing());
    REQUIRE(box.exec("total = 0 rhp.on('ttest.tick', function(n) total = total + n end)"));
    tick_event.fire(0); // registers the event (a program that fires it)
    const value three[] = {value{3}};
    REQUIRE(box.fire_event("ttest.tick", three));
    REQUIRE(box.exec("__rhp_test.fire('ttest.tick', 4)"));
    CHECK(*box.exec("return total") == value_list{value{7}});
    CHECK(box.fire_event("ttest.tick", {}).error().code == errc::kInvalidArgument);
    CHECK(box.fire_event("ttest.nope", three).error().code == errc::kNotFound);

    CHECK(double_point(5) == 10); // registers the point
    const value five[] = {value{5}};
    CHECK(*box.call_point("ttest.double", five) == value_list{value{10}});
    REQUIRE(box.exec("rhp.patch('ttest.double', function(original, v) return original(v) + 1 end)"));
    CHECK(*box.call_point("ttest.double", five) == value_list{value{11}});
    CHECK(*box.exec("return __rhp_test.call_point('ttest.double', 7)") == value_list{value{15}});
    const value text[] = {value{"x"}};
    CHECK(box.call_point("ttest.double", text).error().code == errc::kTypeMismatch);
    (void)box.revert_all();
    CHECK(double_point(5) == 10);
}

TEST_CASE("os.time and os.clock follow the script clock in test sandboxes", "[script][testing]") {
    manual_clock clock;
    sandbox box{sandbox_options{.clock = clock.fn()}};
    REQUIRE(box.enable_testing(Rhp::script::testing_options{.host = {}, .fake_os_epoch = 1'700'000'000}));
    CHECK(*box.exec("return os.time(), os.clock()") == value_list{value{1'700'000'000}, value{0.0}});
    clock.now += std::chrono::milliseconds{2500};
    CHECK(*box.exec("return os.time(), os.clock(), __rhp_test.now()") == value_list{value{1'700'000'002}, value{2.5}, value{2500.0}});
    CHECK(*box.exec("return os.time({year = 2020, month = 1, day = 1, hour = 12}) > 0") == value_list{value{true}});
}

TEST_CASE("the bridge meter reads the running thread too", "[script][testing]") {
    sandbox box;
    REQUIRE(box.enable_testing());
    box.start_metering();
    const auto r = box.exec("local a = __rhp_test.meter().instructions local s = 0 for i = 1, 500 do s = s + i end "
                            "local b = __rhp_test.meter().instructions return b - a");
    REQUIRE(r.has_value());
    const auto ran = r->front().get_if<std::int64_t>();
    REQUIRE(ran != nullptr);
    CHECK(*ran >= 1000); // two instructions per iteration (ADD, FORLOOP), plus the reads around it
    CHECK(*ran < 1050);
}

TEST_CASE("the test host answers the framework", "[script][testing]") {
    sandbox box;
    std::vector<std::string> seen;
    REQUIRE(box.enable_testing(Rhp::script::testing_options{
        .host = [&](std::string_view cmd, std::span<const value> args) -> Rhp::result<value> {
            seen.emplace_back(cmd);
            if (cmd == "fail") {
                return Rhp::fail(errc::kNotFound, "nothing here");
            }
            return value{static_cast<std::int64_t>(args.size())};
        },
        .fake_os_epoch = {}}));
    CHECK(*box.exec("return __rhp_test.host('count', 1, 'x', {a = 1})") == value_list{value{3}});
    CHECK(box.exec("return __rhp_test.host('fail')").error().code == errc::kNotFound);
    CHECK(box.exec("return __rhp_test.host('count', function() end)").error().code == errc::kTypeMismatch);
    CHECK(seen == std::vector<std::string>{"count", "fail"});
}

TEST_CASE("the API description lists libs events and patch points", "[script][testing]") {
    tick_event.fire(0);
    (void)double_point(1);
    sandbox box;
    REQUIRE(box.install<tt_lib>());
    const value api = box.api();
    const auto* libs = api.find("libs")->get_if<value::array>();
    REQUIRE(libs != nullptr);
    REQUIRE(libs->size() == 1);
    const value& lib = libs->front();
    CHECK(*lib.find("name") == value{"ttest"});
    const auto find_named = [](const value& list, std::string_view name) -> const value* {
        for (const value& v : *list.get_if<value::array>()) {
            if (*v.find("name") == value{std::string{name}}) {
                return &v;
            }
        }
        return nullptr;
    };
    const value* spawn = find_named(*lib.find("functions"), "spawn");
    REQUIRE(spawn != nullptr);
    CHECK(*spawn->find("params") == value{value::array{value{"integer"}}});
    CHECK(*spawn->find("returns") == value{value::array{value{"integer"}}});
    CHECK(*spawn->find("undo") == value{true});
    CHECK(*spawn->find("role") == value{"patch"});
    CHECK(*find_named(*lib.find("functions"), "make")->find("returns") == value{value::array{value{"mob"}}});
    const value* speed = find_named(*lib.find("variables"), "speed");
    REQUIRE(speed != nullptr);
    CHECK(*speed->find("type") == value{"number"});
    CHECK(*speed->find("writable") == value{true});
    const value* mob_desc = find_named(*lib.find("handles"), "mob");
    REQUIRE(mob_desc != nullptr);
    const value* hit = find_named(*mob_desc->find("methods"), "hit");
    REQUIRE(hit != nullptr);
    CHECK(*hit->find("params") == value{value::array{value{"integer"}}});
    CHECK(*find_named(*mob_desc->find("properties"), "hp")->find("type") == value{"integer"});
    bool tick = false;
    for (const value& e : *api.find("events")->get_if<value::array>()) {
        tick = tick || (*e.find("name") == value{"ttest.tick"} && *e.find("arity") == value{1});
    }
    CHECK(tick);
    bool point = false;
    for (const value& p : *api.find("points")->get_if<value::array>()) {
        point = point || (*p.find("id") == value{"ttest.double"} && *p.find("callable") == value{true});
    }
    CHECK(point);
    CHECK(*box.exec("local a = rhp.api() return a.libs[1].name, a.libs[1].handles[1].name") == value_list{value{"ttest"}, value{"mob"}});

    sandbox observer{sandbox_options{.caller_role = Rhp::role::kObserve}};
    REQUIRE(observer.install<tt_lib>());
    const value seen = observer.api();
    const value& seen_lib = seen.find("libs")->get_if<value::array>()->front();
    CHECK(find_named(*seen_lib.find("functions"), "spawn") == nullptr); // needs patch
    CHECK(*find_named(*seen_lib.find("variables"), "speed")->find("writable") == value{false});
    CHECK(seen.find("points")->get_if<value::array>()->empty());
}

TEST_CASE("exec_cached compiles a source once and keeps its line information", "[script][testing]") {
    const std::string source = "local t = {}\n"
                               "for i = 1, 3 do\n"
                               "  t[#t + 1] = i\n"
                               "end\n"
                               "return #t, debug and 1 or 0\n";
    for (int round = 0; round < 3; ++round) { // the first compiles, the others load bytecode
        sandbox box;
        REQUIRE(box.start_coverage());
        auto r = box.exec_cached(source, "testing.cached");
        REQUIRE(r);
        REQUIRE_FALSE(r->empty());
        CHECK(r->front() == value{std::int64_t{3}});
        const auto report = box.coverage();
        const auto* c = report.find("testing.cached");
        REQUIRE(c != nullptr);
        CHECK(c->lines == std::vector<std::uint32_t>{1, 2, 3, 5});
    }
    sandbox box;
    auto bad = box.exec_cached("return +", "testing.cached_bad");
    REQUIRE_FALSE(bad);
    CHECK(bad.error().code == errc::kCompile);
    auto failing = box.exec_cached("error('boom')", "testing.cached_error");
    REQUIRE_FALSE(failing);
    CHECK(failing.error().message.find("testing.cached_error:1: boom") != std::string::npos);
}
