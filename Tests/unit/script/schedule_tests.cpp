#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/script_support.hpp>

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
using Rhp::script::value_list;

namespace schedule_tests_fixtures {

inline constexpr Rhp::lua_event<"tests.schedule.ping", int> ping{};

} // namespace schedule_tests_fixtures

namespace {

namespace fx = schedule_tests_fixtures;
using std::chrono::milliseconds;

using rhp_test::manual_clock;

struct capture {
    std::vector<std::string> lines;
    std::vector<Rhp::script::handler_failure> failures;
};

sandbox make_box(capture& out, manual_clock& clock) {
    sandbox_options options;
    options.clock = clock.fn();
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_handler_error = [&out](const Rhp::script::handler_failure& f) { out.failures.push_back(f); };
    return sandbox{std::move(options)};
}

using rhp_test::code_of;

void pump(sandbox& box, int n) {
    for (int i = 0; i < n; ++i) {
        box.pump();
    }
}

std::vector<std::string> repeat(std::string_view line, std::size_t n) {
    return std::vector<std::string>(n, std::string{line});
}

} // namespace

TEST_CASE("every_frame calls its function once per pump", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.each", "rhp.every_frame(function() print('tick ' .. rhp.frame()) end)"));
    CHECK(out.lines.empty());
    pump(box, 3);
    CHECK(out.lines == std::vector<std::string>{"tick 1", "tick 2", "tick 3"});
}

TEST_CASE("every_frames waits n pumps between calls", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.third", "rhp.every_frames(3, function() print('at ' .. rhp.frame()) end)"));
    pump(box, 7);
    CHECK(out.lines == std::vector<std::string>{"at 3", "at 6"});
}

TEST_CASE("frame callbacks fire in registration order before due timers", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.order", R"lua(
        rhp.after(0, function() print("timer") end)
        rhp.every_frame(function() print("frame a") end, {times = 1})
        rhp.every_frame(function() print("frame b") end, {times = 1})
    )lua"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"frame a", "frame b", "timer"});
}

TEST_CASE("rhp.after fires once and leaves the ledger", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto mod = box.load("tests.schedule.after", R"lua(
        id = rhp.after(50, function() print("once") end)
        function try_off() local ok, err = pcall(rhp.off, id) return ok end
    )lua");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->effects == 1);
    clock.advance(milliseconds{49});
    box.pump();
    CHECK(out.lines.empty());
    clock.advance(milliseconds{1});
    box.pump();
    clock.advance(milliseconds{500});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"once"});
    CHECK(box.status(*mod)->effects == 0);
    CHECK(box.call(*mod, "try_off")->at(0) == Rhp::value{false});
}

TEST_CASE("rhp.every repeats at most once per pump without catch-up bursts", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.every", "rhp.every(10, function() print('tick') end)"));
    clock.advance(milliseconds{10});
    box.pump();
    clock.advance(milliseconds{45});
    box.pump();
    box.pump();
    CHECK(out.lines == repeat("tick", 2));
}

TEST_CASE("times limits the calls of a timer and of a frame callback", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto mod = box.load("tests.schedule.times", R"lua(
        rhp.every(5, function() print("timer") end, {times = 2})
        rhp.every_frame(function() print("frame") end, {times = 3})
    )lua");
    REQUIRE(mod.has_value());
    for (int i = 0; i < 6; ++i) {
        clock.advance(milliseconds{5});
        box.pump();
    }
    CHECK(std::ranges::count(out.lines, std::string{"timer"}) == 2);
    CHECK(std::ranges::count(out.lines, std::string{"frame"}) == 3);
    CHECK(box.status(*mod)->effects == 0);
}

TEST_CASE("pause and resume keep the remaining time of a timer", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto mod = box.load("tests.schedule.pause_timer", R"lua(
        id = rhp.after(100, function() print("fired") end)
        function pause() rhp.pause(id) end
        function resume() rhp.resume(id) end
    )lua");
    REQUIRE(mod.has_value());
    clock.advance(milliseconds{40});
    REQUIRE(box.call(*mod, "pause"));
    clock.advance(milliseconds{1'000});
    box.pump();
    CHECK(out.lines.empty());
    REQUIRE(box.call(*mod, "resume"));
    clock.advance(milliseconds{59});
    box.pump();
    CHECK(out.lines.empty());
    clock.advance(milliseconds{1});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"fired"});
}

TEST_CASE("pause and resume keep the remaining frames of a frame callback", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto mod = box.load("tests.schedule.pause_frames", R"lua(
        id = rhp.every_frames(4, function() print("at " .. rhp.frame()) end)
        function pause() rhp.pause(id) end
        function resume() rhp.resume(id) end
    )lua");
    REQUIRE(mod.has_value());
    pump(box, 1); // 3 frames left
    REQUIRE(box.call(*mod, "pause"));
    pump(box, 10); // frame 11
    REQUIRE(box.call(*mod, "resume"));
    pump(box, 3); // fires at frame 14
    CHECK(out.lines == std::vector<std::string>{"at 14"});
}

TEST_CASE("reschedule restarts the countdown with the new interval", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto mod = box.load("tests.schedule.reschedule", R"lua(
        timer = rhp.every(100, function() print("timer") end)
        frames = rhp.every_frames(10, function() print("frames " .. rhp.frame()) end)
        function change() rhp.reschedule(timer, 20) rhp.reschedule(frames, 2) end
        function bad(v) local ok, err = pcall(rhp.reschedule, frames, v) return ok end
    )lua");
    REQUIRE(mod.has_value());
    clock.advance(milliseconds{90});
    REQUIRE(box.call(*mod, "change"));
    clock.advance(milliseconds{19});
    box.pump(); // frame 1
    CHECK(out.lines.empty());
    clock.advance(milliseconds{1});
    box.pump(); // frame 2
    CHECK(out.lines == std::vector<std::string>{"frames 2", "timer"});
    CHECK(box.call(*mod, "bad", 0)->at(0) == Rhp::value{false});
    CHECK(box.call(*mod, "bad", 1.5)->at(0) == Rhp::value{false});
}

TEST_CASE("reschedule during a pump does not fire an entry twice", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.respin", R"lua(
        local b
        rhp.every(10, function() print("a") rhp.reschedule(b, 0) end)
        b = rhp.every(10, function() print("b") end)
    )lua"));
    clock.advance(milliseconds{10});
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"a", "b"});
    box.pump(); // b is due again (0 ms) at the next pump only
    CHECK(out.lines == std::vector<std::string>{"a", "b", "b"});
}

TEST_CASE("a callback can remove pause or reschedule itself", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.self", R"lua(
        local off, paused, slow
        off = rhp.every_frame(function() print("off") rhp.off(off) end)
        paused = rhp.every_frame(function() print("paused") rhp.pause(paused) end)
        slow = rhp.every_frame(function() print("slow") rhp.reschedule(slow, 5) end)
    )lua"));
    pump(box, 4);
    CHECK(out.lines == std::vector<std::string>{"off", "paused", "slow"});
    CHECK(out.failures.empty());
}

TEST_CASE("entries made during a pump wait for the next pump", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.chain", R"lua(
        local function again() print("call " .. rhp.frame()) rhp.after(0, again) end
        rhp.after(0, again)
    )lua"));
    pump(box, 3);
    CHECK(out.lines == std::vector<std::string>{"call 1", "call 2", "call 3"});
}

TEST_CASE("a repeating entry skips while its previous run is suspended", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.overlap", "rhp.every_frame(function() print('start') rhp.wait(3) end)"));
    pump(box, 1);
    CHECK(box.suspended() == 1);
    pump(box, 2);
    CHECK(box.suspended() == 1);
    CHECK(out.lines == std::vector<std::string>{"start"});
    pump(box, 2); // the wait ended at frame 4, so frame 5 starts the next call
    CHECK(out.lines == repeat("start", 2));
}

TEST_CASE("rhp.timers lists only the calling module's entries", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.other", "rhp.every_frame(function() end)"));
    const auto mod = box.load("tests.schedule.list", R"lua(
        t = rhp.every(100, function() end, {times = 4})
        f = rhp.every_frames(3, function() end)
        rhp.pause(f)
        function list()
            local all = rhp.timers()
            local a, b = all[1], all[2]
            return #all, a.id == t, a.kind, a.interval, a.remaining, a.times, a.repeating, a.paused,
                   b.id == f, b.kind, b.interval, b.remaining, b.paused, b.runs
        end
    )lua");
    REQUIRE(mod.has_value());
    clock.advance(milliseconds{30});
    const auto r = box.call(*mod, "list");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{2}, Rhp::value{true}, Rhp::value{"timer"}, Rhp::value{100.0}, Rhp::value{70.0}, Rhp::value{4}, Rhp::value{true},
                           Rhp::value{false}, Rhp::value{true}, Rhp::value{"frames"}, Rhp::value{3}, Rhp::value{3}, Rhp::value{true}, Rhp::value{0}});
}

TEST_CASE("pause resume and reschedule refuse foreign and unknown ids", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto owner = box.load("tests.schedule.owner", R"lua(
        id = rhp.every_frame(function() end)
        sub = rhp.on("tests.schedule.ping", function() end)
        function get() return id, sub end
    )lua");
    REQUIRE(owner.has_value());
    const auto ids = box.call(*owner, "get");
    REQUIRE(ids.has_value());
    const auto id = *ids->at(0).get_if<std::int64_t>();
    const auto sub = *ids->at(1).get_if<std::int64_t>();
    const auto other = box.load("tests.schedule.intruder", R"lua(
        function try(fn, id, ...) local ok, err = pcall(rhp[fn], id, ...) return ok, ok or err:match("%[([%w_]+)%]") end
    )lua");
    REQUIRE(other.has_value());
    for (const std::string fn : {"pause", "resume"}) {
        CHECK(*box.call(*other, "try", fn, id) == value_list{Rhp::value{false}, Rhp::value{"not_found"}});
        CHECK(*box.call(*other, "try", fn, 99'999) == value_list{Rhp::value{false}, Rhp::value{"not_found"}});
    }
    CHECK(*box.call(*other, "try", std::string{"reschedule"}, id, 2) == value_list{Rhp::value{false}, Rhp::value{"not_found"}});
    CHECK(*box.call(*owner, "get") == *ids);
    const auto inside = box.exec(std::format("local ok, err = pcall(rhp.reschedule, {}, 2) return ok", sub));
    CHECK(inside->at(0) == Rhp::value{false});
}

TEST_CASE("schedule functions validate their arguments", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    CHECK(code_of(box.exec("rhp.after(-1, function() end)")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.every_frames(0, function() end)")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.every_frames(1.5, function() end)")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.every(10, 5)")) == errc::kTypeMismatch);
    CHECK(code_of(box.exec("rhp.every_frame(function() end, 3)")) == errc::kTypeMismatch);
    CHECK(code_of(box.exec("rhp.every(10, function() end, {tims = 3})")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.every(10, function() end, {times = 0})")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.after(10, function() end, {times = 2})")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.every(10, function() end, {on_error = 'ignore'})")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.pause('x')")) == errc::kTypeMismatch);
    CHECK(code_of(box.exec("rhp.every_frames(2^62, function() end)")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.reschedule(rhp.every_frames(1, function() end), math.huge)")) == errc::kInvalidArgument);
    CHECK(code_of(box.exec("rhp.reschedule(rhp.every_frames(1, function() end), 2^64)")) == errc::kInvalidArgument);
    CHECK(box.effects().empty());
}

TEST_CASE("revert unload and a reload swap remove frame callbacks", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto a = box.load("tests.schedule.gone_a", "rhp.every_frame(function() print('a') end)");
    const auto b = box.load("tests.schedule.gone_b", "rhp.every_frame(function() print('b') end)");
    const auto c = box.load("tests.schedule.gone_c", "rhp.every_frame(function() print('c1') end)");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(c.has_value());
    REQUIRE(box.revert(*a));
    REQUIRE(box.unload(*b));
    REQUIRE(box.reload(*c, "rhp.every_frame(function() print('c2') end)"));
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"c2"});
    CHECK(box.stats().schedule_entries == 1);
}

TEST_CASE("rhp.timer keeps its signature and repeating flag", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    REQUIRE(box.load("tests.schedule.legacy", R"lua(
        rhp.timer(10, function() print("once") end)
        rhp.timer(10, function() print("again") end, true)
    )lua"));
    for (int i = 0; i < 3; ++i) {
        clock.advance(milliseconds{10});
        box.pump();
    }
    CHECK(std::ranges::count(out.lines, std::string{"once"}) == 1);
    CHECK(std::ranges::count(out.lines, std::string{"again"}) == 3);
}

TEST_CASE("pause and resume apply to subscriptions", "[script][schedule]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, clock);
    const auto mod = box.load("tests.schedule.sub_pause", R"lua(
        id = rhp.on("tests.schedule.ping", function(n) print("got " .. n) end)
        function pause() rhp.pause(id) end
        function resume() rhp.resume(id) end
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "pause"));
    fx::ping.fire(1);
    REQUIRE(box.call(*mod, "resume"));
    fx::ping.fire(2);
    CHECK(out.lines == std::vector<std::string>{"got 2"});
}
