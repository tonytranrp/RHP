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
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>

using Rhp::errc;
using Rhp::revision_id;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

namespace reload_tests_fixtures {

inline int g_counter = 0;

using counter_lib = Rhp::lib<"counter">::var<"value", &g_counter>;

inline constexpr Rhp::lua_event<"tests.reload.ping", int> ping{};

inline float default_damage(float base, int target) {
    return base * static_cast<float>(target);
}

inline constexpr Rhp::patch_point<"tests.reload.damage", &default_damage> damage{};

} // namespace reload_tests_fixtures

namespace {

namespace fx = reload_tests_fixtures;

struct capture {
    std::vector<std::string> lines;
    std::vector<std::pair<Rhp::request_id, Rhp::result<Rhp::script::value_list>>> results;
};

using rhp_test::manual_clock;

sandbox make_box(capture& out, Rhp::limits limits = {}, manual_clock* clock = nullptr) {
    fx::g_counter = 0;
    sandbox_options options;
    options.limits = limits;
    if (clock != nullptr) {
        options.clock = [clock] { return clock->now; };
    }
    options.output = [&out](std::string_view line) { out.lines.emplace_back(line); };
    options.on_result = [&out](Rhp::request_id id, const Rhp::result<Rhp::script::value_list>& r) { out.results.emplace_back(id, r); };
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::counter_lib>());
    return box;
}

using rhp_test::code_of;

std::uint32_t hash_of(std::string_view source) {
    return Rhp::utils::crc32c(Rhp::utils::as_bytes(source));
}

// The first value a call returned.
Rhp::value call_value(sandbox& box, Rhp::module_id mod, std::string_view function) {
    const auto r = box.call(mod, function);
    REQUIRE(r.has_value());
    return r->empty() ? Rhp::value{} : r->front();
}

constexpr std::string_view kOld = R"lua(
    counter.value = 1
    function which() return "old" end
)lua";

} // namespace

TEST_CASE("reload runs the new revision in a fresh environment next to the old one", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.fresh", "x = 1 counter.value = 10 function get_x() return x end");
    REQUIRE(mod.has_value());
    CHECK(box.status(*mod)->revision == revision_id{1});

    constexpr std::string_view kNew = R"lua(
        seen = counter.value
        counter.value = 20
        function get_x() return x end
        function get_seen() return seen end
    )lua";
    const auto rev = box.reload(*mod, kNew);
    REQUIRE(rev.has_value());
    CHECK(*rev == revision_id{2});
    CHECK(call_value(box, *mod, "get_x").is_nil());             // the old globals are gone
    CHECK(call_value(box, *mod, "get_seen") == Rhp::value{10}); // the old revision was live meanwhile
    CHECK(fx::g_counter == 20);

    const auto info = box.status(*mod);
    REQUIRE(info.has_value());
    CHECK(info->state == module_state::kActive);
    CHECK(info->revision == revision_id{2});
    CHECK(info->revisions == 2);
    CHECK_FALSE(info->reloading);
    CHECK(info->source_hash == hash_of(kNew));
    CHECK(info->effects == 1); // only the new revision's write is left

    REQUIRE(box.revert(*mod));
    CHECK(fx::g_counter == 0);
}

TEST_CASE("reload order: new top level and on_load then old on_save then new on_restore", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.order", R"lua(
        function on_save() print("save") return 5 end
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(box.reload(*mod, R"lua(
        print("top")
        function on_load() print("load") end
        function on_restore(saved) print("restore " .. tostring(saved)) end
    )lua"));
    CHECK(out.lines == std::vector<std::string>{"top", "load", "save", "restore 5"});
}

TEST_CASE("on_save runs only for an active old revision", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    constexpr std::string_view kSaver = R"lua(
        function on_save() print("save") return "state" end
        function on_restore(saved) print("restore " .. tostring(saved)) end
        function boom() error("boom") end
    )lua";
    const auto mod = box.load("tests.reload.saver", kSaver);
    REQUIRE(mod.has_value());

    SECTION("reverted") {
        REQUIRE(box.revert(*mod));
        REQUIRE(box.reload(*mod, kSaver));
        CHECK(out.lines == std::vector<std::string>{"restore nil"});
    }

    SECTION("faulted") {
        REQUIRE_FALSE(box.call(*mod, "boom").has_value());
        REQUIRE(box.status(*mod)->state == module_state::kFaulted);
        REQUIRE(box.reload(*mod, kSaver));
        CHECK(out.lines == std::vector<std::string>{"restore nil"});
    }

    SECTION("active") {
        REQUIRE(box.reload(*mod, kSaver));
        CHECK(out.lines == std::vector<std::string>{"save", "restore state"});
    }
    const auto info = box.status(*mod);
    CHECK(info->state == module_state::kActive);
    CHECK_FALSE(info->fault.has_value());
}

TEST_CASE("reload removes the old revision's timers subscriptions and suspended requests", "[script][reload]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, &clock);
    const auto mod = box.load("tests.reload.swap", R"lua(
        rhp.timer(10, function() print("old timer") end, true)
        rhp.on("tests.reload.ping", function(n) print("old ping") end)
        function waiter() rhp.wait(100) return "never" end
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(box.call(*mod, "waiter"));
    const Rhp::request_id waiter = box.last_request();
    CHECK(box.suspended() == 1);
    CHECK(fx::ping.listeners() == 1);

    REQUIRE(box.reload(*mod, R"lua(
        rhp.on("tests.reload.ping", function(n) print("new ping") end)
    )lua"));
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == waiter);
    REQUIRE_FALSE(out.results[0].second.has_value());
    CHECK(out.results[0].second.error().code == errc::kCancelled);

    CHECK(fx::ping.listeners() == 1);
    fx::ping.fire(1);
    clock.now += std::chrono::milliseconds{100};
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"new ping"});
    CHECK(box.status(*mod)->effects == 1);

    REQUIRE(box.unload(*mod));
    CHECK(fx::ping.listeners() == 0);
}

TEST_CASE("a failing reload reverts the new revision and leaves the old one untouched", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    std::string old_source{kOld};
    std::string new_source;
    errc expected = errc::kRuntime;

    SECTION("compile error") {
        new_source = "counter.value = 2 function which( return 'new' end";
        expected = errc::kCompile;
    }
    SECTION("runtime error in the top level") {
        new_source = "counter.value = 2 rhp.on('tests.reload.ping', function() end) error('top failed')";
    }
    SECTION("on_load fails") {
        new_source = "counter.value = 2 function on_load() error('load failed') end";
    }
    SECTION("old on_save fails") {
        old_source += " function on_save() error('save failed') end";
        new_source = "counter.value = 2 rhp.on('tests.reload.ping', function() end)";
    }
    SECTION("new on_restore fails") {
        new_source = "counter.value = 2 function on_restore(saved) error('restore failed') end";
    }
    SECTION("old on_save can't suspend") {
        old_source += " function on_save() rhp.wait(1) return 1 end";
        new_source = "counter.value = 2";
        expected = errc::kInvalidArgument;
    }
    SECTION("new on_restore can't suspend") {
        new_source = "counter.value = 2 function on_restore(saved) rhp.next_frame() end";
        expected = errc::kInvalidArgument;
    }
    SECTION("the new revision requires itself") {
        new_source = "counter.value = 2 require('tests.reload.victim')";
        expected = errc::kInvalidArgument;
    }

    const auto mod = box.load("tests.reload.victim", old_source);
    REQUIRE(mod.has_value());
    REQUIRE(fx::g_counter == 1);
    const auto before = box.status(*mod);

    const auto bad = box.reload(*mod, new_source);
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error().code == expected);
    CHECK(fx::g_counter == 1);
    CHECK(fx::ping.listeners() == 0);

    const auto after = box.status(*mod);
    REQUIRE(after.has_value());
    CHECK(after->state == module_state::kActive);
    CHECK_FALSE(after->fault.has_value());
    CHECK(after->revision == revision_id{1});
    CHECK(after->revisions == 1);
    CHECK_FALSE(after->reloading);
    CHECK(after->source_hash == before->source_hash);
    CHECK(after->effects == before->effects);
    CHECK(call_value(box, *mod, "which") == Rhp::value{"old"});

    // The failed attempt used up revision 2. (Reverted first: some sections leave a broken on_save.)
    REQUIRE(box.revert(*mod));
    const auto good = box.reload(*mod, "function which() return 'new' end");
    REQUIRE(good.has_value());
    CHECK(*good == revision_id{3});
    CHECK(call_value(box, *mod, "which") == Rhp::value{"new"});
}

TEST_CASE("a reload whose top level suspends swaps in a later pump", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.slow", kOld);
    REQUIRE(mod.has_value());

    const auto rev = box.reload(*mod, "rhp.next_frame() counter.value = 2 function which() return 'new' end");
    REQUIRE(rev.has_value());
    CHECK(*rev == revision_id{});
    const Rhp::request_id id = box.last_request();
    auto info = box.status(*mod);
    CHECK(info->reloading);
    CHECK(info->revision == revision_id{1});
    CHECK(info->state == module_state::kActive);
    CHECK(call_value(box, *mod, "which") == Rhp::value{"old"}); // the old revision stays live

    const auto again = box.reload(*mod, "return {}");
    REQUIRE_FALSE(again.has_value());
    CHECK(again.error().code == errc::kInvalidArgument);

    box.pump();
    info = box.status(*mod);
    CHECK_FALSE(info->reloading);
    CHECK(info->revision == revision_id{2});
    CHECK(info->revisions == 2);
    CHECK(fx::g_counter == 2);
    CHECK(call_value(box, *mod, "which") == Rhp::value{"new"});
    REQUIRE(out.results.size() == 1);
    CHECK(out.results[0].first == id);
    CHECK(out.results[0].second.has_value());
}

TEST_CASE("the new revision's on_load may wait", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.on_load_wait", "function on_save() return 'kept' end");
    REQUIRE(mod.has_value());
    const auto rev = box.reload(*mod, R"lua(
        function on_load() rhp.wait(2) print("loaded") end
        function on_restore(saved) print("restore " .. tostring(saved)) end
    )lua");
    REQUIRE(rev.has_value());
    CHECK(*rev == revision_id{});
    CHECK(box.status(*mod)->reloading);
    box.pump();
    CHECK(out.lines.empty());
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"loaded", "restore kept"});
    CHECK(box.status(*mod)->revision == revision_id{2});
    CHECK_FALSE(box.status(*mod)->reloading);
}

TEST_CASE("a module whose first load failed can be loaded again", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto broken = box.load("tests.reload.first_fail", "counter.value = 1 error('first')");
    REQUIRE_FALSE(broken.has_value());
    const auto id = box.find("tests.reload.first_fail");
    REQUIRE(id.has_value());
    CHECK(box.status(*id)->state == module_state::kFaulted);
    CHECK(fx::g_counter == 0);

    const auto fixed = box.load("tests.reload.first_fail", kOld);
    REQUIRE(fixed.has_value());
    CHECK(*fixed == *id);
    const auto info = box.status(*id);
    CHECK(info->state == module_state::kActive);
    CHECK(info->revision == revision_id{2});
    CHECK_FALSE(info->fault.has_value());
    CHECK(call_value(box, *id, "which") == Rhp::value{"old"});
}

TEST_CASE("a suspended reload that fails later leaves the old revision alone", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.slow_fail", kOld);
    REQUIRE(mod.has_value());
    REQUIRE(box.reload(*mod, "counter.value = 2 rhp.next_frame() error('late')"));
    CHECK(fx::g_counter == 2);
    box.pump();
    REQUIRE(out.results.size() == 1);
    REQUIRE_FALSE(out.results[0].second.has_value());
    CHECK(out.results[0].second.error().message.find("late") != std::string::npos);
    const auto info = box.status(*mod);
    CHECK(info->state == module_state::kActive);
    CHECK_FALSE(info->fault.has_value());
    CHECK_FALSE(info->reloading);
    CHECK(info->revision == revision_id{1});
    CHECK(fx::g_counter == 1);
    CHECK(call_value(box, *mod, "which") == Rhp::value{"old"});
}

TEST_CASE("reverting or unloading a module abandons its reload in flight", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.abandon", kOld);
    REQUIRE(mod.has_value());
    REQUIRE(box.reload(*mod, "counter.value = 2 rhp.wait(5) function which() return 'new' end"));
    CHECK(fx::g_counter == 2);

    SECTION("revert") {
        REQUIRE(box.revert(*mod));
        const auto info = box.status(*mod);
        CHECK(info->state == module_state::kReverted);
        CHECK_FALSE(info->reloading);
        CHECK(info->revision == revision_id{1});
    }
    SECTION("unload") {
        REQUIRE(box.unload(*mod));
        CHECK_FALSE(box.find("tests.reload.abandon").has_value());
    }
    CHECK(fx::g_counter == 0);
    CHECK(box.suspended() == 0);
    REQUIRE(out.results.size() == 1);
    CHECK(code_of(out.results[0].second) == errc::kCancelled);
    for (int i = 0; i < 6; ++i) {
        box.pump();
    }
    CHECK(fx::g_counter == 0);
}

TEST_CASE("reload refuses a module that is still loading", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.loading", "rhp.next_frame() function which() return 'first' end");
    REQUIRE(mod.has_value());
    REQUIRE(box.status(*mod)->state == module_state::kLoading);
    const auto r = box.reload(*mod, "function which() return 'second' end");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kInvalidArgument);
    const auto via_load = box.load("tests.reload.loading", "return {}");
    REQUIRE_FALSE(via_load.has_value());
    CHECK(via_load.error().code == errc::kInvalidArgument);
    box.pump();
    CHECK(box.status(*mod)->state == module_state::kActive);
    CHECK(call_value(box, *mod, "which") == Rhp::value{"first"});
}

TEST_CASE("loading an existing name reloads it and keeps its id", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto first = box.load("tests.reload.same", kOld);
    REQUIRE(first.has_value());
    const auto second = box.load("tests.reload.same", "counter.value = 2 function which() return 'new' end");
    REQUIRE(second.has_value());
    CHECK(*second == *first);
    CHECK(box.status(*first)->revision == revision_id{2});
    CHECK(fx::g_counter == 2);
    CHECK(box.list().size() == 2); // scratch + this one

    const auto broken = box.load("tests.reload.same", "error('no')");
    REQUIRE_FALSE(broken.has_value());
    CHECK(box.status(*first)->state == module_state::kActive);
    CHECK(call_value(box, *first, "which") == Rhp::value{"new"});
}

TEST_CASE("reload brings reverted and faulted modules back", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.revive", "counter.value = 1 function boom() error('x') end");
    REQUIRE(mod.has_value());

    REQUIRE(box.revert(*mod));
    REQUIRE(box.status(*mod)->state == module_state::kReverted);
    REQUIRE(box.reload(*mod, "counter.value = 2 function boom() error('y') end"));
    CHECK(box.status(*mod)->state == module_state::kActive);
    CHECK(fx::g_counter == 2);

    REQUIRE_FALSE(box.call(*mod, "boom").has_value());
    REQUIRE(box.status(*mod)->state == module_state::kFaulted);
    CHECK(fx::g_counter == 0);
    REQUIRE(box.reload(*mod, "counter.value = 3"));
    const auto info = box.status(*mod);
    CHECK(info->state == module_state::kActive);
    CHECK_FALSE(info->fault.has_value());
    CHECK(info->revision == revision_id{3});
    CHECK(fx::g_counter == 3);
}

TEST_CASE("status keeps the last N revisions", "[script][reload]") {
    capture out;

    SECTION("limits.revisions = 3") {
        Rhp::limits limits;
        limits.revisions = 3;
        sandbox box = make_box(out, limits);
        const auto mod = box.load("tests.reload.history", "return { n = 1 }");
        REQUIRE(mod.has_value());
        for (int n = 2; n <= 5; ++n) {
            REQUIRE(box.reload(*mod, std::format("return {{ n = {} }}", n)));
        }
        auto info = box.status(*mod);
        CHECK(info->revision == revision_id{5});
        CHECK(info->revisions == 3);
        CHECK(info->source_hash == hash_of("return { n = 5 }"));

        const auto too_far = box.rollback(*mod, 3);
        REQUIRE_FALSE(too_far.has_value());
        CHECK(too_far.error().code == errc::kOutOfRange);
        const auto back = box.rollback(*mod, 2); // revision 3's source
        REQUIRE(back.has_value());
        CHECK(*back == revision_id{6});
        info = box.status(*mod);
        CHECK(info->source_hash == hash_of("return { n = 3 }"));
        CHECK(info->revisions == 3);
    }

    SECTION("limits.revisions = 0 keeps one") {
        Rhp::limits limits;
        limits.revisions = 0;
        sandbox box = make_box(out, limits);
        const auto mod = box.load("tests.reload.history", "return { n = 1 }");
        REQUIRE(mod.has_value());
        REQUIRE(box.reload(*mod, "return { n = 2 }"));
        CHECK(box.status(*mod)->revisions == 1);
        const auto back = box.rollback(*mod, 1);
        REQUIRE_FALSE(back.has_value());
        CHECK(back.error().code == errc::kOutOfRange);
    }
}

TEST_CASE("rollback reloads a kept source as a new revision and carries state", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto source = [](int n) {
        return std::format(R"lua(
            counter.value = {0}
            hits = 0
            function version() return {0} end
            function hit() hits = hits + 1 return hits end
            function on_save() return hits end
            function on_restore(saved) hits = saved or 0 end
        )lua",
                           n);
    };
    const auto mod = box.load("tests.reload.rollback", source(1));
    REQUIRE(mod.has_value());
    REQUIRE(box.reload(*mod, source(2)));
    REQUIRE(box.reload(*mod, source(3)));
    REQUIRE(box.call(*mod, "hit"));
    REQUIRE(box.call(*mod, "hit"));

    const auto zero = box.rollback(*mod, 0);
    REQUIRE_FALSE(zero.has_value());
    CHECK(zero.error().code == errc::kOutOfRange);
    const auto far = box.rollback(*mod, 3);
    REQUIRE_FALSE(far.has_value());
    CHECK(far.error().code == errc::kOutOfRange);

    const auto back = box.rollback(*mod);
    REQUIRE(back.has_value());
    CHECK(*back == revision_id{4});
    CHECK(call_value(box, *mod, "version") == Rhp::value{2});
    CHECK(call_value(box, *mod, "hit") == Rhp::value{3}); // two hits carried over
    CHECK(fx::g_counter == 2);
    CHECK(box.status(*mod)->source_hash == hash_of(source(2)));

    const auto further = box.rollback(*mod, 3); // history: 1, 2, 3, 2 → three back is revision 1's source
    REQUIRE(further.has_value());
    CHECK(*further == revision_id{5});
    CHECK(call_value(box, *mod, "version") == Rhp::value{1});
    CHECK(fx::g_counter == 1);
}

TEST_CASE("reload and rollback validate their target", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const Rhp::module_id unknown{424'242};
    CHECK(code_of(box.reload(unknown, "return {}")) == errc::kNotFound);
    CHECK(code_of(box.rollback(unknown)) == errc::kNotFound);
    CHECK(code_of(box.reload(box.scratch_module(), "return {}")) == errc::kNotFound);
    CHECK(code_of(box.rollback(box.scratch_module())) == errc::kNotFound);
    const auto fresh = box.load("tests.reload.fresh_rollback", "return {}");
    REQUIRE(fresh.has_value());
    CHECK(code_of(box.rollback(*fresh)) == errc::kOutOfRange); // nothing to go back to
}

TEST_CASE("reload swaps patch handlers; a failed reload keeps the old one", "[script][reload]") {
    capture out;
    {
        sandbox box = make_box(out);
        const auto mod = box.load("tests.reload.patcher", R"lua(
            rhp.patch("tests.reload.damage", function(original, base, target) return original(base, target) + 1 end)
        )lua");
        REQUIRE(mod.has_value());
        CHECK(fx::damage(2.0f, 3) == 7.0f);

        REQUIRE_FALSE(box.reload(*mod, R"lua(
            rhp.patch("tests.reload.damage", function(original, base, target) return original(base, target) + 100 end)
            error("not this one")
        )lua"));
        CHECK(fx::damage.depth() == 1);
        CHECK(fx::damage(2.0f, 3) == 7.0f);

        REQUIRE(box.reload(*mod, R"lua(
            rhp.patch("tests.reload.damage", function(original, base, target) return original(base, target) + 2 end)
        )lua"));
        CHECK(fx::damage.depth() == 1);
        CHECK(fx::damage(2.0f, 3) == 8.0f);
        CHECK(box.status(*mod)->effects == 1);
    }
    CHECK(fx::damage.depth() == 0);
}

TEST_CASE("effects made in on_save belong to the old revision in on_restore to the new", "[script][reload]") {
    manual_clock clock;
    capture out;
    sandbox box = make_box(out, {}, &clock);
    const auto mod = box.load("tests.reload.hooks", R"lua(
        function on_save() rhp.timer(10, function() print("from on_save") end, true) return 1 end
    )lua");
    REQUIRE(mod.has_value());
    REQUIRE(box.reload(*mod, R"lua(
        function on_restore(saved) rhp.timer(10, function() print("from on_restore") end, true) end
    )lua"));
    CHECK(box.status(*mod)->effects == 1);
    clock.now += std::chrono::milliseconds{10};
    box.pump();
    CHECK(out.lines == std::vector<std::string>{"from on_restore"});
}

TEST_CASE("a module reverted while loading can be reloaded", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto mod = box.load("tests.reload.revert_loading", "counter.value = 1 rhp.next_frame() function which() return 'first' end");
    REQUIRE(mod.has_value());
    REQUIRE(box.revert(*mod));
    CHECK(box.status(*mod)->state == module_state::kReverted);
    CHECK(fx::g_counter == 0);
    CHECK(box.suspended() == 0);
    box.pump();
    CHECK(box.status(*mod)->state == module_state::kReverted);

    REQUIRE(box.reload(*mod, kOld));
    CHECK(box.status(*mod)->state == module_state::kActive);
    CHECK(call_value(box, *mod, "which") == Rhp::value{"old"});
}

TEST_CASE("on_unload runs on unload can't suspend and its errors are ignored", "[script][reload]") {
    capture out;
    sandbox box = make_box(out);
    const auto quiet = box.load("tests.reload.unload_print", "counter.value = 1 function on_unload() print('bye') end");
    const auto waits = box.load("tests.reload.unload_wait", "function on_unload() rhp.wait(1) print('unreachable') end");
    const auto fails = box.load("tests.reload.unload_fail", "function on_unload() error('nope') end");
    REQUIRE(quiet.has_value());
    REQUIRE(waits.has_value());
    REQUIRE(fails.has_value());
    CHECK(box.unload(*quiet).has_value());
    CHECK(box.unload(*waits).has_value());
    CHECK(box.unload(*fails).has_value());
    CHECK(out.lines == std::vector<std::string>{"bye"});
    CHECK(fx::g_counter == 0);
    CHECK(box.list().size() == 1);
    CHECK(box.suspended() == 0);
}
