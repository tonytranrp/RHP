#include <algorithm>
#include <atomic>
#include <cstddef>
#include <format>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::role;
using Rhp::script::module_state;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

// Everything the lib binds lives here: referenced as template arguments, so a named namespace.
namespace binding_tests_fixtures {

struct entity_id {
    int v = 0;
    bool operator==(const entity_id&) const = default;
};

inline std::vector<int> g_alive;
inline std::vector<int> g_despawned;
inline int g_next_id = 1;
inline float g_gravity = 0.0f;
inline int g_tick = 0;
inline int g_x = 0;
inline std::vector<int> g_unset_calls;
inline int g_explosions = 0;
inline int g_wipes = 0;

inline void reset() {
    g_alive.clear();
    g_despawned.clear();
    g_next_id = 1;
    g_gravity = 0.0f;
    g_tick = 17;
    g_x = 0;
    g_unset_calls.clear();
    g_explosions = 0;
    g_wipes = 0;
}

inline entity_id spawn(float x, float y) {
    (void)x;
    (void)y;
    const entity_id e{g_next_id++};
    g_alive.push_back(e.v);
    return e;
}

inline void despawn(entity_id e) {
    g_despawned.push_back(e.v);
    std::erase(g_alive, e.v);
}

inline bool is_alive(const entity_id& e) {
    return std::ranges::find(g_alive, e.v) != g_alive.end();
}

// Removes an entity behind the script's back, making its handles stale.
inline void forget(entity_id e) {
    std::erase(g_alive, e.v);
}

inline int count() {
    return static_cast<int>(g_alive.size());
}

inline std::optional<entity_id> first() {
    if (g_alive.empty()) {
        return std::nullopt;
    }
    return entity_id{g_alive.front()};
}

inline bool same(entity_id a, entity_id b) {
    return a == b;
}

inline int find(std::string_view name) {
    return static_cast<int>(name.size());
}

inline int add(int a, int b) {
    return a + b;
}

inline std::optional<int> maybe(std::optional<int> x) {
    if (!x) {
        return std::nullopt;
    }
    return *x * 2;
}

inline std::tuple<int, std::string, bool> triple() {
    return {1, "two", true};
}

inline Rhp::result<int> checked(int x) {
    if (x < 0) {
        return Rhp::fail(errc::kOutOfRange, "negative");
    }
    return x;
}

inline int throws_std(int) {
    throw std::runtime_error("kaboom");
}

inline int throws_rhp(int) {
    throw Rhp::exception{Rhp::make_error(errc::kStaleHandle, "custom")};
}

inline Rhp::value echo(Rhp::value v) {
    return v;
}

inline void set_x(int x) {
    g_x = x;
}

inline void unset_x(int x) {
    g_unset_calls.push_back(x);
    g_x = 0;
}

inline void explode() {
    ++g_explosions;
}

inline void wipe() {
    ++g_wipes;
}

using game_lib = Rhp::lib<"game">                              //
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>                 //
    ::fn<"forget", &forget>                                    //
    ::fn<"count", &count>                                      //
    ::fn<"first", &first>                                      //
    ::fn<"same", &same>                                        //
    ::fn<"add", &add>                                          //
    ::fn<"maybe", &maybe>                                      //
    ::fn<"triple", &triple>                                    //
    ::fn<"checked", &checked>                                  //
    ::fn<"throws_std", &throws_std>                            //
    ::fn<"throws_rhp", &throws_rhp>                            //
    ::fn<"echo", &echo>                                        //
    ::fn<"twice", [](int x) { return 2 * x; }>                 //
    ::fn<"set_x", &set_x, Rhp::undo<&unset_x>>                 //
    ::fn<"explode", &explode, Rhp::irreversible>               //
    ::fn<"wipe", &wipe, Rhp::requires_role<Rhp::role::kAdmin>> //
    ::var<"gravity", &g_gravity>                               //
    ::ro<"tick", &g_tick>                                      //
    ::handle<"entity", entity_id, &is_alive>                   //
    ::sub<Rhp::lib<"debug">::fn<"find", &find>>;

inline float default_damage(float base, int target) {
    return base * static_cast<float>(target);
}

inline constexpr Rhp::patch_point<"tests.binding.damage", &default_damage> damage{};

} // namespace binding_tests_fixtures

namespace {

namespace fx = binding_tests_fixtures;

sandbox make_game_box(role caller = role::kPatch) {
    fx::reset();
    sandbox_options options;
    options.caller_role = caller;
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::game_lib>());
    return box;
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

std::string describe(const Rhp::error& err) {
    return err.message + " | " + err.where + " | " + err.traceback;
}

// Runs source expecting failure; returns the error code (kOk if it unexpectedly succeeded).
errc exec_error(sandbox& box, std::string_view source) {
    const auto r = box.exec(source);
    return r ? errc::kOk : r.error().code;
}

} // namespace

TEST_CASE("binding errors are formatted strings inside Lua and errc outside", "[script][binding]") {
    sandbox box = make_game_box(role::kObserve);

    const auto outside = box.exec("game.gravity = 1");
    REQUIRE_FALSE(outside.has_value());
    CHECK(outside.error().code == errc::kForbidden);
    CHECK(contains(describe(outside.error()), "game.gravity"));

    const auto inside = box.exec(R"lua(
        local ok, e = pcall(function() game.gravity = 1 end)
        return ok, type(e), string.find(e, "forbidden", 1, true) ~= nil,
               string.find(e, "[forbidden] game.gravity: needs role patch", 1, true) ~= nil
    )lua");
    REQUIRE(inside.has_value());
    REQUIRE(inside->size() == 4);
    CHECK((*inside)[0] == Rhp::value{false});
    CHECK((*inside)[1] == Rhp::value{"string"});
    CHECK((*inside)[2] == Rhp::value{true});
    CHECK((*inside)[3] == Rhp::value{true});
    CHECK(fx::g_gravity == 0.0f);
}

TEST_CASE("observe may read and call pure bindings only", "[script][binding]") {
    REQUIRE(fx::damage(2.0f, 3) == 6.0f); // registers the point
    sandbox box = make_game_box(role::kObserve);
    fx::g_gravity = -9.5f;

    CHECK(box.exec<double>("return game.gravity") == -9.5);
    CHECK(box.exec<int>("return game.tick") == 17);
    CHECK(box.exec<int>("return game.debug.find('abc')") == 3);
    CHECK(box.exec<int>("return game.add(2, 3)") == 5);

    CHECK(exec_error(box, "game.gravity = 1") == errc::kForbidden);
    CHECK(exec_error(box, "game.spawn(1, 2)") == errc::kForbidden);
    CHECK(exec_error(box, "game.set_x(1)") == errc::kForbidden);
    CHECK(exec_error(box, "game.explode()") == errc::kForbidden);
    CHECK(exec_error(box, "game.wipe()") == errc::kForbidden);
    CHECK(exec_error(box, "rhp.patch('tests.binding.damage', function(original, b, t) return 0 end)") == errc::kForbidden);

    CHECK(fx::g_alive.empty());
    CHECK(fx::g_x == 0);
    CHECK(fx::g_explosions == 0);
    CHECK(fx::damage.depth() == 0);
    CHECK(box.effects().empty());
}

TEST_CASE("requires_role gates a binding above patch", "[script][binding]") {
    SECTION("patch is refused") {
        sandbox box = make_game_box(role::kPatch);
        CHECK(exec_error(box, "game.wipe()") == errc::kForbidden);
        CHECK(fx::g_wipes == 0);
        // Patch may do everything else.
        REQUIRE(box.exec("game.gravity = 2 game.set_x(3) game.explode() game.spawn(0, 0)"));
        CHECK(fx::g_gravity == 2.0f);
    }

    SECTION("admin is allowed") {
        sandbox box = make_game_box(role::kAdmin);
        REQUIRE(box.exec("game.wipe()"));
        CHECK(fx::g_wipes == 1);
    }
}

TEST_CASE("arguments are checked and labelled", "[script][binding]") {
    sandbox box = make_game_box();

    SECTION("type mismatch names the binding and argument") {
        const auto bad = box.exec("game.spawn(1, 'x')");
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kTypeMismatch);
        CHECK(contains(bad.error().where, "game.spawn (argument 2)"));
        CHECK(fx::g_alive.empty());

        const auto sub = box.exec("game.debug.find(1)");
        REQUIRE_FALSE(sub.has_value());
        CHECK(sub.error().code == errc::kTypeMismatch);
        CHECK(contains(sub.error().where, "game.debug.find (argument 1)"));
    }

    SECTION("missing and extra arguments") {
        CHECK(exec_error(box, "game.add(1)") == errc::kTypeMismatch);
        CHECK(exec_error(box, "game.add()") == errc::kTypeMismatch);
        CHECK(box.exec<bool>("return game.maybe() == nil") == true);
        CHECK(box.exec<bool>("return game.maybe(nil) == nil") == true);
        CHECK(box.exec<int>("return game.maybe(3)") == 6);
        CHECK(box.exec<int>("return game.add(1, 2, 3)") == 3);
    }

    SECTION("integers") {
        CHECK(exec_error(box, "game.add(1.5, 1)") == errc::kOutOfRange);
        CHECK(box.exec<int>("return game.add(2.0, 1)") == 3);
        CHECK(exec_error(box, "game.add(1 << 40, 1)") == errc::kOutOfRange);
        CHECK(exec_error(box, "game.add('1', 1)") == errc::kTypeMismatch);
        CHECK(box.exec<int>("return game.twice(21)") == 42);
    }

    SECTION("variables") {
        REQUIRE(box.exec("game.gravity = 3"));
        CHECK(fx::g_gravity == 3.0f);
        CHECK(exec_error(box, "game.gravity = 'up'") == errc::kTypeMismatch);
        CHECK(fx::g_gravity == 3.0f);
    }
}

TEST_CASE("results: tuples, Rhp::result and exceptions", "[script][binding]") {
    sandbox box = make_game_box();

    const auto values = box.exec("return game.triple()");
    REQUIRE(values.has_value());
    REQUIRE(values->size() == 3);
    CHECK((*values)[0] == Rhp::value{1});
    CHECK((*values)[1] == Rhp::value{"two"});
    CHECK((*values)[2] == Rhp::value{true});

    CHECK(box.exec<int>("return game.checked(2)") == 2);
    CHECK(exec_error(box, "game.checked(-1)") == errc::kOutOfRange);
    CHECK(box.exec<bool>("local ok, e = pcall(game.checked, -1) return not ok and string.find(e, 'negative', 1, true) ~= nil") == true);

    const auto thrown = box.exec("game.throws_std(1)");
    REQUIRE_FALSE(thrown.has_value());
    CHECK(thrown.error().code == errc::kRuntime);
    CHECK(contains(describe(thrown.error()), "kaboom"));

    CHECK(exec_error(box, "game.throws_rhp(1)") == errc::kStaleHandle);

    CHECK(box.exec<std::vector<int>>("return game.echo({ 1, 2 })") == std::vector<int>{1, 2});
    CHECK(box.exec<std::string>("return game.echo('v')") == "v");

    // The sandbox survives all of the above.
    CHECK(box.exec<int>("return game.add(1, 1)") == 2);
}

TEST_CASE("handles are opaque userdata", "[script][binding]") {
    sandbox box = make_game_box();
    REQUIRE(box.exec("e = game.spawn(1, 2)"));
    REQUIRE(fx::g_alive.size() == 1);

    CHECK(box.exec<std::string>("return type(e)") == "userdata");
    CHECK(box.exec<std::string>("return tostring(e):sub(1, 6)") == "entity");
    CHECK(box.exec<bool>("return game.same(e, e)") == true);
    CHECK(box.exec<bool>("return game.first() == e") == true);
    CHECK(box.exec<bool>("return rawequal(game.first(), e)") == false);
    REQUIRE(box.exec("other = game.spawn(3, 4)"));
    CHECK(box.exec<bool>("return other == e") == false);
    CHECK(box.exec<bool>("return game.same(e, other)") == false);

    CHECK(exec_error(box, "game.same(1, e)") == errc::kTypeMismatch);
    CHECK(exec_error(box, "game.same(e, {})") == errc::kTypeMismatch);

    REQUIRE(box.exec("game.forget(e)"));
    const auto stale = box.exec("game.same(e, e)");
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error().code == errc::kStaleHandle);
    CHECK(contains(stale.error().where, "game.same (argument 1)"));
    // The other handle is still valid.
    CHECK(box.exec<bool>("return game.same(other, other)") == true);
}

TEST_CASE("lib globals are locked proxies", "[script][binding]") {
    sandbox box = make_game_box();
    CHECK(box.exec<std::string>("return type(game)") == "userdata");
    CHECK(box.exec<std::string>("return getmetatable(game)") == "locked");
    CHECK(box.exec<std::string>("return type(game.debug)") == "userdata");
    CHECK(box.exec<bool>("return game.nope == nil") == true);
    CHECK(box.exec<bool>("return game.debug.nope == nil") == true);

    for (const std::string_view source : {"game.nope = 1", "game.spawn = 1", "game.tick = 1", "game.debug = 1", "game.debug.find = 1"}) {
        CAPTURE(source);
        const auto bad = box.exec(source);
        REQUIRE_FALSE(bad.has_value());
        CHECK(bad.error().code == errc::kInvalidArgument);
        CHECK(contains(describe(bad.error()), "not writable"));
    }
    CHECK(fx::g_tick == 17);
    CHECK(box.exec<int>("return game.tick") == 17);
    CHECK(box.exec<bool>("return setmetatable ~= nil and not pcall(setmetatable, game, {})") == true);
}

TEST_CASE("undo bindings are reverted with their module", "[script][binding]") {
    sandbox box = make_game_box();

    SECTION("undo fed with the result") {
        const auto mod = box.load("tests.binding.spawner", "e1 = game.spawn(1, 2)\ne2 = game.spawn(3, 4)");
        REQUIRE(mod.has_value());
        REQUIRE(fx::g_alive == std::vector<int>{1, 2});
        CHECK(box.status(*mod)->effects == 2);

        const auto report = box.revert(*mod);
        REQUIRE(report.has_value());
        CHECK(report->undone == 2);
        CHECK(fx::g_alive.empty());
        CHECK(fx::g_despawned == std::vector<int>{2, 1});
    }

    SECTION("undo fed with the arguments") {
        const auto mod = box.load("tests.binding.setter", "game.set_x(5)");
        REQUIRE(mod.has_value());
        REQUIRE(fx::g_x == 5);
        const auto report = box.revert(*mod);
        REQUIRE(report.has_value());
        CHECK(report->undone == 1);
        CHECK(fx::g_unset_calls == std::vector<int>{5});
        CHECK(fx::g_x == 0);
    }

    SECTION("irreversible bindings are counted") {
        const auto mod = box.load("tests.binding.boom", "game.explode()");
        REQUIRE(mod.has_value());
        CHECK(fx::g_explosions == 1);
        const auto info = box.status(*mod);
        REQUIRE(info.has_value());
        CHECK(info->effects == 1);
        CHECK(info->irreversible_effects == 1);

        const auto report = box.revert(*mod);
        REQUIRE(report.has_value());
        CHECK(report->irreversible == 1);
        CHECK(report->undone == 0);
        CHECK(fx::g_explosions == 1);
        CHECK(box.status(*mod)->state == module_state::kReverted);
    }

    SECTION("failed calls record nothing") {
        CHECK(exec_error(box, "game.checked(-1)") == errc::kOutOfRange);
        CHECK(exec_error(box, "game.spawn(1, 'x')") == errc::kTypeMismatch);
        CHECK(box.effects().empty());
    }
}

TEST_CASE("variable writes from several modules revert in any order", "[script][binding]") {
    sandbox box = make_game_box();
    fx::g_gravity = 0.0f;
    const auto a = box.load("tests.binding.grav.a", "game.gravity = 1");
    const auto b = box.load("tests.binding.grav.b", "game.gravity = 2");
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE(fx::g_gravity == 2.0f);

    SECTION("older first") {
        REQUIRE(box.revert(*a));
        CHECK(fx::g_gravity == 2.0f);
        REQUIRE(box.revert(*b));
        CHECK(fx::g_gravity == 0.0f);
    }

    SECTION("newer first") {
        REQUIRE(box.revert(*b));
        CHECK(fx::g_gravity == 1.0f);
        REQUIRE(box.revert(*a));
        CHECK(fx::g_gravity == 0.0f);
    }

    SECTION("across sandboxes") {
        sandbox other = make_game_box();
        fx::g_gravity = 2.0f; // make_game_box reset it; the first sandbox's writes are still layered
        REQUIRE(other.exec("game.gravity = 3"));
        REQUIRE(box.revert(*b));
        CHECK(fx::g_gravity == 3.0f);
        REQUIRE(box.revert(*a));
        CHECK(fx::g_gravity == 3.0f);
        other.revert_all();
        CHECK(fx::g_gravity == 0.0f);
    }
}

namespace shared_var_fixtures {

inline int g_shared = 0;
using shared_lib = Rhp::lib<"sharedvar">::var<"v", &g_shared>;

} // namespace shared_var_fixtures

TEST_CASE("sandboxes on two threads write one variable without a data race", "[script][binding][threads]") {
    shared_var_fixtures::g_shared = 0;
    std::atomic<int> failures{0};
    const auto writer = [&failures](int value) {
        sandbox box;
        if (!box.install<shared_var_fixtures::shared_lib>()) {
            ++failures;
            return;
        }
        const std::string write = std::format("sharedvar.v = {}", value);
        for (int i = 0; i < 1'000; ++i) {
            if (!box.exec(write) || !box.exec("return sharedvar.v")) {
                ++failures;
            }
        }
    }; // each sandbox reverts its writes when it dies, on its own thread
    {
        std::jthread a{writer, 1};
        std::jthread b{writer, 2};
    }
    CHECK(failures == 0);
    CHECK(shared_var_fixtures::g_shared == 0);
    CHECK(Rhp::script::detail::var_layers<&shared_var_fixtures::g_shared>::depth() == 0);
}
