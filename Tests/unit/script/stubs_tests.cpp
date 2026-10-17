#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/convert.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/stubs.hpp>

using Rhp::role;

// Fixtures referenced only as template arguments: a named namespace with inline definitions.
namespace stubs_tests_fixtures {

struct entity_id {
    int v = 0;
    bool operator==(const entity_id&) const = default;
};

struct vec3 {
    float x = 0;
    float y = 0;
    float z = 0;
};

struct color {
    int rgb = 0;
};

} // namespace stubs_tests_fixtures

// Names its Lua type for the stubs.
template <>
struct Rhp::convert<stubs_tests_fixtures::vec3> {
    static constexpr std::string_view lua_type = "vec3";
    static Rhp::value to_value(const stubs_tests_fixtures::vec3& v) { return Rhp::value{Rhp::value::array{v.x, v.y, v.z}}; }
    static Rhp::result<stubs_tests_fixtures::vec3> from_value(const Rhp::value&) { return stubs_tests_fixtures::vec3{}; }
};

// Convertible, but without a Lua type name: annotated as `any`.
template <>
struct Rhp::convert<stubs_tests_fixtures::color> {
    static Rhp::value to_value(const stubs_tests_fixtures::color& c) { return Rhp::value{static_cast<std::int64_t>(c.rgb)}; }
    static Rhp::result<stubs_tests_fixtures::color> from_value(const Rhp::value&) { return stubs_tests_fixtures::color{}; }
};

namespace stubs_tests_fixtures {

inline entity_id spawn(std::string_view, float x, float y) {
    return entity_id{static_cast<int>(x + y)};
}
inline void despawn(entity_id) {}
inline std::optional<entity_id> find(int id) {
    return entity_id{id};
}
inline void wipe() {}
inline std::string dump() {
    return {};
}
inline bool is_alive(const entity_id& e) {
    return e.v != 0;
}

inline std::tuple<int, std::string, bool> triple() {
    return {1, "a", true};
}
inline Rhp::result<int> checked(int x) {
    return x;
}
inline Rhp::result<void> reset() {
    return {};
}
inline Rhp::result<std::tuple<double, std::uint8_t>> split() {
    return std::tuple<double, std::uint8_t>{1.0, 2};
}
inline void maybe(std::optional<int>) {}
inline Rhp::value echo(Rhp::value v) {
    return v;
}
inline vec3 tint(const vec3& v, color) {
    return v;
}
inline color pick() {
    return {};
}
inline void target(std::optional<entity_id>) {}
inline void named(const std::string&, const char*) {}

inline float g_gravity = -9.8f;
inline int g_tick = 0;
inline vec3 g_wind{};

using game_lib = Rhp::lib<"game">                              //
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>                 //
    ::fn<"find", &find>                                        //
    ::fn<"wipe", &wipe, Rhp::requires_role<Rhp::role::kAdmin>> //
    ::var<"gravity", &g_gravity>                               //
    ::ro<"tick", &g_tick>                                      //
    ::handle<"entity", entity_id, &is_alive>                   //
    ::sub<Rhp::lib<"debug">::fn<"dump", &dump>>;

using types_lib = Rhp::lib<"types"> //
    ::fn<"triple", &triple>         //
    ::fn<"checked", &checked>       //
    ::fn<"reset", &reset>           //
    ::fn<"split", &split>           //
    ::fn<"maybe", &maybe>           //
    ::fn<"echo", &echo>             //
    ::fn<"tint", &tint>             //
    ::fn<"pick", &pick>             //
    ::fn<"target", &target>         //
    ::fn<"named", &named>           //
    ::var<"wind", &g_wind>          //
    ::handle<"entity", entity_id, &is_alive>;

// The handle lives two levels down; the root's function still sees it by name.
using nested_lib = Rhp::lib<"a"> //
    ::fn<"first", &find>         //
    ::sub<Rhp::lib<"b">          //
          ::sub<Rhp::lib<"c">    //
                ::fn<"f", &wipe> //
                ::handle<"entity", entity_id, &is_alive>>>;

using empty_lib = Rhp::lib<"empty">;

} // namespace stubs_tests_fixtures

namespace stubs = Rhp::script::stubs;
using namespace stubs_tests_fixtures;

TEST_CASE("generate emits the whole lib for kAdmin", "[script][stubs]") {
    const std::string expected = R"lua(---@class entity

---@class game
---@field gravity number
---@field tick integer read-only
---@field debug game.debug
game = {}

---@param arg1 string
---@param arg2 number
---@param arg3 number
---@return entity
function game.spawn(arg1, arg2, arg3) end

---@param arg1 integer
---@return entity?
function game.find(arg1) end

function game.wipe() end

---@class game.debug
game.debug = {}

---@return string
function game.debug.dump() end
)lua";
    REQUIRE(stubs::generate<game_lib>(role::kAdmin) == expected);
    REQUIRE(stubs::generate<game_lib>() == expected);
}

TEST_CASE("generate filters functions and writable fields by role", "[script][stubs]") {
    SECTION("observe") {
        const std::string out = stubs::generate<game_lib>(role::kObserve);
        CHECK(!out.contains("game.spawn"));
        CHECK(!out.contains("game.wipe"));
        CHECK(out.contains("function game.find(arg1) end"));
        CHECK(out.contains("---@field gravity number read-only\n"));
        CHECK(out.contains("---@field tick integer read-only\n"));
        // Sub-libs and handle classes stay.
        CHECK(out.starts_with("---@class entity\n\n"));
        CHECK(out.contains("---@class game.debug\ngame.debug = {}\n"));
        CHECK(out.contains("function game.debug.dump() end"));
    }
    SECTION("patch") {
        const std::string out = stubs::generate<game_lib>(role::kPatch);
        CHECK(out.contains("function game.spawn(arg1, arg2, arg3) end"));
        CHECK(!out.contains("game.wipe"));
        CHECK(out.contains("---@field gravity number\n"));
    }
}

TEST_CASE("generate maps parameter and result types", "[script][stubs]") {
    const std::string out = stubs::generate<types_lib>();

    SECTION("tuples give one ---@return per element") {
        CHECK(out.contains("---@return integer\n---@return string\n---@return boolean\nfunction types.triple() end\n"));
    }
    SECTION("Rhp::result<T> is T, Rhp::result<void> is nothing") {
        CHECK(out.contains("---@param arg1 integer\n---@return integer\nfunction types.checked(arg1) end\n"));
        CHECK(out.contains("\n\nfunction types.reset() end\n"));
        CHECK(out.contains("---@return number\n---@return integer\nfunction types.split() end\n"));
    }
    SECTION("optionals and Rhp::value") {
        CHECK(out.contains("---@param arg1 integer?\nfunction types.maybe(arg1) end\n"));
        CHECK(out.contains("---@param arg1 any\n---@return any\nfunction types.echo(arg1) end\n"));
        CHECK(out.contains("---@param arg1 entity?\nfunction types.target(arg1) end\n"));
    }
    SECTION("Rhp::convert types use lua_type, or any without it") {
        CHECK(out.contains("---@param arg1 vec3\n---@param arg2 any\n---@return vec3\nfunction types.tint(arg1, arg2) end\n"));
        CHECK(out.contains("---@return any\nfunction types.pick() end\n"));
        CHECK(out.contains("---@field wind vec3\n"));
    }
    SECTION("cv/ref stripped, every string-like type is string") {
        CHECK(out.contains("---@param arg1 string\n---@param arg2 string\nfunction types.named(arg1, arg2) end\n"));
    }
    SECTION("ends with exactly one newline") {
        CHECK(out.ends_with(" end\n"));
        CHECK(!out.ends_with("\n\n"));
    }
}

TEST_CASE("generate walks nested sub-libs", "[script][stubs]") {
    const std::string expected = R"lua(---@class entity

---@class a
---@field b a.b
a = {}

---@param arg1 integer
---@return entity?
function a.first(arg1) end

---@class a.b
---@field c a.b.c
a.b = {}

---@class a.b.c
a.b.c = {}

function a.b.c.f() end
)lua";
    REQUIRE(stubs::generate<nested_lib>() == expected);
}

TEST_CASE("generate handles a lib with no entries", "[script][stubs]") {
    REQUIRE(stubs::generate<empty_lib>() == "---@class empty\nempty = {}\n");
    REQUIRE(stubs::generate<empty_lib>(role::kObserve) == "---@class empty\nempty = {}\n");
}

TEST_CASE("write streams generate", "[script][stubs]") {
    std::ostringstream os;
    stubs::write<game_lib>(os, role::kPatch);
    REQUIRE(os.str() == stubs::generate<game_lib>(role::kPatch));

    std::ostringstream all;
    stubs::write<game_lib>(all);
    REQUIRE(all.str() == stubs::generate<game_lib>());
}

TEST_CASE("rhp_api filters rhp.patch by role", "[script][stubs]") {
    const std::string observe = stubs::rhp_api(role::kObserve);
    const std::string patch = stubs::rhp_api(role::kPatch);
    const std::string admin = stubs::rhp_api();

    CHECK(observe.starts_with("---@meta\n\n---@class rhp\n"));
    CHECK(!observe.contains("rhp.patch"));
    CHECK(patch.contains("---@param handler fun(original: function, ...): any\nfunction rhp.patch(id, handler) end\n\n"));
    CHECK(admin == patch);

    // Observe is patch minus exactly the rhp.patch block.
    const std::string block = "---Overrides a C++ patch point until this module is reverted.\n"
                              "---@param id string\n"
                              "---@param handler fun(original: function, ...): any\n"
                              "function rhp.patch(id, handler) end\n\n";
    std::string without = patch;
    without.erase(without.find(block), block.size());
    CHECK(without == observe);

    for (const std::string& api : {observe, patch}) {
        CHECK(api.contains("function rhp.timer(ms, fn, repeating) end\n"));
        CHECK(api.contains("function require(name) end\n"));
        CHECK(api.ends_with("---@field on_restore? fun(state: any)\n"));
        CHECK(!api.ends_with("\n\n"));
        for (const char* fn : {"function rhp.after(ms, fn, opts) end", "function rhp.every(ms, fn, opts) end", "function rhp.every_frame(fn, opts) end",
                               "function rhp.every_frames(frames, fn, opts) end", "function rhp.pause(id) end", "function rhp.resume(id) end",
                               "function rhp.reschedule(id, interval) end", "function rhp.timers() end", "function rhp.on(event, handler, opts) end",
                               "function rhp.once(event, handler, opts) end", "function rhp.on_error(handler, opts) end", "function rhp.publish(event, ...) end",
                               "function rhp.wait_event(event, timeout_ms) end", "function rhp.spawn(fn, ...) end", "function rhp.tasks() end",
                               "function rhp.stats() end", "---@class rhp.task", "---@class rhp.handler_options"}) {
            CHECK(api.contains(fn));
        }
    }
}
