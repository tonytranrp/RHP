#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/async.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stubs.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;
using Rhp::script::value_list;

namespace method_tests_fixtures {

struct unit_id {
    std::uint32_t value = 0;
    bool operator==(const unit_id&) const = default;
};

struct unit {
    float x = 0;
    float y = 0;
    int hp = 100;
    bool alive = true;
};

inline std::map<std::uint32_t, unit> g_units;
inline std::uint32_t g_next = 1;
inline std::vector<Rhp::promise<int>> g_heals;

inline void reset() {
    g_units.clear();
    g_next = 1;
    g_heals.clear();
}

inline bool is_alive(const unit_id& id) {
    const auto it = g_units.find(id.value);
    return it != g_units.end() && it->second.alive;
}

inline unit_id make_unit(float x, float y) {
    const unit_id id{g_next++};
    g_units[id.value] = unit{x, y, 100, true};
    return id;
}

inline void kill(unit_id id) {
    g_units[id.value].alive = false;
}

inline std::tuple<float, float> move(unit_id id, float dx, float dy) {
    unit& u = g_units[id.value];
    u.x += dx;
    u.y += dy;
    return {u.x, u.y};
}

inline void move_back(unit_id id, float dx, float dy) {
    unit& u = g_units[id.value];
    u.x -= dx;
    u.y -= dy;
}

inline float x_of(unit_id id) {
    return g_units[id.value].x;
}

inline int hp_of(const unit_id& id) {
    return g_units[id.value].hp;
}

inline std::string secret_of(unit_id) {
    return "admin only";
}

inline Rhp::result<int> damage(unit_id id, int amount) {
    if (amount < 0) {
        return Rhp::fail(errc::kOutOfRange, "damage can't be negative");
    }
    g_units[id.value].hp -= amount;
    return g_units[id.value].hp;
}

inline Rhp::async<int> heal(unit_id) {
    auto [result, done] = Rhp::make_async<int>();
    g_heals.push_back(std::move(done));
    return std::move(result);
}

inline bool same(unit_id a, unit_id b) {
    return a == b;
}

using game_lib = Rhp::lib<"units">::handle<"unit", unit_id, &is_alive>::fn<"make", &make_unit>::fn<"kill", &kill>::method<"move", &move, Rhp::undo<&move_back>>::method<"damage", &damage>::method<"heal", &heal>::method<"same", &same>::property<"x", &x_of>::property<"hp", &hp_of>::property<"secret", &secret_of, Rhp::requires_role<Rhp::role::kAdmin>>;

// A second lib adding a member to the same handle (it re-declares the handle).
inline std::string describe(unit_id id) {
    return "unit " + std::to_string(id.value);
}

using extra_lib = Rhp::lib<"units_extra">::handle<"unit", unit_id, &is_alive>::method<"describe", &describe>;
using clash_lib = Rhp::lib<"units_clash">::handle<"unit", unit_id, &is_alive>::method<"move", &describe>;

// Methods only: __index is the methods table.
struct tag_id {
    int value = 0;
    bool operator==(const tag_id&) const = default;
};

inline bool tag_alive(const tag_id&) {
    return true;
}

inline tag_id make_tag(int v) {
    return tag_id{v};
}

inline int tag_value(tag_id t) {
    return t.value;
}

using tag_lib = Rhp::lib<"tags">::handle<"tag", tag_id, &tag_alive>::fn<"make", &make_tag>::method<"value", &tag_value>;

inline constexpr Rhp::lua_event<"tests.methods.spotted", unit_id> spotted{};

struct bare_id {
    int v = 0;
    bool operator==(const bare_id&) const = default;
};

inline bool bare_alive(const bare_id&) {
    return true;
}

inline bare_id make_bare() {
    return bare_id{1};
}

using bare_lib = Rhp::lib<"bare">::handle<"bare", bare_id, &bare_alive>::fn<"make", &make_bare>;

} // namespace method_tests_fixtures

namespace {

namespace fx = method_tests_fixtures;

sandbox make_box(Rhp::role role = Rhp::role::kPatch) {
    fx::reset();
    sandbox_options options;
    options.caller_role = role;
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::game_lib>());
    return box;
}

std::string text(const Rhp::result<value_list>& r, std::size_t i = 0) {
    if (!r) {
        return "error: " + r.error().where + ": " + r.error().message;
    }
    if (i >= r->size()) {
        return "<none>";
    }
    const auto* s = r->at(i).get_if<std::string>();
    return s != nullptr ? *s : "<not a string>";
}

} // namespace

TEST_CASE("methods are called on a handle with colon syntax", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(1, 2) local x, y = u:move(3, 4) return x, y");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{4.0}, Rhp::value{6.0}});
}

TEST_CASE("properties read a handle's values", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(7, 0) u:move(1, 0) return u.x, u.hp");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{8.0}, Rhp::value{100}});
}

TEST_CASE("a handle type without members reads every key as nil and refuses writes", "[script][methods]") {
    sandbox box = make_box();
    REQUIRE(box.install<fx::bare_lib>());
    const auto r = box.exec("local b = bare.make() return b.anything == nil");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{true}});
    CHECK(box.exec("local b = bare.make() b.x = 1").error().code == errc::kInvalidArgument);
}

TEST_CASE("an unknown member reads as nil", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(0, 0) return u.nothing == nil, u.move ~= nil");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{true}, Rhp::value{true}});
}

TEST_CASE("handle members are read-only", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(0, 0) u.x = 5");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kInvalidArgument);
    CHECK(r.error().message.find("unit.x is read-only") != std::string::npos);
}

TEST_CASE("a method's undo is journaled like a function's", "[script][methods]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.methods.mover", "u = units.make(0, 0) u:move(5, 5)");
    REQUIRE(mod.has_value());
    CHECK(fx::g_units[1].x == 5.0f);
    REQUIRE(box.revert(*mod));
    CHECK(fx::g_units[1].x == 0.0f);
}

TEST_CASE("a method called with dot syntax and no handle names self", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(0, 0) u.move(1, 2)");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().code == errc::kTypeMismatch);
    CHECK(r.error().where == "unit:move (self)");
}

TEST_CASE("a method's argument errors count from after self", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(0, 0) u:move(1, 'far')");
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().where == "unit:move (argument 2)");
}

TEST_CASE("a stale handle fails its method and property calls", "[script][methods]") {
    sandbox box = make_box();
    const auto method = box.exec("local u = units.make(0, 0) units.kill(u) return u:move(1, 1)");
    REQUIRE_FALSE(method.has_value());
    CHECK(method.error().code == errc::kStaleHandle);
    const auto property = box.exec("local u = units.make(0, 0) units.kill(u) return u.hp");
    REQUIRE_FALSE(property.has_value());
    CHECK(property.error().code == errc::kStaleHandle);
}

TEST_CASE("result errors of a method are raised with its label", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local u = units.make(0, 0) return pcall(u.damage, u, -1)");
    REQUIRE(r.has_value());
    CHECK((*r)[0] == Rhp::value{false});
    CHECK(text(r, 1).find("unit:damage") != std::string::npos);
    const auto ok = box.exec("local u = units.make(0, 0) return u:damage(30)");
    REQUIRE(ok.has_value());
    CHECK(*ok == value_list{Rhp::value{70}});
}

TEST_CASE("methods take other handles as arguments", "[script][methods]") {
    sandbox box = make_box();
    const auto r = box.exec("local a, b = units.make(0, 0), units.make(1, 1) return a:same(a), a:same(b)");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{true}, Rhp::value{false}});
}

TEST_CASE("an async method suspends the script", "[script][methods][async]") {
    sandbox box = make_box();
    REQUIRE(box.exec("local u = units.make(0, 0) healed = u:heal()"));
    REQUIRE(fx::g_heals.size() == 1);
    CHECK(fx::g_heals[0].complete(150));
    box.pump();
    const auto r = box.exec("return healed");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{150}});
}

TEST_CASE("properties a role can't use are refused", "[script][methods]") {
    sandbox patcher = make_box(Rhp::role::kPatch);
    const auto refused = patcher.exec("local u = units.make(0, 0) return u.secret");
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error().code == errc::kForbidden);
    sandbox admin = make_box(Rhp::role::kAdmin);
    CHECK(text(admin.exec("local u = units.make(0, 0) return u.secret")) == "admin only");
}

TEST_CASE("another lib can add members to the same handle", "[script][methods]") {
    sandbox box = make_box();
    REQUIRE(box.install<fx::extra_lib>());
    CHECK(text(box.exec("local u = units.make(0, 0) return u:describe()")) == "unit 1");
    const auto clash = box.install<fx::clash_lib>();
    REQUIRE_FALSE(clash.has_value());
    CHECK(clash.error().code == errc::kAlreadyLoaded);
    // The failed install added nothing: move is still the original method.
    const auto r = box.exec("local u = units.make(0, 0) return (u:move(1, 1))");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{1.0}});
}

TEST_CASE("a handle with only methods works without properties", "[script][methods]") {
    sandbox box;
    REQUIRE(box.install<fx::tag_lib>());
    const auto r = box.exec("local t = tags.make(9) return t:value(), t.missing == nil");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{9}, Rhp::value{true}});
}

TEST_CASE("handles delivered by events carry their methods", "[script][methods]") {
    sandbox box = make_box();
    const auto mod = box.load("tests.methods.watcher", "seen = 0 rhp.on('tests.methods.spotted', function(u) seen = u.hp end) function seen_hp() return seen end");
    REQUIRE(mod.has_value());
    const auto id = fx::make_unit(0, 0);
    fx::spotted.fire(id); // queued for the sandbox's next pump()
    box.pump();
    const auto r = box.call(*mod, "seen_hp");
    REQUIRE(r.has_value());
    CHECK(*r == value_list{Rhp::value{100}});
}

TEST_CASE("stubs list a handle's methods and properties", "[script][methods][stubs]") {
    const std::string patch = Rhp::script::stubs::generate<fx::game_lib>(Rhp::role::kPatch);
    CHECK(patch.find("---@class unit\n") != std::string::npos);
    CHECK(patch.find("---@field move fun(self: unit, arg1: number, arg2: number): number, number\n") != std::string::npos);
    CHECK(patch.find("---@field heal async fun(self: unit): integer\n") != std::string::npos);
    CHECK(patch.find("---@field same fun(self: unit, arg1: unit): boolean\n") != std::string::npos);
    CHECK(patch.find("---@field x number read-only\n") != std::string::npos);
    CHECK(patch.find("---@field hp integer read-only\n") != std::string::npos);
    CHECK(patch.find("secret") == std::string::npos);
    CHECK(patch.find("function units.move") == std::string::npos);
    const std::string admin = Rhp::script::stubs::generate<fx::game_lib>(Rhp::role::kAdmin);
    CHECK(admin.find("---@field secret string read-only\n") != std::string::npos);
}
