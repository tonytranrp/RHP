#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/utils/fixed_string.hpp>

using Rhp::errc;
using Rhp::role;
using Rhp::value;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

// Capability scopes in one sandbox (decision AL13). Referenced as template arguments: a named namespace.
namespace scope_tests_fixtures {

struct store_id {
    int v = 0;
    bool operator==(const store_id&) const = default;
};

inline int g_coins = 0;
inline int g_stock = 0;
inline float g_speed = 1.0f;

inline void buy(int n) {
    g_coins -= n;
}
inline int price() {
    return 3;
}
inline void grant(int n) {
    g_coins += n;
}
inline bool store_alive(const store_id& s) {
    return s.v != 0;
}
inline store_id open_store() {
    return store_id{1};
}
inline int restock(store_id, int n) {
    g_stock += n;
    return g_stock;
}
inline int stock_of(store_id) {
    return g_stock;
}
inline int dump() {
    return 7;
}
inline int hello() {
    return 1;
}
inline int base_price(int n) {
    return n;
}
inline int base_tax(int n) {
    return n;
}

using debug_lib = Rhp::lib<"debug">::var<"speed", &g_speed>::fn<"dump", &dump>;
using shop_lib = Rhp::lib<"shop">                                                      //
    ::fn<"buy", &buy, Rhp::cap<"economy.write">>                                       //
    ::fn<"price", &price>                                                              // untagged
    ::fn<"grant", &grant, Rhp::requires_role<role::kAdmin>, Rhp::cap<"economy.grant">> //
    ::handle<"store", store_id, &store_alive>                                          //
    ::fn<"open", &open_store>                                                          //
    ::method<"restock", &restock, Rhp::cap<"economy.write">>                           //
    ::property<"stock", &stock_of, Rhp::cap<"economy.read">>                           //
    ::sub<debug_lib>;
using other_lib = Rhp::lib<"other">::fn<"hello", &hello>;

inline constexpr Rhp::lua_event<"tests.scopes.sale", int> sale{};
inline constexpr Rhp::lua_event<"tests.scopes.secret", int> secret{};
inline constexpr Rhp::patch_point<"tests.scopes.price", &base_price> price_point{};
inline constexpr Rhp::patch_point<"tests.scopes.tax", &base_tax> tax_point{};

// 70 capability names, more than the 63 bits that are each one name's: the rest share the last bit.
template <std::size_t I>
consteval Rhp::utils::fixed_string<8> over_cap() {
    Rhp::utils::fixed_string<8> out{"over.c00"};
    out.chars[6] = static_cast<char>('0' + I / 10);
    out.chars[7] = static_cast<char>('0' + I % 10);
    return out;
}

template <std::size_t I>
consteval Rhp::utils::fixed_string<3> over_fn() {
    Rhp::utils::fixed_string<3> out{"f00"};
    out.chars[1] = static_cast<char>('0' + I / 10);
    out.chars[2] = static_cast<char>('0' + I % 10);
    return out;
}

template <class Seq>
struct over_lib_of;

template <std::size_t... Is>
struct over_lib_of<std::index_sequence<Is...>> {
    using type = Rhp::lib<"over", Rhp::script::detail::fn_entry<over_fn<Is>(), &hello, Rhp::cap<over_cap<Is>()>>...>;
};

using over_lib = over_lib_of<std::make_index_sequence<70>>::type;

} // namespace scope_tests_fixtures

namespace {

namespace fx = scope_tests_fixtures;

void reset() {
    fx::g_coins = 0;
    fx::g_stock = 0;
    fx::g_speed = 1.0f;
}

Rhp::scope_set scopes_of(std::string_view text) {
    auto s = Rhp::scope_set::parse(text);
    REQUIRE(s);
    return *s;
}

sandbox make_box(std::string_view scopes, role caller = role::kPatch) {
    sandbox_options options;
    options.caller_role = caller;
    options.scopes = scopes_of(scopes);
    options.output = [](std::string_view) {};
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::shop_lib>());
    REQUIRE(box.install<fx::other_lib>());
    return box;
}

Rhp::error exec_error(sandbox& box, std::string_view source) {
    auto r = box.exec(source);
    REQUIRE_FALSE(r);
    return r.error();
}

// The names of the libs (and their sub-libs, as paths) in an api() description.
void lib_paths(const value& libs, std::vector<std::string>& out) {
    for (const value& lib : *libs.get_if<value::array>()) {
        out.push_back(*lib.find("path")->get_if<std::string>());
        lib_paths(*lib.find("libs"), out);
    }
}

std::vector<std::string> names_in(const value& list, std::string_view field) {
    std::vector<std::string> out;
    for (const value& v : *list.get_if<value::array>()) {
        out.push_back(*v.find(field)->get_if<std::string>());
    }
    return out;
}

bool has(const std::vector<std::string>& v, std::string_view s) {
    return std::ranges::find(v, s) != v.end();
}

} // namespace

TEST_CASE("scopes: the default allows every lib cap point and event", "[script][scopes]") {
    reset();
    sandbox box = make_box("", role::kAdmin);
    REQUIRE(box.exec("shop.buy(2) shop.grant(5) local s = shop.open() s:restock(4) assert(s.stock == 4) assert(shop.debug.dump() == 7)"));
    CHECK(fx::g_coins == 3);
    CHECK(fx::g_stock == 4);
    REQUIRE(box.exec("assert(other.hello() == 1)"));
    REQUIRE(box.exec("rhp.patch('tests.scopes.price', function(original, n) return original(n) + 1 end)"));
    CHECK(fx::price_point(1) == 2);
    REQUIRE(box.exec("rhp.on('tests.scopes.secret', function() end) rhp.on('anything.at.all', function() end)"));
    fx::secret.fire(0); // an event registers itself where the program fires it (api() lists registered events)
    const value api = box.api();
    std::vector<std::string> libs;
    lib_paths(*api.find("libs"), libs);
    CHECK(libs == std::vector<std::string>{"shop", "shop.debug", "other"});
    CHECK(has(names_in(*api.find("events"), "name"), "tests.scopes.secret"));
    CHECK(has(names_in(*api.find("points"), "id"), "tests.scopes.price"));
    auto tunables = box.tunables();
    REQUIRE(tunables);
    CHECK(tunables->size() == 1);
    (void)box.revert_all();
    CHECK(fx::price_point(1) == 1);
}

TEST_CASE("scopes: a binding whose cap is denied raises like a missing role", "[script][scopes]") {
    reset();
    SECTION("a deny pattern") {
        sandbox box = make_box("!cap:economy.write");
        const Rhp::error bought = exec_error(box, "shop.buy(1)");
        CHECK(bought.code == errc::kForbidden);
        CHECK(bought.message == "needs capability economy.write");
        CHECK(bought.where.contains("shop.buy"));
        CHECK(fx::g_coins == 0);
        const Rhp::error restocked = exec_error(box, "shop.open():restock(2)");
        CHECK(restocked.code == errc::kForbidden);
        CHECK(restocked.where.contains("store:restock"));
        CHECK(fx::g_stock == 0);
        // Untagged bindings and other caps are untouched.
        REQUIRE(box.exec("assert(shop.price() == 3) assert(shop.open().stock == 0)"));
    }
    SECTION("an allow list") {
        sandbox box = make_box("cap:economy.read");
        CHECK(exec_error(box, "shop.buy(1)").code == errc::kForbidden);
        REQUIRE(box.exec("assert(shop.open().stock == 0)"));
    }
    SECTION("a property") {
        sandbox box = make_box("!cap:economy.read");
        const Rhp::error read = exec_error(box, "return shop.open().stock");
        CHECK(read.code == errc::kForbidden);
        CHECK(read.message == "needs capability economy.read");
        CHECK(read.where.contains("store.stock"));
    }
    SECTION("the role is checked first") {
        sandbox box = make_box("!cap:economy.grant");
        CHECK(exec_error(box, "shop.grant(1)").message == "needs role admin");
        sandbox admin = make_box("!cap:economy.grant", role::kAdmin);
        CHECK(exec_error(admin, "shop.grant(1)").message == "needs capability economy.grant");
        CHECK(fx::g_coins == 0);
    }
    SECTION("each sandbox has its own mask") {
        sandbox denied = make_box("!cap:economy.*");
        sandbox allowed = make_box("cap:economy.*");
        CHECK(exec_error(denied, "shop.buy(1)").code == errc::kForbidden);
        REQUIRE(allowed.exec("shop.buy(1)"));
        CHECK(fx::g_coins == -1);
        CHECK(exec_error(denied, "shop.open():restock(1)").code == errc::kForbidden);
    }
}

TEST_CASE("scopes: capability names past the 63rd share a bit and are told apart by name", "[script][scopes]") {
    sandbox_options options;
    options.scopes = scopes_of("!cap:over.c00,!cap:over.c69");
    sandbox box{std::move(options)};
    REQUIRE(box.install<fx::over_lib>());
    CHECK(exec_error(box, "over.f00()").message == "needs capability over.c00");
    CHECK(exec_error(box, "over.f69()").message == "needs capability over.c69");
    REQUIRE(box.exec("assert(over.f01() == 1) assert(over.f68() == 1) assert(over.f67() == 1)"));
    sandbox open;
    REQUIRE(open.install<fx::over_lib>());
    REQUIRE(open.exec("assert(over.f00() == 1) assert(over.f69() == 1)"));
}

TEST_CASE("scopes: a denied lib is not installed at all", "[script][scopes]") {
    reset();
    SECTION("a lib outside the allow list") {
        sandbox box = make_box("lib:shop");
        REQUIRE(box.exec("assert(other == nil) assert(shop.price() == 3)"));
        std::vector<std::string> libs;
        lib_paths(*box.api().find("libs"), libs);
        CHECK(libs == std::vector<std::string>{"shop", "shop.debug"});
        CHECK_FALSE(box.stubs().contains("other.hello"));
    }
    SECTION("a denied sub-lib") {
        sandbox box = make_box("!lib:shop.debug");
        REQUIRE(box.exec("assert(shop.debug == nil) assert(shop.price() == 3) assert(other.hello() == 1)"));
        std::vector<std::string> libs;
        lib_paths(*box.api().find("libs"), libs);
        CHECK(libs == std::vector<std::string>{"shop", "other"});
        auto tunables = box.tunables();
        REQUIRE(tunables);
        CHECK(tunables->empty());
        auto tuned = box.tune("shop.debug.speed", value{2.0});
        REQUIRE_FALSE(tuned);
        CHECK(tuned.error().code == errc::kNotFound);
        CHECK(fx::g_speed == 1.0f);
    }
}

TEST_CASE("scopes: rhp.patch refuses a point the scopes deny", "[script][scopes]") {
    sandbox box = make_box("patch:tests.scopes.tax");
    const Rhp::error refused = exec_error(box, "rhp.patch('tests.scopes.price', function(original, n) return 0 end)");
    CHECK(refused.code == errc::kForbidden);
    CHECK(refused.message == "needs scope patch:tests.scopes.price");
    CHECK(refused.where.contains("rhp.patch"));
    CHECK(fx::price_point(5) == 5);
    REQUIRE(box.exec("rhp.patch('tests.scopes.tax', function(original, n) return 0 end)"));
    CHECK(fx::tax_point(5) == 0);
    const auto points = names_in(*box.api().find("points"), "id");
    CHECK(has(points, "tests.scopes.tax"));
    CHECK_FALSE(has(points, "tests.scopes.price"));
    (void)box.revert_all();
    CHECK(fx::tax_point(5) == 5);
}

TEST_CASE("scopes: rhp.on refuses an event the scopes deny", "[script][scopes]") {
    sandbox box = make_box("!event:tests.scopes.secret,!event:admin.*");
    for (const std::string_view call : {"rhp.on('tests.scopes.secret', function() end)", "rhp.once('tests.scopes.secret', function() end)",
                                        "rhp.wait_event('tests.scopes.secret', 1)", "rhp.on('admin.kick', function() end)"}) {
        const Rhp::error refused = exec_error(box, call);
        CHECK(refused.code == errc::kForbidden);
        CHECK(refused.message.starts_with("needs scope event:"));
    }
    REQUIRE(box.exec("rhp.on('tests.scopes.sale', function(n) shop_seen = n end) rhp.on('game.round_over', function() end)"));
    REQUIRE(box.exec("rhp.on_error(function() end)")); // its own failed handlers, not an outside event
    fx::sale.fire(4);
    REQUIRE(box.exec("assert(shop_seen == 4)"));
    const auto events = names_in(*box.api().find("events"), "name");
    CHECK(has(events, "tests.scopes.sale"));
    CHECK_FALSE(has(events, "tests.scopes.secret"));
}
