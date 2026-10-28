// sandbox::narrow (decision AL13): scopes one exec or one module revision runs with on top of the
// sandbox's own, as a host narrows a script signed under an operator certificate.
#include <string>
#include <string_view>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/script/sandbox.hpp>

using Rhp::errc;
using Rhp::script::sandbox;
using Rhp::script::sandbox_options;

// Referenced as template arguments: a named namespace.
namespace narrow_tests_fixtures {

inline int g_coins = 0;

inline void buy(int n) {
    g_coins -= n;
}
inline int price() {
    return 3;
}
inline int dump() {
    return 7;
}
inline int base_price(int n) {
    return n;
}
inline int base_tax(int n) {
    return n;
}

using debug_lib = Rhp::lib<"debug">::fn<"dump", &dump>;
using shop_lib = Rhp::lib<"nshop">::fn<"buy", &buy, Rhp::cap<"narrow.write">>::fn<"price", &price>::sub<debug_lib>;
using other_lib = Rhp::lib<"nother">::fn<"price", &price>;

inline constexpr Rhp::lua_event<"tests.narrow.sale", int> sale{};
inline constexpr Rhp::patch_point<"tests.narrow.price", &base_price> price_point{};
inline constexpr Rhp::patch_point<"tests.narrow.tax", &base_tax> tax_point{};

} // namespace narrow_tests_fixtures

namespace {

namespace fx = narrow_tests_fixtures;

Rhp::scope_set scopes_of(std::string_view text) {
    auto s = Rhp::scope_set::parse(text);
    REQUIRE(s);
    return *s;
}

sandbox make_box(std::string_view scopes = "") {
    fx::g_coins = 0;
    sandbox_options options;
    options.caller_role = Rhp::role::kPatch;
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

} // namespace

TEST_CASE("narrow: an exec runs under its narrowing and the next one doesn't", "[script][narrow]") {
    sandbox box = make_box();
    box.narrow(scopes_of("!cap:narrow.write"));
    const Rhp::error refused = exec_error(box, "nshop.buy(1)");
    CHECK(refused.code == errc::kForbidden);
    CHECK(refused.message == "needs capability narrow.write");
    REQUIRE(box.exec("assert(nshop.price() == 3)")); // untagged bindings are untouched
    CHECK(fx::g_coins == 0);
    box.narrow({});
    REQUIRE(box.exec("nshop.buy(1)"));
    CHECK(fx::g_coins == -1);
}

TEST_CASE("narrow: the sandbox's own scopes still apply", "[script][narrow]") {
    sandbox box = make_box("!cap:narrow.write");
    box.narrow(scopes_of("cap:narrow.*"));
    CHECK(exec_error(box, "nshop.buy(1)").code == errc::kForbidden);
    CHECK(fx::g_coins == 0);
}

TEST_CASE("narrow: a narrowed exec can't leave handlers or patches behind", "[script][narrow]") {
    sandbox box = make_box();
    box.narrow(scopes_of("!cap:narrow.other")); // "cap:*" would be no narrowing at all
    for (const std::string_view call : {"rhp.after(10, function() end)", "rhp.every_frame(function() end)", "rhp.on('tests.narrow.sale', function() end)",
                                        "rhp.spawn(function() end)", "rhp.patch('tests.narrow.price', function(original, n) return 0 end)"}) {
        const Rhp::error refused = exec_error(box, call);
        CHECK(refused.code == errc::kForbidden);
        CHECK(refused.message.contains("narrowed exec"));
    }
    CHECK(fx::price_point(2) == 2);
    box.narrow({});
    REQUIRE(box.exec("rhp.after(10, function() end)"));
    (void)box.revert_all();
}

TEST_CASE("narrow: a narrowed module keeps its narrowing in later calls and handlers", "[script][narrow]") {
    sandbox box = make_box();
    box.narrow(scopes_of("!cap:narrow.write"));
    const auto mod = box.load("narrowed", R"lua(
        local M = {}
        local seen = nil
        rhp.on('tests.narrow.sale', function(n) seen = pcall(nshop.buy, n) end)
        function M.buy() return (pcall(nshop.buy, 1)) end
        function M.seen() return seen end
        return M)lua");
    box.narrow({});
    REQUIRE(mod);
    // What a module function returns: one boolean.
    const auto returned = [&](std::string_view fn) {
        const auto r = box.call(*mod, fn);
        REQUIRE(r);
        REQUIRE(r->size() == 1);
        REQUIRE(r->front().get_if<bool>() != nullptr);
        return *r->front().get_if<bool>();
    };
    CHECK_FALSE(returned("buy"));
    fx::sale.fire(2);
    CHECK_FALSE(returned("seen"));
    CHECK(fx::g_coins == 0);

    // A reload without a narrowing takes it away; a rollback to the narrowed revision brings it back.
    REQUIRE(box.reload(*mod, "local M = {} function M.buy() return (pcall(nshop.buy, 1)) end return M"));
    CHECK(returned("buy"));
    CHECK(fx::g_coins == -1);
    REQUIRE(box.rollback(*mod));
    CHECK_FALSE(returned("buy"));
    CHECK(fx::g_coins == -1);
    (void)box.revert_all();
}

TEST_CASE("narrow: patch and event scopes narrow rhp.patch and rhp.on", "[script][narrow]") {
    sandbox box = make_box();
    box.narrow(scopes_of("patch:tests.narrow.tax,!event:tests.narrow.*"));
    const auto denied = box.load("narrow_patch", "rhp.patch('tests.narrow.price', function(original, n) return 0 end) return {}");
    REQUIRE_FALSE(denied);
    CHECK(denied.error().message == "needs scope patch:tests.narrow.price");
    const auto event = box.load("narrow_event", "rhp.on('tests.narrow.sale', function() end) return {}");
    REQUIRE_FALSE(event);
    CHECK(event.error().message == "needs scope event:tests.narrow.sale");
    REQUIRE(box.load("narrow_tax", "rhp.patch('tests.narrow.tax', function(original, n) return 0 end) return {}"));
    box.narrow({});
    CHECK(fx::price_point(5) == 5);
    CHECK(fx::tax_point(5) == 0);
    (void)box.revert_all();
    CHECK(fx::tax_point(5) == 5);
}

TEST_CASE("narrow: scopes that deny a lib the sandbox has are refused", "[script][narrow]") {
    sandbox box = make_box();
    box.narrow(scopes_of("lib:nshop"));
    const auto refused = box.exec("return 1");
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::kForbidden);
    CHECK(refused.error().where == "nother");
    box.narrow(scopes_of("!lib:nshop.debug"));
    CHECK(box.load("narrow_sub", "return {}").error().where == "nshop.debug");
    // Allowing every lib it has, or saying nothing of libs, is fine.
    box.narrow(scopes_of("lib:nshop,lib:nother,!cap:narrow.write"));
    REQUIRE(box.exec("return nshop.debug.dump()"));
    box.narrow({});
}
