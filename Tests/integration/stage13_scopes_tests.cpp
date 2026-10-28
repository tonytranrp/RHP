// Stage 13b capability scopes over the wire (decision AL13): a keyring line's scopes reach the
// identity's sandbox (libs, caps, patch points, events), the request check (op:) and remote
// subscriptions (event:); without the column nothing changes.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/eventually.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/core/value.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/script/patch_point.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace stage13_scopes_fixtures {

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
inline int hello() {
    return 1;
}
inline int base_price(int n) {
    return n;
}
inline int quote(int n);

// quote hits the patch point on the pump thread (a layer is skipped on any other thread).
using shop_lib = Rhp::lib<"s13s">::fn<"buy", &buy, Rhp::cap<"s13s.write">>::fn<"price", &price>::fn<"quote", &quote>::sub<Rhp::lib<"debug">::fn<"dump", &dump>>;
using other_lib = Rhp::lib<"s13other">::fn<"hello", &hello>;

inline constexpr Rhp::lua_event<"itest.s13s.secret", int> secret_event{};
inline constexpr Rhp::lua_event<"itest.s13s.sale", int> sale_event{};
inline constexpr Rhp::patch_point<"itest.s13s.price", &base_price> price_point{};

inline int quote(int n) {
    return price_point(n);
}

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;

constexpr std::string_view kNarrow = "lib:s13s,!lib:s13s.debug,!cap:s13s.write,!patch:itest.s13s.*,!event:itest.s13s.secret,!event:game.hidden,!op:load,!op:revert_all";
constexpr std::string_view kWatch = "op:exec,op:subscribe,op:unsubscribe";

struct keys {
    Rhp::security::key full = *Rhp::security::key::generate();
    Rhp::security::key narrow = *Rhp::security::key::generate();
    Rhp::security::key watch = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        // As a keyring file says it: the third line has no scopes column.
        const std::string text = "narrow admin " + narrow.to_base64() + " " + std::string{kNarrow} + "\n" + "watch observe " + watch.to_base64() + " " +
                                 std::string{kWatch} + "\n" + "full patch " + full.to_base64() + "\n";
        auto ring = Rhp::security::keyring::parse(text);
        REQUIRE(ring);
        return std::move(*ring);
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
    [[nodiscard]] Rhp::security::psk_identity as(std::string_view who) const {
        if (who == "narrow") {
            return {"narrow", narrow};
        }
        if (who == "watch") {
            return {"watch", watch};
        }
        return {"full", full};
    }
};

// A host pumped on its own thread, with both libs installed.
class running_host {
public:
    running_host(Rhp::endpoint ep, const keys& k) : host_(std::move(ep), k.ring(), k.trusted()) {
        REQUIRE(host_.install<shop_lib>());
        REQUIRE(host_.install<other_lib>());
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~running_host() {
        pump_.request_stop();
        if (pump_.joinable()) {
            pump_.join();
        }
    }

    running_host(const running_host&) = delete;
    running_host& operator=(const running_host&) = delete;

private:
    Rhp::host<cfg> host_;
    std::jthread pump_;
};

struct received {
    std::mutex mutex;
    std::vector<std::string> names;

    Rhp::remote_event_fn fn() {
        return [this](const Rhp::remote_event& e) {
            const std::scoped_lock lock{mutex};
            names.emplace_back(e.name);
        };
    }
    std::vector<std::string> copy() {
        const std::scoped_lock lock{mutex};
        return names;
    }
};

[[nodiscard]] bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

} // namespace stage13_scopes_fixtures

using namespace stage13_scopes_fixtures;
using rhp_test::eventually;

TEST_CASE("stage13: an identity without scopes reaches everything as before", "[stage13][scopes]") {
    keys k;
    g_coins = 0;
    const auto at = Rhp::endpoint::listen("itest.s13s.full", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), k.as("full"), k.signer()};
    CHECK(c.exec<int>("s13s.buy(2) return s13s.debug.dump() + s13other.hello()") == 8);
    CHECK(g_coins == -2);
    REQUIRE(c.load("s13s.m", "rhp.patch('itest.s13s.price', function(original, n) return original(n) * 10 end)"));
    CHECK(c.exec<int>("return s13s.quote(2)") == 20);
    received got;
    REQUIRE(c.on("itest.s13s.secret", got.fn()));
}

TEST_CASE("stage13: a keyring line's scopes reach the identity's sandbox", "[stage13][scopes]") {
    keys k;
    g_coins = 0;
    const auto at = Rhp::endpoint::listen("itest.s13s.sandbox", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), k.as("narrow"), k.signer()};
    // lib: the other lib and the denied sub-lib aren't there at all.
    CHECK(c.exec<bool>("return s13other == nil and s13s.debug == nil and s13s.price() == 3") == true);
    // cap: the tagged binding raises like a missing role.
    const auto bought = c.exec("s13s.buy(1)");
    REQUIRE_FALSE(bought);
    CHECK(bought.error().code == errc::kForbidden);
    CHECK(contains(bought.error().message, "needs capability s13s.write"));
    CHECK(g_coins == 0);
    // patch: refused when attached.
    const auto patched = c.exec("rhp.patch('itest.s13s.price', function() return 0 end)");
    REQUIRE_FALSE(patched);
    CHECK(patched.error().code == errc::kForbidden);
    CHECK(c.exec<int>("return s13s.quote(2)") == 2);
    // event: rhp.on refuses the denied event, allows the others.
    CHECK(c.exec("rhp.on('itest.s13s.secret', function() end)").error().code == errc::kForbidden);
    CHECK(c.exec("rhp.on('itest.s13s.sale', function() end)"));
}

TEST_CASE("stage13: a request whose op the scopes deny is refused after the role check", "[stage13][scopes]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s13s.ops", 1);
    running_host host{at, k};
    Rhp::client<cfg> narrow{at.reversed(), k.as("narrow"), k.signer()};
    const auto loaded = narrow.load("s13s.n", "return {}");
    REQUIRE_FALSE(loaded);
    CHECK(loaded.error().code == errc::kForbidden);
    CHECK(contains(loaded.error().message, "needs scope op:load"));
    CHECK(narrow.revert_all().error().code == errc::kForbidden); // admin's role allows it; the scope doesn't
    CHECK(narrow.list());                                        // no allow pattern for op: every other op
    CHECK(narrow.exec<int>("return 6 * 7") == 42);

    Rhp::client<cfg> watch{at.reversed(), k.as("watch"), k.signer()};
    CHECK(watch.exec<int>("return 1") == 1);
    const auto listed = watch.list();
    REQUIRE_FALSE(listed);
    CHECK(listed.error().code == errc::kForbidden);
    CHECK(contains(listed.error().message, "needs scope op:list"));
    // The role is checked first: observe can't load whatever its scopes say.
    const auto load = watch.load("s13s.w", "return {}");
    REQUIRE_FALSE(load);
    CHECK(contains(load.error().message, "needs role patch"));
}

TEST_CASE("stage13: a remote subscription to a denied event is refused", "[stage13][scopes]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s13s.events", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), k.as("narrow"), k.signer()};
    received got;
    // A C++ lua_event the scopes deny: refused (remote observe sessions could listen to any before).
    const auto secret = c.on("itest.s13s.secret", got.fn());
    REQUIRE_FALSE(secret);
    CHECK(secret.error().code == errc::kForbidden);
    CHECK(secret_event.listeners() == 0);
    // A script event the scopes deny: refused too.
    CHECK(c.on("game.hidden", got.fn()).error().code == errc::kForbidden);
    // "*" (every script event of the identity) delivers only what the scopes allow.
    REQUIRE(c.on("*", got.fn()));
    REQUIRE(c.on("itest.s13s.sale", got.fn()));
    REQUIRE(c.exec("rhp.publish('game.hidden', 1) rhp.publish('game.shown', 2)"));
    sale_event.fire(5);
    REQUIRE(eventually([&] { return got.copy().size() >= 2; }));
    REQUIRE(c.exec("return 1")); // a round trip after the publishes' pump
    std::this_thread::sleep_for(50ms);
    const auto names = got.copy();
    CHECK(std::ranges::find(names, "game.shown") != names.end());
    CHECK(std::ranges::find(names, "itest.s13s.sale") != names.end());
    CHECK(std::ranges::find(names, "game.hidden") == names.end());
}
