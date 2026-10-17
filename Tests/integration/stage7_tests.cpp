#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/lua_event.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace stage7_fixtures {

inline int g_ticks = 0;
inline constexpr Rhp::lua_event<"itest.s7.alarm", int, std::string_view> alarm_event{};

inline void raise_alarm(int level) {
    alarm_event.fire(level, "from a script");
}

using test_lib = Rhp::lib<"s7">::var<"ticks", &g_ticks>::fn<"alarm", &raise_alarm>;

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
using fast_redial_cfg = cfg::limits<Rhp::limits{.backoff_min_ms = 5, .backoff_max_ms = 40}>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::key other = *Rhp::security::key::generate();
    Rhp::security::key observe = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin},
                                      {"patch", patch, Rhp::role::kPatch},
                                      {"other", other, Rhp::role::kPatch},
                                      {"observe", observe, Rhp::role::kObserve}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
    [[nodiscard]] Rhp::security::psk_identity as(std::string_view name) const {
        const std::string n{name};
        return {n, n == "admin" ? admin : n == "patch" ? patch
                                      : n == "other"   ? other
                                                       : observe};
    }
};

// A host pumped on its own thread.
template <class Cfg>
class running_host {
public:
    running_host(Rhp::endpoint ep, const keys& k, Rhp::host_options options = {}) : host_(std::move(ep), k.ring(), k.trusted(), options) {
        REQUIRE(host_.template install<test_lib>());
    }

    void start() {
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

    Rhp::host<Cfg>* operator->() { return &host_; }

private:
    Rhp::host<Cfg> host_;
    std::jthread pump_;
};

bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = 10s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::this_thread::sleep_for(2ms);
    }
    return true;
}

// Events a client received (on its network thread).
struct received {
    struct item {
        std::string name;
        Rhp::module_id module;
        Rhp::value_list args;
        std::uint64_t dropped = 0;
    };
    std::mutex mutex;
    std::vector<item> items;

    Rhp::remote_event_fn fn() {
        return [this](const Rhp::remote_event& e) {
            const std::scoped_lock lock{mutex};
            items.push_back(item{std::string{e.name}, e.module, {e.args.begin(), e.args.end()}, e.dropped});
        };
    }
    std::size_t size() {
        const std::scoped_lock lock{mutex};
        return items.size();
    }
    std::vector<item> copy() {
        const std::scoped_lock lock{mutex};
        return items;
    }
};

} // namespace stage7_fixtures

using namespace stage7_fixtures;

TEST_CASE("stage7: a client receives what scripts of its identity publish", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.publish", 1);
    running_host<cfg> host{at, k};
    host.start();
    Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer()};
    received got;
    const auto id = c.on("game.round_over", got.fn());
    REQUIRE(id);
    REQUIRE(c.exec("rhp.publish('game.round_over', 'red', 3) rhp.publish('game.ignored', 1)"));
    REQUIRE(eventually([&] { return got.size() == 1; }));
    const auto items = got.copy();
    CHECK(items[0].name == "game.round_over");
    CHECK(items[0].args == Rhp::value_list{value{"red"}, value{3}});
    REQUIRE(c.off(*id));
    REQUIRE(c.exec("rhp.publish('game.round_over', 'blue', 1)"));
    REQUIRE(c.exec("return 1")); // a round trip after the publish's pump
    std::this_thread::sleep_for(50ms);
    CHECK(got.size() == 1);
    CHECK(c.off(*id).error().code == errc::kNotFound);
}

TEST_CASE("stage7: a client receives C++ events from the pump thread and other threads", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.cpp", 1);
    running_host<cfg> host{at, k};
    host.start();
    Rhp::client<cfg> c{at.reversed(), k.as("observe"), k.signer()}; // observe may subscribe
    received got;
    REQUIRE(c.on("itest.s7.alarm", got.fn()));
    CHECK(alarm_event.listeners() == 1);
    REQUIRE(c.exec("s7.alarm(2)"));
    std::thread game{[] { alarm_event.fire(9, "from a game thread"); }};
    game.join();
    REQUIRE(eventually([&] { return got.size() == 2; }));
    const auto items = got.copy();
    CHECK(items[0].args == Rhp::value_list{value{2}, value{"from a script"}});
    CHECK(items[1].args == Rhp::value_list{value{9}, value{"from a game thread"}});
    CHECK(items[0].module == Rhp::module_id{});
}

TEST_CASE("stage7: another identity's script events are not delivered", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.isolated", 1);
    running_host<cfg> host{at, k};
    host.start();
    Rhp::client<cfg> mine{at.reversed(), k.as("patch"), k.signer()};
    Rhp::client<cfg> theirs{at.reversed(), k.as("other"), k.signer()};
    received got;
    REQUIRE(mine.on("*", got.fn()));
    REQUIRE(theirs.exec("rhp.publish('game.secret', 1)"));
    REQUIRE(mine.exec("rhp.publish('game.mine', 2)"));
    REQUIRE(eventually([&] { return got.size() == 1; }));
    std::this_thread::sleep_for(50ms);
    const auto items = got.copy();
    REQUIRE(items.size() == 1);
    CHECK(items[0].name == "game.mine");
}

TEST_CASE("stage7: unsubscribe and a closed session detach the host from C++ events", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.detach", 1);
    running_host<cfg> host{at, k};
    host.start();
    received got;
    {
        Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer()};
        const auto a = c.on("itest.s7.alarm", got.fn());
        const auto b = c.on("itest.s7.alarm", got.fn());
        REQUIRE(a);
        REQUIRE(b);
        CHECK(alarm_event.listeners() == 1);
        REQUIRE(c.off(*a));
        CHECK(alarm_event.listeners() == 1); // b still wants it
        REQUIRE(c.off(*b));
        CHECK(eventually([] { return alarm_event.listeners() == 0; }));
        REQUIRE(c.on("itest.s7.alarm", got.fn()));
        CHECK(alarm_event.listeners() == 1);
    }
    CHECK(eventually([] { return alarm_event.listeners() == 0; }));
}

TEST_CASE("stage7: subscribing to a conflicting or invalid name fails", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.invalid", 1);
    running_host<cfg> host{at, k};
    host.start();
    Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer()};
    received got;
    CHECK(c.on("Not An Event", got.fn()).error().code == errc::kInvalidArgument);
    CHECK(c.on("game.ok", Rhp::remote_event_fn{}).error().code == errc::kInvalidArgument);
    CHECK(c.on("game.ok", got.fn()));
}

TEST_CASE("stage7: host on_script_event sees every identity", "[stage7][host]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.host_listener", 1);
    running_host<cfg> host{at, k};
    std::mutex mutex;
    std::vector<std::pair<std::string, std::string>> seen;
    auto sub = host->on_script_event("game.hello", [&](const Rhp::event::script_event& e) {
        const std::scoped_lock lock{mutex};
        seen.emplace_back(e.identity, e.module);
    });
    host.start();
    Rhp::client<cfg> a{at.reversed(), k.as("patch"), k.signer()};
    Rhp::client<cfg> b{at.reversed(), k.as("other"), k.signer()};
    REQUIRE(a.load("tests.s7.greeter", "function hi() rhp.publish('game.hello') end"));
    REQUIRE(a.call("tests.s7.greeter", "hi"));
    REQUIRE(b.exec("rhp.publish('game.hello')"));
    REQUIRE(eventually([&] {
        const std::scoped_lock lock{mutex};
        return seen.size() == 2;
    }));
    const std::scoped_lock lock{mutex};
    CHECK(std::ranges::count(seen, std::pair<std::string, std::string>{"patch", "tests.s7.greeter"}) == 1);
    CHECK(std::ranges::count(seen, std::pair<std::string, std::string>{"other", "scratch"}) == 1);
}

TEST_CASE("stage7: handler failures are published as host events and output lines", "[stage7][host]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.failures", 1);
    running_host<cfg> host{at, k};
    std::mutex mutex;
    std::vector<Rhp::event::handler_failed> failures;
    std::vector<std::string> json;
    auto sub = host->on<Rhp::event::handler_failed>([&](const Rhp::event::handler_failed& e) {
        const std::scoped_lock lock{mutex};
        failures.push_back(e);
    });
    auto audit = host->on_any([&](const Rhp::event::any& e) {
        if (std::holds_alternative<Rhp::event::handler_failed>(e)) {
            const std::scoped_lock lock{mutex};
            json.push_back(Rhp::event::to_json(e));
        }
    });
    host.start();
    std::mutex lines_mutex;
    std::vector<std::string> lines;
    Rhp::client_options options;
    options.on_output = [&](std::uint64_t, std::string_view line) {
        const std::scoped_lock lock{lines_mutex};
        lines.emplace_back(line);
    };
    Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer(), options};
    REQUIRE(c.load("tests.s7.flaky", "rhp.after(0, function() error('flaky timer') end)"));
    REQUIRE(eventually([&] {
        const std::scoped_lock lock{mutex};
        return !failures.empty();
    }));
    {
        const std::scoped_lock lock{mutex};
        CHECK(failures[0].identity == "patch");
        CHECK(failures[0].module == "tests.s7.flaky");
        CHECK(failures[0].kind == "timer");
        CHECK(failures[0].action == "report");
        CHECK(failures[0].outcome.message.find("flaky timer") != std::string::npos);
        REQUIRE(json.size() == 1);
        CHECK(json[0].starts_with(R"({"event":"handler_failed")"));
    }
    CHECK(eventually([&] {
        const std::scoped_lock lock{lines_mutex};
        return std::ranges::any_of(lines, [](const std::string& l) { return l.starts_with("[handler failed] tests.s7.flaky"); });
    }));
    CHECK(c.status("tests.s7.flaky")->state == "active");
}

TEST_CASE("stage7: a spawned task keeps running after its request was answered", "[stage7][tasks]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.task", 1);
    running_host<cfg> host{at, k};
    host.start();
    Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer()};
    received got;
    REQUIRE(c.on("game.progress", got.fn()));
    const auto answered = c.exec("rhp.spawn(function() for i = 1, 3 do rhp.publish('game.progress', i) rhp.next_frame() end end) return 'started'");
    REQUIRE(answered);
    CHECK(answered->at(0) == value{"started"});
    REQUIRE(eventually([&] { return got.size() == 3; }));
}

TEST_CASE("stage7: tasks are cancelled when the identity's last session ends", "[stage7][tasks]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.task_end", 1);
    running_host<cfg> host{at, k};
    host.start();
    g_ticks = 0;
    {
        Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer()};
        REQUIRE(c.exec("rhp.spawn(function() while true do s7.ticks = s7.ticks + 1 rhp.next_frame() end end)"));
        REQUIRE(eventually([] { return g_ticks > 3; }));
    }
    REQUIRE(eventually([&] { return host->identities() == 0; }));
    const int after = g_ticks;
    std::this_thread::sleep_for(30ms);
    CHECK(g_ticks == after);
}

TEST_CASE("stage7: a pinned module's task survives its session", "[stage7][tasks]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.pinned_task", 1);
    running_host<cfg> host{at, k};
    host.start();
    g_ticks = 0;
    {
        Rhp::client<cfg> c{at.reversed(), k.as("admin"), k.signer()};
        const auto mod = c.load("tests.s7.ticker", "rhp.spawn(function() while true do s7.ticks = s7.ticks + 1 rhp.next_frame() end end)");
        REQUIRE(mod);
        REQUIRE(c.pin(*mod));
    }
    const int before = g_ticks;
    CHECK(eventually([&] { return g_ticks > before + 5; }));
    Rhp::client<cfg> back{at.reversed(), k.as("admin"), k.signer()};
    REQUIRE(back.revert_all());
}

TEST_CASE("stage7: an event flood is capped per session and reported as dropped", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.flood", 1);
    Rhp::host_options options;
    options.remote_events_per_pump = 4;
    running_host<cfg> host{at, k, options};
    host.start();
    Rhp::client<cfg> c{at.reversed(), k.as("patch"), k.signer()};
    received got;
    REQUIRE(c.on("game.flood", got.fn()));
    REQUIRE(c.exec("for i = 1, 10 do rhp.publish('game.flood', i) end"));
    REQUIRE(eventually([&] { return got.size() == 4; }));
    REQUIRE(c.exec("rhp.publish('game.flood', 99)"));
    REQUIRE(eventually([&] { return got.size() == 5; }));
    const auto items = got.copy();
    CHECK(items[3].args == Rhp::value_list{value{4}});
    CHECK(items[4].args == Rhp::value_list{value{99}});
    CHECK(items[4].dropped == 6);
}

TEST_CASE("stage7: a reverse-mode client subscribes again for the next host", "[stage7][events]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s7.reverse", 1);
    Rhp::client_options brief;
    brief.connect_timeout = 2s;
    Rhp::client<fast_redial_cfg> c{at, k.as("patch"), k.signer(), brief};
    REQUIRE(c.port());
    received got;
    {
        running_host<fast_redial_cfg> first{at.reversed(), k};
        first.start();
        REQUIRE(c.on("game.ping", got.fn()));
        REQUIRE(c.exec("rhp.publish('game.ping', 1)"));
        REQUIRE(eventually([&] { return got.size() == 1; }));
    }
    running_host<fast_redial_cfg> second{at.reversed(), k};
    second.start();
    REQUIRE(eventually([&] {
        auto r = c.exec("rhp.publish('game.ping', 2)");
        return r.has_value() && eventually([&] { return got.size() >= 2; }, 200ms);
    }));
    CHECK(got.copy().back().args == Rhp::value_list{value{2}});
}
