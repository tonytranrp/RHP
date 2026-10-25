// Stage 11 over the wire: tunables, the profiler and the debugger of a client's own sandbox.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/script/detail/var_layers.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace stage11_fixtures {

inline double g_gravity = 9.8;

using test_lib = Rhp::lib<"s11">::var<"gravity", &g_gravity, Rhp::range<0.0, 50.0>, Rhp::unit<"m/s2">, Rhp::doc<"downward pull">>;

using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
using small_frames_cfg = cfg::limits<Rhp::limits{.max_frame = 64u * 1024u}>; // profile replies get truncated

struct keys {
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::key observe = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"patch", patch, Rhp::role::kPatch}, {"watcher", observe, Rhp::role::kObserve}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
};

template <class Cfg>
class basic_running_host {
public:
    basic_running_host(Rhp::endpoint ep, const keys& k) : host_(std::move(ep), k.ring(), k.trusted()) {
        REQUIRE(host_.template install<test_lib>());
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~basic_running_host() {
        pump_.request_stop();
        if (pump_.joinable()) {
            pump_.join();
        }
    }

    basic_running_host(const basic_running_host&) = delete;
    basic_running_host& operator=(const basic_running_host&) = delete;

    [[nodiscard]] Rhp::host<Cfg>& get() noexcept { return host_; }

private:
    Rhp::host<Cfg> host_;
    std::jthread pump_;
};

using running_host = basic_running_host<cfg>;

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

Rhp::wire::debug_request action(std::string name, std::uint64_t request = 0) {
    Rhp::wire::debug_request r;
    r.action = std::move(name);
    r.request = request;
    return r;
}

} // namespace stage11_fixtures

using namespace stage11_fixtures;

TEST_CASE("stage11: a client lists and tunes the host's variables", "[stage11][tunables]") {
    g_gravity = 9.8;
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.tune", 1);
    running_host host{at, k};
    std::optional<Rhp::client<cfg>> tuner;
    tuner.emplace(at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer());
    Rhp::client<cfg>& c = *tuner;
    const auto list = c.tunables();
    REQUIRE(list.has_value());
    REQUIRE(list->size() == 1);
    const auto& g = list->front();
    CHECK(g.path == "s11.gravity");
    CHECK(g.type == "number");
    CHECK(g.current == value{9.8});
    CHECK(g.writable);
    CHECK(g.min == 0.0);
    CHECK(g.max == 50.0);
    CHECK(g.unit == "m/s2");
    CHECK(g.doc == "downward pull");
    REQUIRE(c.tune("s11.gravity", value{1.6}));
    CHECK(g_gravity == 1.6);
    CHECK(c.tune("s11.gravity", value{60.0}).error().code == errc::kOutOfRange);
    CHECK(c.tunables("nope").error().code == errc::kNotFound);
    tuner.reset(); // the identity's last session ends: what it tuned is undone like any exec
    // Read under the variable's lock: the host's pump thread restores it.
    CHECK(eventually([] { return Rhp::script::detail::var_layers<&g_gravity>::read() == 9.8; }));

    Rhp::client<cfg> watcher{at.reversed(), Rhp::security::psk_identity{"watcher", k.observe}, k.signer()};
    REQUIRE(watcher.tunables());
    CHECK_FALSE(watcher.tunables()->front().writable);
    CHECK(watcher.tune("s11.gravity", value{2.0}).error().code == errc::kForbidden);
    CHECK(watcher.debug(action("paused")).error().code == errc::kForbidden);
}

TEST_CASE("stage11: a client profiles its scripts", "[stage11][profile]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.profile", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    const auto started = c.profile("start", 200);
    REQUIRE(started.has_value());
    CHECK(started->running);
    CHECK(c.profile("start").error().code == errc::kAlreadyLoaded);
    REQUIRE(c.load("s11.work", "function spin()\n  local s = 0\n  for i = 1, 50000 do s = s + i end\n  return s\nend"));
    REQUIRE(c.call("s11.work", "spin"));
    const auto read = c.profile("read");
    REQUIRE(read.has_value());
    CHECK(read->running);
    const auto stopped = c.profile("stop");
    REQUIRE(stopped.has_value());
    CHECK_FALSE(stopped->running);
    CHECK(stopped->samples > 50);
    REQUIRE_FALSE(stopped->stacks.empty());
    CHECK(stopped->stacks.front().stack.find("spin (s11.work:1)") != std::string::npos);
    CHECK(c.profile("bogus").error().code == errc::kInvalidArgument);
}

TEST_CASE("stage11: a client debugs a script that pauses at a breakpoint", "[stage11][debug]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.debug", 1);
    running_host host{at, k};
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    std::mutex mutex;
    std::vector<value> events;
    REQUIRE(c.on("rhp.debug", [&](const Rhp::remote_event& e) {
        const std::scoped_lock lock{mutex};
        if (!e.args.empty()) {
            events.push_back(e.args.front());
        }
    }));
    REQUIRE(c.load("s11.dbg", "function add(a, b)\n  local sum = a + b\n  return sum\nend"));
    Rhp::wire::debug_request brk = action("break");
    brk.source = "s11.dbg";
    brk.lines = {3};
    const auto set = c.debug(brk);
    REQUIRE(set.has_value());
    CHECK(set->lines == std::vector<std::uint32_t>{3});

    auto call = c.async().call("s11.dbg", "add", 2, 5);
    REQUIRE(eventually([&] {
        const std::scoped_lock lock{mutex};
        return !events.empty();
    }));
    const auto paused = c.debug(action("paused"));
    REQUIRE(paused.has_value());
    REQUIRE(paused->paused.size() == 1);
    const std::uint64_t req = paused->paused[0].request;
    CHECK(paused->paused[0].line == 3);
    CHECK(paused->paused[0].reason == "breakpoint");
    const auto stack = c.debug(action("stack", req));
    REQUIRE(stack.has_value());
    REQUIRE_FALSE(stack->frames.empty());
    CHECK(stack->frames.front().name == "add");
    Rhp::wire::debug_request locals = action("variables", req);
    const auto vars = c.debug(locals);
    REQUIRE(vars.has_value());
    bool saw_sum = false;
    for (const auto& v : vars->variables) {
        saw_sum = saw_sum || (v.name == "sum" && v.text == "7");
    }
    CHECK(saw_sum);
    Rhp::wire::debug_request eval = action("evaluate", req);
    eval.expression = "a";
    const auto a = c.debug(eval);
    REQUIRE(a.has_value());
    REQUIRE(a->variables.size() == 1);
    CHECK(a->variables.front().text == "2");

    REQUIRE(c.debug(action("continue", req)));
    const auto result = std::move(call).get();
    REQUIRE(result.has_value());
    CHECK(*result == Rhp::value_list{value{7}});
    CHECK(c.debug(action("nonsense")).error().code == errc::kInvalidArgument);
}

TEST_CASE("stage11: a debugging client that goes away lets paused scripts run on", "[stage11][debug]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.leave", 1);
    running_host host{at, k};
    Rhp::client<cfg> runner{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    REQUIRE(runner.load("s11.leave", "function go()\n  local x = 1\n  return x + 1\nend"));
    std::optional<Rhp::client<cfg>> debugger;
    debugger.emplace(at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer());
    Rhp::wire::debug_request brk = action("break");
    brk.source = "s11.leave";
    brk.lines = {2};
    REQUIRE(debugger->debug(brk));
    auto call = runner.async().call("s11.leave", "go");
    REQUIRE(eventually([&] {
        const auto p = debugger->debug(action("paused"));
        return p.has_value() && p->paused.size() == 1;
    }));
    debugger.reset(); // its session ends: breakpoints go, the paused call runs on
    const auto result = std::move(call).get();
    REQUIRE(result.has_value());
    CHECK(*result == Rhp::value_list{value{2}});
}

TEST_CASE("stage11: breakpoints stay while another session still debugs", "[stage11][debug]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.two", 1);
    running_host host{at, k};
    Rhp::client<cfg> runner{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    REQUIRE(runner.load("s11.two", "function go()\n  local x = 1\n  return x + 1\nend"));
    std::optional<Rhp::client<cfg>> first;
    std::optional<Rhp::client<cfg>> second;
    first.emplace(at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer());
    second.emplace(at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer());
    Rhp::wire::debug_request brk = action("break");
    brk.source = "s11.two";
    brk.lines = {2};
    REQUIRE(first->debug(brk));
    Rhp::wire::debug_request other = action("break");
    other.source = "s11.elsewhere";
    other.lines = {1};
    REQUIRE(second->debug(other)); // the second session debugs too
    first.reset(); // one of two debugging sessions ends: the breakpoint stays
    auto call = runner.async().call("s11.two", "go");
    REQUIRE(eventually([&] {
        const auto p = second->debug(action("paused"));
        return p.has_value() && p->paused.size() == 1;
    }));
    CHECK_FALSE(call.wait_for(50ms));
    second.reset(); // the last one ends: the paused call runs on
    const auto result = std::move(call).get();
    REQUIRE(result.has_value());
    CHECK(*result == Rhp::value_list{value{2}});
}

TEST_CASE("stage11: debugger actions that change scripts are audited", "[stage11][debug]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.audit", 1);
    running_host host{at, k};
    std::mutex mutex;
    std::vector<std::string> ops;
    auto sub = host.get().on<Rhp::event::script_executed>([&](const Rhp::event::script_executed& e) {
        const std::scoped_lock lock{mutex};
        ops.push_back(e.op);
    });
    const auto count = [&](std::string_view op) {
        const std::scoped_lock lock{mutex};
        return std::ranges::count(ops, op);
    };
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    REQUIRE(c.debug(action("paused")));
    REQUIRE(c.debug(action("stack", 12345)).error().code == errc::kNotFound);
    REQUIRE(c.tunables());
    REQUIRE(c.profile("read"));
    REQUIRE(c.exec("return 1")); // an audited op, to know the host has reported everything before it
    REQUIRE(eventually([&] { return count("exec") == 1; }));
    CHECK(count("debug") == 0); // reading isn't audited
    Rhp::wire::debug_request brk = action("break");
    brk.source = "s11.audited";
    brk.lines = {1};
    REQUIRE(c.debug(brk));
    REQUIRE(c.debug(action("reset")));
    REQUIRE(eventually([&] { return count("debug") == 2; }));
    REQUIRE(c.tune("s11.gravity", value{9.8}));
    CHECK(eventually([&] { return count("tune") == 1; }));
}

TEST_CASE("stage11: a profile too big for one reply is truncated", "[stage11][profile]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.s11.trunc", 1);
    basic_running_host<small_frames_cfg> host{at, k};
    Rhp::client<cfg> c{at.reversed(), Rhp::security::psk_identity{"patch", k.patch}, k.signer()};
    // 400 functions on lines of their own: their distinct stacks need more than a quarter of 64 KiB.
    std::string source = "fns = {}\n";
    for (int i = 0; i < 400; ++i) {
        source += "fns[#fns + 1] = function() local s = 0 for i = 1, 3000 do s = s + i end return s end\n";
    }
    source += "function all() for _, f in ipairs(fns) do f() end end\n";
    REQUIRE(c.load("s11.trunc", source));
    REQUIRE(c.profile("start", 100));
    REQUIRE(c.call("s11.trunc", "all"));
    const auto report = c.profile("stop");
    REQUIRE(report.has_value());
    CHECK(report->truncated > 0);
    CHECK_FALSE(report->stacks.empty());
    std::size_t bytes = 0;
    for (const auto& st : report->stacks) {
        bytes += st.stack.size() + 16;
    }
    CHECK(bytes <= 16u * 1024u);
    CHECK(report->stacks.size() + report->truncated >= 400);
}
