#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/eventually.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/errors_mode.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/exec/io_runner.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/session/session.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/messages.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace host_client_fixtures {

int g_value = 0;
int g_bumps = 0;

int bump(int by) {
    g_bumps += by;
    return by;
}

void unbump(int by) {
    g_bumps -= by;
}

using test_lib = Rhp::lib<"itest">           //
    ::var<"value", &g_value>                 //
    ::fn<"bump", &bump, Rhp::undo<&unbump>>; //

using loopback_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;

int one() {
    return 1;
}

// Libraries installed late, to test which thread may install them.
using late_lib_a = Rhp::lib<"hclatea">::fn<"one", &one>;
using late_lib_b = Rhp::lib<"hclateb">::fn<"one", &one>;
using late_lib_c = Rhp::lib<"hclatec">::fn<"one", &one>;

// A stderr_logger that starts silent; a test changes its level while the host runs.
struct quiet_stderr_logger : Rhp::core::stderr_logger {
    quiet_stderr_logger() noexcept : stderr_logger{Rhp::log_level::kOff} {}
};
using logged_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<quiet_stderr_logger>;

// A logger whose write() throws while a test arms it.
std::atomic<bool> g_logger_throws{false};
struct throwing_logger {
    [[nodiscard]] static bool enabled(Rhp::log_level) noexcept { return true; }
    static void write(Rhp::log_level, std::string_view) {
        if (g_logger_throws.load()) {
            throw std::runtime_error{"the log is full"};
        }
    }
};
using throwing_log_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<throwing_logger>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::key observe = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin}, {"patch", patch, Rhp::role::kPatch}, {"observe", observe, Rhp::role::kObserve}};
    }
    [[nodiscard]] Rhp::security::psk_identity as_admin() const { return {"admin", admin}; }
    [[nodiscard]] Rhp::security::psk_identity as_patch() const { return {"patch", patch}; }
    [[nodiscard]] Rhp::security::psk_identity as_observe() const { return {"observe", observe}; }
    // Every script is signed by one developer key the hosts trust.
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key signer() const { return {"dev", developer}; }
};

// A host whose pump runs on its own thread (the "game thread"), started after installing libs.
template <class Cfg>
class running_host {
public:
    running_host(Rhp::endpoint ep, const keys& k, Rhp::host_options options = {}) : host_(std::move(ep), k.ring(), k.trusted(), options) {
        if constexpr (std::is_same_v<typename Cfg::errors_t, Rhp::errors::throwing>) {
            host_.template install<test_lib>();
        } else {
            REQUIRE(host_.template install<test_lib>());
        }
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~running_host() {
        pump_.request_stop();
        pump_.join();
    }

    running_host(const running_host&) = delete;
    running_host& operator=(const running_host&) = delete;

    Rhp::host<Cfg>& operator*() { return host_; }
    Rhp::host<Cfg>* operator->() { return &host_; }

    // The address a client dials.
    [[nodiscard]] Rhp::endpoint dial_at(const Rhp::endpoint& listen_at) {
        std::uint16_t port = 0;
        if constexpr (std::is_same_v<typename Cfg::errors_t, Rhp::errors::throwing>) {
            port = host_.port();
        } else {
            auto p = host_.port();
            REQUIRE(p);
            port = *p;
        }
        return listen_at.reversed().with_port(port == 0 ? listen_at.port : port);
    }

private:
    Rhp::host<Cfg> host_;
    std::jthread pump_;
};

using rhp_test::eventually;

// Collects output and emits (called on the client's network thread).
struct inbox {
    std::mutex mutex;
    std::vector<std::pair<std::uint64_t, std::string>> lines;
    std::vector<value> emitted;

    Rhp::client_options options() {
        Rhp::client_options o;
        o.on_output = [this](std::uint64_t req, std::string_view line) {
            const std::scoped_lock lock{mutex};
            lines.emplace_back(req, std::string{line});
        };
        o.on_emit = [this](std::uint64_t, Rhp::module_id, const value& v) {
            const std::scoped_lock lock{mutex};
            emitted.push_back(v);
        };
        return o;
    }

    bool has_line(std::string_view text) {
        const std::scoped_lock lock{mutex};
        for (const auto& [req, line] : lines) {
            if (line == text) {
                return true;
            }
        }
        return false;
    }
};

} // namespace host_client_fixtures

using namespace host_client_fixtures;

TEST_CASE("host+client: exec returns values and errors", "[integration][exec]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.exec", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.connect());
    CHECK(c.info().identity == "patch");
    CHECK(c.info().granted == Rhp::role::kPatch);

    auto values = c.exec("return 1, 'two', {3, x = true}, nil");
    REQUIRE(values);
    REQUIRE(values->size() == 4);
    CHECK((*values)[0] == value{1});
    CHECK((*values)[1] == value{"two"});
    CHECK((*values)[2].is_map());
    CHECK((*values)[3].is_nil());
    CHECK(c.exec<int>("return 6 * 7") == 42);
    CHECK(c.exec<std::string>("return 'x' .. 1") == std::string{"x1"});
    CHECK(c.exec("return").value().empty());

    auto syntax = c.exec("return +");
    REQUIRE_FALSE(syntax);
    CHECK(syntax.error().code == errc::kCompile);
    auto runtime = c.exec("error('boom')");
    REQUIRE_FALSE(runtime);
    CHECK(runtime.error().code == errc::kRuntime);
    CHECK(runtime.error().message.find("boom") != std::string::npos);

    // The session survives errors, and the scratch module keeps earlier effects.
    REQUIRE(c.exec("kept = 5"));
    CHECK(c.exec<int>("return kept") == 5);
}

TEST_CASE("host+client: roles gate requests and bindings", "[integration][roles]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.roles", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> observer{host.dial_at(at), k.as_observe(), k.signer()};
    Rhp::client<loopback_cfg> patcher{host.dial_at(at), k.as_patch(), k.signer()};
    Rhp::client<loopback_cfg> admin{host.dial_at(at), k.as_admin(), k.signer()};

    CHECK(observer.exec<int>("return itest.value") == 0);
    CHECK(observer.exec("itest.value = 1").error().code == errc::kForbidden);
    CHECK(observer.exec("return itest.bump(1)").error().code == errc::kForbidden);
    CHECK(observer.load("itest.mod", "return {}").error().code == errc::kForbidden);
    CHECK(observer.checkpoint("x").error().code == errc::kForbidden);
    CHECK(observer.describe()); // observe may introspect
    CHECK(observer.list());

    CHECK(patcher.exec("itest.value = 3"));
    CHECK(patcher.revert_all().error().code == errc::kForbidden);
    CHECK(observer.exec<int>("return itest.value") == 3);

    // The admin's panic button reverts every identity.
    auto all = admin.revert_all();
    REQUIRE(all);
    CHECK(all->undone >= 1);
    CHECK(observer.exec<int>("return itest.value") == 0);

    // Admin gets the full standard library, others don't.
    CHECK(admin.exec<bool>("return io ~= nil") == true);
    CHECK(patcher.exec<bool>("return io ~= nil") == false);
}

TEST_CASE("host+client: the module lifecycle over the wire", "[integration][lifecycle]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.lifecycle", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};

    auto mod = c.load("itest.counter", "local M = {} itest.value = 10 function M.add(n) itest.value = itest.value + n return itest.value end return M");
    REQUIRE(mod);
    CHECK(c.call(*mod, "add", 5).value().front() == value{15});
    CHECK(c.call("itest.counter", "add", 1).value().front() == value{16}); // by name
    CHECK(c.call(*mod, "missing").error().code == errc::kNotFound);
    CHECK(c.call("itest.nobody", "add", 1).error().code == errc::kNotFound);

    auto status = c.status(*mod);
    REQUIRE(status);
    CHECK(status->name == "itest.counter");
    CHECK(status->state == "active");
    CHECK(status->revision == Rhp::revision_id{1});

    auto rev2 = c.reload(*mod, "local M = {} itest.value = 20 function M.add(n) return -n end return M");
    REQUIRE(rev2);
    CHECK(*rev2 == Rhp::revision_id{2});
    CHECK(c.call(*mod, "add", 1).value().front() == value{-1});
    CHECK(c.exec<int>("return itest.value") == 20);

    auto rev3 = c.rollback(*mod, 1);
    REQUIRE(rev3);
    CHECK(*rev3 == Rhp::revision_id{3});
    CHECK(c.exec<int>("return itest.value") == 10);

    REQUIRE(c.checkpoint("before_bump"));
    REQUIRE(c.exec("itest.bump(4)"));
    auto back = c.revert_to("before_bump");
    REQUIRE(back);
    CHECK(back->undone == 1);

    auto list = c.list();
    REQUIRE(list);
    CHECK(list->size() == 2); // scratch + itest.counter

    auto reverted = c.revert(*mod);
    REQUIRE(reverted);
    CHECK(reverted->undone >= 1);
    CHECK(c.status(*mod)->state == "reverted");
    auto unloaded = c.unload(*mod);
    REQUIRE(unloaded);
    CHECK(c.status(*mod).error().code == errc::kNotFound);

    auto stubs = c.describe();
    REQUIRE(stubs);
    CHECK(stubs->find("itest") != std::string::npos);
}

TEST_CASE("host+client: require; force unload; faults", "[integration][lifecycle]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.require", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    auto base = c.load("itest.base", "return {n = 7}");
    REQUIRE(base);
    auto user = c.load("itest.user", "local b = require('itest.base') return {get = function() return b.n end}");
    REQUIRE(user);
    CHECK(c.call(*user, "get").value().front() == value{7});
    CHECK(c.unload(*base).error().code == errc::kHasDependents);
    CHECK(c.unload(*base, true));
    CHECK(c.call(*user, "get").error().code == errc::kUnloaded);

    auto faulty = c.load("itest.faulty", "error('nope')");
    REQUIRE_FALSE(faulty);
    CHECK(faulty.error().code == errc::kRuntime);
}

TEST_CASE("host+client: print and rhp.emit reach the requester", "[integration][output]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.output", 1);
    running_host<loopback_cfg> host{at, k};
    inbox seen;
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer(), seen.options()};
    REQUIRE(c.exec("print('one', 2) rhp.emit({kind = 'pos', x = 1}) return 0"));
    REQUIRE(eventually([&] { return seen.has_line("one\t2"); }));
    REQUIRE(eventually([&] {
        const std::scoped_lock lock{seen.mutex};
        return seen.emitted.size() == 1;
    }));
    {
        const std::scoped_lock lock{seen.mutex};
        CHECK(seen.lines.front().first != 0); // tied to the request
        CHECK(seen.emitted.front().find("kind") != nullptr);
    }

    // A timer prints later, outside any request: every session of the identity hears it.
    inbox other;
    Rhp::client<loopback_cfg> second{host.dial_at(at), k.as_patch(), k.signer(), other.options()};
    REQUIRE(second.connect());
    REQUIRE(c.exec("rhp.timer(10, function() print('tick') end)"));
    CHECK(eventually([&] { return seen.has_line("tick") && other.has_line("tick"); }));
}

TEST_CASE("host+client: a request that suspends is answered when it finishes", "[integration][scheduler]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.wait", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    CHECK(c.exec<int>("local f = rhp.frame() rhp.wait(3) return rhp.frame() - f") == 3);
    auto mod = c.load("itest.slow", "rhp.wait(2) return {ready = true}");
    REQUIRE(mod);
    CHECK(c.status(*mod)->state == "active");
    CHECK(c.call(*mod, "missing").error().code == errc::kNotFound);
    auto failing = c.exec("rhp.wait(1) error('late')");
    REQUIRE_FALSE(failing);
    CHECK(failing.error().message.find("late") != std::string::npos);
}

TEST_CASE("host+client: cancel stops a running loop and a suspended wait", "[integration][cancel]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.cancel", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.connect());

    SECTION("an infinite loop holding the pump thread") {
        std::optional<Rhp::result<Rhp::value_list>> r;
        std::jthread caller{[&] { r = c.exec("while true do end"); }};
        std::this_thread::sleep_for(100ms);
        c.cancel();
        caller.join();
        REQUIRE(r.has_value());
        REQUIRE_FALSE(*r);
        CHECK(r->error().code == errc::kCancelled);
    }
    SECTION("a request suspended in rhp.sleep") {
        std::optional<Rhp::result<Rhp::value_list>> r;
        std::jthread caller{[&] { r = c.exec("rhp.sleep(600000) return 1"); }};
        std::this_thread::sleep_for(100ms);
        c.cancel();
        caller.join();
        REQUIRE(r.has_value());
        REQUIRE_FALSE(*r);
        CHECK(r->error().code == errc::kCancelled);
    }
    // The host is still fine afterwards.
    CHECK(c.exec<int>("return 1") == 1);
}

TEST_CASE("host+client: disconnect reverts the identity; shared sessions keep it", "[integration][disconnect]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.disconnect", 1);
    {
        running_host<loopback_cfg> host{at, k};
        Rhp::client<loopback_cfg> watcher{host.dial_at(at), k.as_observe(), k.signer()};
        {
            auto first = std::make_unique<Rhp::client<loopback_cfg>>(host.dial_at(at), k.as_patch(), k.signer());
            Rhp::client<loopback_cfg> second{host.dial_at(at), k.as_patch(), k.signer()};
            REQUIRE(first->exec("itest.value = 99 shared = 'yes'"));
            REQUIRE(second.connect());
            REQUIRE(watcher.connect());
            CHECK(eventually([&] { return host->identities() == 2; }));             // observe + patch
            CHECK(second.exec<std::string>("return shared") == std::string{"yes"}); // one sandbox per identity
            first.reset();
            // patch still has a session: nothing reverted.
            std::this_thread::sleep_for(50ms);
            CHECK(watcher.exec<int>("return itest.value") == 99);
        }
        // patch's last session is gone: everything it did is reverted.
        REQUIRE(eventually([&] { return host->identities() == 1; }));
        CHECK(watcher.exec<int>("return itest.value") == 0);
    }
    CHECK(g_value == 0);
}

TEST_CASE("host+client: a host that goes away fails the client's calls", "[integration][disconnect]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.hostgone", 1);
    auto host = std::make_unique<running_host<loopback_cfg>>(at, k);
    Rhp::client<loopback_cfg> c{host->dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.exec("return 1"));
    host.reset();
    auto r = c.exec("return 1");
    REQUIRE_FALSE(r);
    CHECK(r.error().code == errc::kTransport);
    CHECK_FALSE(c.connected());
}

TEST_CASE("host+client: connection failures", "[integration][connect]") {
    keys k;
    Rhp::client<loopback_cfg> nobody{Rhp::endpoint::dial("itest.nobody", 1), k.as_patch(), k.signer()};
    CHECK(nobody.connect().error().code == errc::kNotFound);

    const auto at = Rhp::endpoint::listen("itest.connect", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> wrong{host.dial_at(at), Rhp::security::psk_identity{"admin", k.patch}};
    CHECK(wrong.exec("return 1").error().code == errc::kAuth);
    Rhp::client<loopback_cfg> stranger{host.dial_at(at), Rhp::security::psk_identity{"stranger", k.patch}};
    CHECK(stranger.connect().error().code == errc::kAuth);
    CHECK(host->sessions() == 0);

    // Reverse mode: a client listening on a channel the host already holds can't.
    Rhp::client<loopback_cfg> listening{Rhp::endpoint::listen("itest.connect", 1), k.as_patch(), k.signer()};
    CHECK(listening.connect().error().code == errc::kAlreadyLoaded);
}

TEST_CASE("host: listen failures are reported by port()", "[integration][host]") {
    keys k;
    Rhp::host<loopback_cfg> first{Rhp::endpoint::listen("itest.port", 1), k.ring()};
    CHECK(first.port());
    Rhp::host<loopback_cfg> second{Rhp::endpoint::listen("itest.port", 1), k.ring()};
    CHECK(second.port().error().code == errc::kAlreadyLoaded);
    Rhp::host<loopback_cfg> dialing{Rhp::endpoint::dial("itest.port_reverse", 1), k.ring()}; // reverse mode: dials, no port
    CHECK(dialing.port() == 0);
    CHECK(first.install<test_lib>());
    CHECK(first.install<test_lib>().error().code == errc::kAlreadyLoaded);
}

TEST_CASE("host+client: a result larger than a frame is an error and not a dead session", "[integration][limits]") {
    using small_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>::limits<Rhp::limits{.max_frame = 16 * 1024}>;
    keys k;
    const auto at = Rhp::endpoint::listen("itest.big", 1);
    running_host<small_cfg> host{at, k};
    Rhp::client<small_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    auto big = c.exec("return string.rep('x', 100000)");
    REQUIRE_FALSE(big);
    CHECK(big.error().code == errc::kLimitExceeded);
    CHECK(c.exec<int>("return 2") == 2);
    auto big_request = c.exec(std::string(20'000, ' ') + "return 1");
    REQUIRE_FALSE(big_request);
    CHECK(big_request.error().code == errc::kLimitExceeded);
    CHECK(c.exec<int>("return 3") == 3);
}

TEST_CASE("host+client: throwing error mode", "[integration][errors]") {
    using throwing_cfg = loopback_cfg::errors<Rhp::errors::throwing>;
    keys k;
    const auto at = Rhp::endpoint::listen("itest.throwing", 1);
    running_host<throwing_cfg> host{at, k};
    Rhp::client<throwing_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    const int answer = c.exec<int>("return 41 + 1");
    CHECK(answer == 42);
    const Rhp::value_list list = c.exec("return 1, 2");
    CHECK(list.size() == 2);
    CHECK_THROWS_AS(c.exec("error('x')"), Rhp::exception);
    try {
        c.load("Bad Name", "return {}");
        FAIL("expected an exception");
    } catch (const Rhp::exception& e) {
        CHECK(e.err().code == errc::kInvalidArgument);
    }
}

TEST_CASE("host+client: zero_threads on both ends", "[integration][threads]") {
    using quiet_cfg = loopback_cfg::io<Rhp::exec::zero_threads>;
    keys k;
    const auto at = Rhp::endpoint::listen("itest.zero", 1);
    running_host<quiet_cfg> host{at, k};                                  // pump() polls the network
    Rhp::client<quiet_cfg> c{host.dial_at(at), k.as_patch(), k.signer()}; // calls run the network while waiting
    CHECK(c.exec<int>("return 7") == 7);
    CHECK(c.exec<int>("rhp.wait(2) return 8") == 8);
}

TEST_CASE("host+client: over TCP on 127.0.0.1", "[integration][tcp]") {
    keys k;
    const auto at = Rhp::endpoint::listen("127.0.0.1", 0);
    {
        running_host<tcp_cfg> host{at, k};
        const auto dial = host.dial_at(at);
        CHECK(dial.port != 0);
        Rhp::client<tcp_cfg> c{dial, k.as_patch(), k.signer()};
        CHECK(c.exec<int>("return 40 + 2") == 42);
        auto mod = c.load("itest.tcp", "itest.value = 5 return {}");
        REQUIRE(mod);
        CHECK(c.exec<int>("return itest.value") == 5);
        CHECK(c.exec(std::string(500'000, ' ') + "return 1")); // many TCP segments
        CHECK(host->sessions() == 1);
    }
    CHECK(g_value == 0); // the host's end reverted everything
}

TEST_CASE("host: unauthenticated connections are capped", "[integration][host]") {
    using capped_cfg = loopback_cfg::limits<Rhp::limits{.pending_handshakes = 2, .handshake_timeout_ms = 60'000, .first_byte_ms = 60'000}>;
    keys k;
    const auto at = Rhp::endpoint::listen("itest.capped", 1);
    running_host<capped_cfg> host{at, k};
    Rhp::net::io_context io;
    std::vector<std::unique_ptr<Rhp::net::link>> raw;
    std::vector<std::unique_ptr<rhp_test::recorder>> events;
    const auto open = [&] {
        const std::size_t before = raw.size();
        Rhp::net::loopback::dial(io, Rhp::endpoint::dial("itest.capped", 1), [&](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
            REQUIRE(l);
            events.push_back(std::make_unique<rhp_test::recorder>());
            (*l)->start(*events.back());
            raw.push_back(std::move(*l));
        });
        REQUIRE(rhp_test::poll_until({&io}, [&] { return raw.size() == before + 1; }));
        std::this_thread::sleep_for(20ms); // let the host accept in order
    };
    for (int i = 0; i < 3; ++i) {
        open();
    }
    // The third takes the place of the first (the oldest that said nothing); the second waits.
    REQUIRE(rhp_test::poll_until({&io}, [&] { return events[0]->closed; }));
    rhp_test::poll_for({&io}, 50ms);
    CHECK_FALSE(events[1]->closed);
    CHECK_FALSE(events[2]->closed);
    // Connections that have started talking keep their slots: the next one is closed at once.
    raw[1]->send(rhp_test::buffer_of("R"));
    raw[2]->send(rhp_test::buffer_of("R"));
    rhp_test::poll_for({&io}, 50ms);
    open();
    REQUIRE(rhp_test::poll_until({&io}, [&] { return events[3]->closed; }));
    CHECK_FALSE(events[1]->closed);
    // An authenticated client still gets in once one of them leaves.
    raw[1].reset();
    std::this_thread::sleep_for(50ms);
    Rhp::client<capped_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    CHECK(c.exec<int>("return 1") == 1);
}

namespace host_client_fixtures {

// Speaks the session protocol directly (to send one request twice, as a retrying client would).
struct raw_client final : Rhp::session::handler {
    Rhp::net::io_context io;
    std::unique_ptr<Rhp::session::session> s;
    bool ready = false;
    bool closed = false;
    std::vector<Rhp::wire::envelope> replies;
    std::vector<Rhp::wire::op> codes;

    Rhp::security::signing_key key;

    raw_client(const Rhp::endpoint& at, const Rhp::security::psk_identity& who, Rhp::security::signing_key signer) : key(std::move(signer)) {
        Rhp::session::options opts;
        opts.codec = Rhp::wire::codec_ops_for<Rhp::wire::msgpack>;
        Rhp::net::loopback::dial(io, at, [this, opts, who](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
            REQUIRE(l);
            s = std::make_unique<Rhp::session::session>(io, std::move(*l), who.begin(), *this, opts);
            s->start();
        });
        REQUIRE(rhp_test::poll_until({&io}, [this] { return ready; }));
    }

    void on_ready(Rhp::session::session&) override { ready = true; }
    void on_message(Rhp::session::session&, Rhp::wire::op code, value body) override {
        codes.push_back(code);
        replies.push_back(*Rhp::from_value<Rhp::wire::envelope>(body));
    }
    void on_closed(Rhp::session::session&, const Rhp::error&) override { closed = true; }

    void exec(std::uint64_t req, std::uint64_t idem, std::string source) {
        auto signature = key.sign(source);
        REQUIRE(signature);
        const value body = Rhp::to_value(Rhp::wire::exec_request{std::move(source), "exec", std::move(*signature)});
        REQUIRE(s->send(Rhp::wire::op::kExec, Rhp::to_value(Rhp::wire::envelope{req, idem, body})));
    }

    bool wait_replies(std::size_t n) {
        return rhp_test::poll_until({&io}, [this, n] { return replies.size() >= n; });
    }
};

} // namespace host_client_fixtures

TEST_CASE("host: a retried request (same idempotency key) runs once", "[integration][idempotency]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.idem", 1);
    running_host<loopback_cfg> host{at, k};
    raw_client c{host.dial_at(at), k.as_patch(), k.signer()};
    const std::string counter = "counter = (counter or 0) + 1 return counter";
    c.exec(1, 777, counter);
    REQUIRE(c.wait_replies(1));
    c.exec(2, 777, counter); // a retry
    c.exec(3, 778, counter); // a new request
    REQUIRE(c.wait_replies(3));
    CHECK(c.replies[0].req == 1);
    CHECK(c.replies[0].body == value{value::array{value{1}}});
    CHECK(c.replies[1].req == 2);
    CHECK(c.replies[1].body == value{value::array{value{1}}}); // answered from the cache
    CHECK(c.replies[2].req == 3);
    CHECK(c.replies[2].body == value{value::array{value{2}}}); // ran: the counter moved once
}

TEST_CASE("host: a reply too large to cache refuses its retry instead of running twice", "[integration][idempotency]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.idem_big", 1);
    running_host<loopback_cfg> host{at, k, Rhp::host_options{.idempotency_cache = 256, .idempotency_bytes = 1024}};
    raw_client c{host.dial_at(at), k.as_patch(), k.signer()};
    const std::string big = "runs = (runs or 0) + 1 return string.rep('x', 4000)";
    c.exec(1, 900, big);
    REQUIRE(c.wait_replies(1));
    CHECK(c.codes[0] == Rhp::wire::op::kResult);
    c.exec(2, 900, big);
    REQUIRE(c.wait_replies(2));
    CHECK(c.codes[1] == Rhp::wire::op::kError);
    CHECK(Rhp::from_value<Rhp::error>(c.replies[1].body)->code == errc::kLimitExceeded);
    c.exec(3, 901, "return runs");
    REQUIRE(c.wait_replies(3));
    CHECK(c.replies[2].body == value{value::array{value{1}}});
}

TEST_CASE("host+client: acks sent at once with ack_delay_ms 0", "[integration][session]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.ack_now", 1);
    running_host<loopback_cfg> host{at, k, Rhp::host_options{.ack_delay_ms = 0}};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer(), Rhp::client_options{.ack_delay_ms = 0}};
    for (int i = 0; i < 20; ++i) {
        CHECK(c.exec<int>(std::format("return {}", i)) == i);
    }
    CHECK_FALSE(c.info().closed);
}

TEST_CASE("host: a full inbox or outbox loses nothing", "[integration][host]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.rings", 1);
    running_host<loopback_cfg> host{at, k, Rhp::host_options{.inbox_capacity = 2}};
    inbox seen;
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer(), seen.options()};
    // 300 prints and a result go through a 2-slot outbox in one pump().
    auto r = c.exec("for i = 1, 300 do print('line ' .. i) end return 1, 2, 3");
    REQUIRE(r);
    CHECK(*r == Rhp::value_list{value{1}, value{2}, value{3}});
    REQUIRE(eventually([&] { return seen.has_line("line 300"); }));
    {
        const std::scoped_lock lock{seen.mutex};
        REQUIRE(seen.lines.size() == 300);
        for (std::size_t i = 0; i < seen.lines.size(); ++i) {
            CHECK(seen.lines[i].second == "line " + std::to_string(i + 1));
        }
    }
    // Many requests at once through a 2-slot inbox.
    std::vector<std::jthread> callers;
    std::atomic<int> ok{0};
    for (int i = 0; i < 8; ++i) {
        callers.emplace_back([&c, &ok, i] {
            if (c.exec<int>("return " + std::to_string(i)) == i) {
                ++ok;
            }
        });
    }
    callers.clear();
    CHECK(ok.load() == 8);
}

TEST_CASE("host: a request whose session closed before it ran never runs", "[integration][cancel]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.dead_start", 1);
    running_host<loopback_cfg> host{at, k};
    {
        raw_client c{host.dial_at(at), k.as_patch(), k.signer()};
        c.exec(1, 0, "while true do end");
        c.s->close(Rhp::make_error(errc::kCancelled, "gone"));
        rhp_test::poll_for({&c.io}, 20ms); // let the close go out
    }
    // The pump thread is free: a new client is served.
    Rhp::client<loopback_cfg> next{host.dial_at(at), k.as_admin(), k.signer()};
    CHECK(next.exec<int>("return 5") == 5);
    CHECK(eventually([&] { return host->identities() == 1; }));
}

TEST_CASE("host+client: cancel reaches a loop whenever it lands", "[integration][cancel]") {
    keys k;
    const auto at = Rhp::endpoint::listen("itest.cancel_storm", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.connect());
    for (int round = 0; round < 20; ++round) {
        std::atomic<bool> done{false};
        std::optional<Rhp::result<Rhp::value_list>> r;
        std::jthread caller{[&] {
            r = c.exec("while true do end");
            done = true;
        }};
        // Cancel early and keep cancelling: some land before the request starts, some while it runs.
        while (!done) {
            c.cancel();
            std::this_thread::sleep_for(std::chrono::microseconds{100 + 700 * (round % 3)});
        }
        caller.join();
        REQUIRE(r.has_value());
        REQUIRE_FALSE(*r);
        CHECK(r->error().code == errc::kCancelled);
    }
    CHECK(c.exec<int>("return 1") == 1);
}

TEST_CASE("host+client: an idle zero_threads client stays connected while it polls", "[integration][threads]") {
    using fast_cfg = loopback_cfg::io<Rhp::exec::zero_threads>::limits<Rhp::limits{.heartbeat_ms = 30, .heartbeat_misses = 3}>;
    using fast_host_cfg = loopback_cfg::limits<Rhp::limits{.heartbeat_ms = 30, .heartbeat_misses = 3}>;
    keys k;
    const auto at = Rhp::endpoint::listen("itest.zero_idle", 1);
    running_host<fast_host_cfg> host{at, k};
    Rhp::client<fast_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.exec("x = 42"));
    const auto until = std::chrono::steady_clock::now() + 400ms; // > 10 heartbeats
    while (std::chrono::steady_clock::now() < until) {
        c.poll();
        std::this_thread::sleep_for(5ms);
    }
    CHECK(c.exec<int>("return x") == 42);
    CHECK(c.connected());
}

TEST_CASE("host: setup calls from another thread are refused once pump has run", "[integration][host][threads]") {
    using namespace host_client_fixtures;
    keys k;
    Rhp::host<loopback_cfg> host{Rhp::endpoint::listen("hc.pump_rule", 1), k.ring(), k.trusted()};
    REQUIRE(host.install<late_lib_a>());           // before the first pump: from this thread is fine
    std::jthread{[&host] { host.pump(); }}.join(); // pump has now run on another thread
    auto late = host.install<late_lib_b>();
    REQUIRE_FALSE(late);
    CHECK(late.error().code == errc::kInvalidArgument);
    auto sink = host.on_blob("hclate", [](const Rhp::blob_view&) -> Rhp::result<void> { return {}; });
    REQUIRE_FALSE(sink);
    CHECK(sink.error().code == errc::kInvalidArgument);
    Rhp::result<void> from_pump = Rhp::fail(errc::kRuntime);
    std::jthread{[&] {
        host.pump();
        from_pump = host.install<late_lib_b>(); // the thread that pumps may still install
    }}.join();
    CHECK(from_pump);
}

TEST_CASE("host: setup calls before the first pump may come from any thread", "[integration][host][threads]") {
    using namespace host_client_fixtures;
    keys k;
    Rhp::host<loopback_cfg> host{Rhp::endpoint::listen("hc.pump_rule_early", 1), k.ring(), k.trusted()};
    Rhp::result<void> installed = Rhp::fail(errc::kRuntime);
    Rhp::result<void> sink = Rhp::fail(errc::kRuntime);
    std::jthread{[&] {
        installed = host.install<late_lib_c>();
        sink = host.on_blob("hcearly", [](const Rhp::blob_view&) -> Rhp::result<void> { return {}; });
    }}.join();
    CHECK(installed);
    CHECK(sink);
    std::jthread{[&host] { host.pump(); }}.join();
}

TEST_CASE("host: the logger level may change while the network thread logs", "[integration][host][log]") {
    using namespace host_client_fixtures;
    keys k;
    const auto at = Rhp::endpoint::listen("hc.log_level", 1);
    Rhp::host<logged_cfg> host{at, k.ring(), k.trusted()};
    std::atomic<bool> done{false};
    std::jthread flipper{[&] {
        for (int i = 0; !done.load(); ++i) { // critical: nothing logs at that level, so the test stays quiet
            host.logger().set_min_level(i % 2 == 0 ? Rhp::log_level::kCritical : Rhp::log_level::kOff);
        }
    }};
    for (int i = 0; i < 20; ++i) {
        Rhp::client<loopback_cfg> c{at.reversed(), k.as_observe()};
        REQUIRE(c.connect()); // the network thread logs "authenticated" (info), then "ended" when c closes
    }
    done = true;
}

TEST_CASE("host: set_enabled survives a logger that throws", "[integration][host][log]") {
    using namespace host_client_fixtures;
    keys k;
    Rhp::host<throwing_log_cfg> host{Rhp::endpoint::listen("hc.throwing_log", 1), k.ring(), k.trusted()};
    REQUIRE(host.port());
    g_logger_throws = true;
    host.set_enabled(false); // noexcept: the logger's exception must not escape (std::terminate)
    g_logger_throws = false;
    CHECK_FALSE(host.enabled());
    host.set_enabled(true);
    CHECK(host.enabled());
}

TEST_CASE("host+client: a blocking call from the client network thread fails instead of deadlocking", "[integration][client][threads]") {
    keys k;
    const auto at = Rhp::endpoint::listen("hc.block_on_io", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer(), Rhp::client_options{.request_timeout = 2s}};
    REQUIRE(c.connect());
    std::promise<Rhp::result<std::vector<value>>> inner;
    auto outer = inner.get_future();
    c.async().exec("rhp.sleep(20) return 1").then([&](Rhp::result<std::vector<value>>) {
        inner.set_value(c.exec("return 2")); // on the network thread: refused, not a 2 s timeout
    });
    REQUIRE(outer.wait_for(5s) == std::future_status::ready);
    const auto r = outer.get();
    REQUIRE_FALSE(r);
    CHECK(r.error().code == errc::kInvalidArgument);
    CHECK(c.exec("return 3")); // and the client still works from other threads
}

TEST_CASE("host+client: a throwing completion callback does not end the session", "[integration][client]") {
    keys k;
    const auto at = Rhp::endpoint::listen("hc.throwing_then", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.connect());
    std::atomic<bool> ran{false};
    // The sleep keeps the reply out until then() has attached the callback, so the network thread
    // runs it (a result already in runs it on the caller's thread, where the throw would escape then()).
    c.async().exec("rhp.sleep(20) return 1").then([&](Rhp::result<std::vector<value>>) {
        ran = true;
        throw std::runtime_error{"an application bug"};
    });
    REQUIRE(eventually([&] { return ran.load(); }));
    auto after = c.exec("return 3");
    REQUIRE(after);
    CHECK((*after)[0] == value{3});
    CHECK_FALSE(c.info().closed);
}

TEST_CASE("host+client: a client destroyed in its own completion callback shuts down cleanly", "[integration][client][lifetime]") {
    keys k;
    const auto at = Rhp::endpoint::listen("hc.self_destroy", 1);
    running_host<loopback_cfg> host{at, k};
    auto* c = new Rhp::client<loopback_cfg>{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c->connect());
    const auto main_id = std::this_thread::get_id();
    std::atomic<bool> destroyed{false};
    std::atomic<std::thread::id> on{};
    const auto started = std::chrono::steady_clock::now();
    c->async().exec("rhp.sleep(30) return 1").then([c, &destroyed, &on](Rhp::result<std::vector<value>>) {
        on = std::this_thread::get_id();
        delete c; // the network thread: no self-join, no 1 s close wait
        destroyed = true;
    });
    REQUIRE(eventually([&] { return destroyed.load(); }, 5s));
    CHECK(on.load() != main_id);
    CHECK(std::chrono::steady_clock::now() - started < 900ms);
    CHECK(eventually([&] { return host->sessions() == 0; }));
}

TEST_CASE("host+client: a zero_threads client destroyed in a callback run by its poll() shuts down cleanly", "[integration][client][lifetime]") {
    using zero_cfg = loopback_cfg::io<Rhp::exec::zero_threads>;
    keys k;
    const auto at = Rhp::endpoint::listen("hc.self_destroy_zero", 1);
    running_host<loopback_cfg> host{at, k};
    auto* c = new Rhp::client<zero_cfg>{host.dial_at(at), k.as_patch(), k.signer()};
    bool destroyed = false;
    c->async().exec("return 1").then([c, &destroyed](Rhp::result<std::vector<value>>) {
        delete c; // inside c->poll(): the engine outlives the poll that runs this
        destroyed = true;
    });
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (!destroyed && std::chrono::steady_clock::now() < deadline) {
        c->poll();
        std::this_thread::sleep_for(1ms);
    }
    CHECK(destroyed);
    CHECK(eventually([&] { return host->sessions() == 0; }));
}

TEST_CASE("host+client: waiting calls on the client's own network thread report errors instead of deadlocking", "[integration][client][threads]") {
    keys k;
    const auto at = Rhp::endpoint::listen("hc.network_thread_waits", 1);
    running_host<loopback_cfg> host{at, k};
    Rhp::client<loopback_cfg> c{host.dial_at(at), k.as_patch(), k.signer()};
    REQUIRE(c.connect());
    auto slow = c.async().exec<int>("rhp.sleep(20) return 2");
    std::atomic<int> get_code{-1};
    std::atomic<int> on_code{-1};
    std::atomic<int> off_code{-1};
    std::atomic<bool> done{false};
    c.async().exec<int>("return 1").then([&](Rhp::result<int>) {
        // All on the network thread that delivers results: each would wait for itself.
        auto r = std::move(slow).get();
        get_code = r ? 0 : static_cast<int>(r.error().code);
        auto sub = c.on("hc.never", [](const Rhp::remote_event&) {});
        on_code = sub ? 0 : static_cast<int>(sub.error().code);
        auto off = c.off(1);
        off_code = off ? 0 : static_cast<int>(off.error().code);
        done = true;
    });
    REQUIRE(eventually([&] { return done.load(); }));
    CHECK(get_code.load() == static_cast<int>(errc::kInvalidArgument));
    CHECK(on_code.load() == static_cast<int>(errc::kInvalidArgument));
    CHECK(off_code.load() == static_cast<int>(errc::kInvalidArgument));
    CHECK(c.exec<int>("return 3") == 3); // the session is fine
}
