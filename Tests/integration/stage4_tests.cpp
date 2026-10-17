#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/audit/sinks.hpp>
#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/exec/io_runner.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/hash.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/security/signer.hpp>
#include <rhp/session/session.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/messages.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace stage4_fixtures {

int g_level = 0;

using s4_lib = Rhp::lib<"s4">::var<"level", &g_level>;

using loop_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;
// Reverse-mode hosts redial fast in tests.
using fast_redial_cfg = loop_cfg::limits<Rhp::limits{.backoff_min_ms = 5, .backoff_max_ms = 40}>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key admin2 = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::key observe = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();
    Rhp::security::ed25519_secret_key stranger = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin},
                                      {"admin2", admin2, Rhp::role::kAdmin},
                                      {"patch", patch, Rhp::role::kPatch},
                                      {"observe", observe, Rhp::role::kObserve}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key dev() const { return {"dev", developer}; }
    [[nodiscard]] Rhp::security::psk_identity as(std::string_view who) const {
        if (who == "admin") {
            return {"admin", admin};
        }
        if (who == "admin2") {
            return {"admin2", admin2};
        }
        if (who == "patch") {
            return {"patch", patch};
        }
        return {"observe", observe};
    }
};

// A host pumped by its own "game" thread.
template <class Cfg>
class pumped_host {
public:
    template <class... Args>
    explicit pumped_host(Args&&... args) : host_(std::forward<Args>(args)...) {
        (void)host_.template install<s4_lib>();
    }

    void start() {
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~pumped_host() { stop(); }

    void stop() {
        if (pump_.joinable()) {
            pump_.request_stop();
            pump_.join();
        }
    }

    pumped_host(const pumped_host&) = delete;
    pumped_host& operator=(const pumped_host&) = delete;

    Rhp::host<Cfg>& operator*() { return host_; }
    Rhp::host<Cfg>* operator->() { return &host_; }

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

// Events a host reports, kept for the test thread.
template <class E>
struct recorder {
    std::mutex mutex;
    std::vector<E> seen;

    [[nodiscard]] auto handler() {
        return [this](const E& e) {
            const std::scoped_lock lock{mutex};
            seen.push_back(e);
        };
    }
    [[nodiscard]] std::vector<E> snapshot() {
        const std::scoped_lock lock{mutex};
        return seen;
    }
    [[nodiscard]] std::size_t size() {
        const std::scoped_lock lock{mutex};
        return seen.size();
    }
};

// The smallest eager coroutine able to co_await.
struct task {
    struct promise_type {
        task get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() { std::terminate(); }
    };
};

template <class Client>
task sum_over_network(Client& c, std::promise<int>& out) {
    auto a = co_await c.async().template exec<int>("return 20");
    auto b = co_await c.async().template exec<int>("return 22");
    out.set_value(a && b ? *a + *b : -1);
}

} // namespace stage4_fixtures

using namespace stage4_fixtures;

// ---- signing --------------------------------------------------------------------------------------------

TEST_CASE("stage4: scripts must be signed by a trusted developer / except from observe", "[stage4][signing]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.signing", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();

    Rhp::client<loop_cfg> signed_patch{host.dial_at(at), k.as("patch"), k.dev()};
    CHECK(signed_patch.exec<int>("s4.level = 3 return s4.level") == 3);
    auto mod = signed_patch.load("signed.mod", "return {get = function() return 1 end}");
    REQUIRE(mod);
    CHECK(signed_patch.reload(*mod, "return {get = function() return 2 end}"));
    CHECK(signed_patch.call(*mod, "get") == Rhp::value_list{value{2}});

    Rhp::client<loop_cfg> unsigned_patch{host.dial_at(at), k.as("patch")};
    CHECK(unsigned_patch.exec("return 1").error().code == errc::kBadSignature);
    CHECK(unsigned_patch.load("x.mod", "return {}").error().code == errc::kBadSignature);
    CHECK(unsigned_patch.reload("signed.mod", "return {}").error().code == errc::kBadSignature); // the module is the patch identity's
    CHECK(unsigned_patch.call(*mod, "get"));                                                     // calling loaded code needs no signature

    Rhp::client<loop_cfg> stranger{host.dial_at(at), k.as("admin"), Rhp::security::signing_key{"dev", k.stranger}};
    auto forged = stranger.exec("return 1");
    REQUIRE_FALSE(forged);
    CHECK(forged.error().code == errc::kBadSignature);

    Rhp::client<loop_cfg> viewer{host.dial_at(at), k.as("observe")};
    CHECK(viewer.exec<int>("return 41 + 1") == 42); // observe may run unsigned code
    Rhp::client<loop_cfg> bad_viewer{host.dial_at(at), k.as("observe"), Rhp::security::signing_key{"dev", k.stranger}};
    CHECK(bad_viewer.exec("return 1").error().code == errc::kBadSignature); // a signature present must verify
}

TEST_CASE("stage4: a host with no trusted signers runs only observe code; unsigned_scripts opts out", "[stage4][signing]") {
    keys k;
    {
        const auto at = Rhp::endpoint::listen("s4.untrusting", 1);
        pumped_host<loop_cfg> host{at, k.ring()};
        host.start();
        Rhp::client<loop_cfg> c{host.dial_at(at), k.as("admin"), k.dev()};
        CHECK(c.exec("return 1").error().code == errc::kBadSignature);
    }
    {
        using open_cfg = loop_cfg::signer<Rhp::security::unsigned_scripts>;
        const auto at = Rhp::endpoint::listen("s4.unsigned", 1);
        pumped_host<open_cfg> host{at, k.ring()};
        host.start();
        Rhp::client<open_cfg> c{host.dial_at(at), k.as("patch")};
        CHECK(c.exec<int>("return 7") == 7);
    }
}

// ---- audit ------------------------------------------------------------------------------------------------

TEST_CASE("stage4: the host reports every script / session and revert", "[stage4][audit]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.audit", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    recorder<Rhp::event::script_executed> scripts;
    recorder<Rhp::event::session_opened> opened;
    recorder<Rhp::event::session_closed> closed;
    recorder<Rhp::event::auth_failed> refused;
    recorder<Rhp::event::identity_reverted> reverted;
    std::ostringstream lines;
    auto s1 = host->on<Rhp::event::script_executed>(scripts.handler());
    auto s2 = host->on<Rhp::event::session_opened>(opened.handler());
    auto s3 = host->on<Rhp::event::session_closed>(closed.handler());
    auto s4 = host->on<Rhp::event::auth_failed>(refused.handler());
    auto s5 = host->on<Rhp::event::identity_reverted>(reverted.handler());
    auto s6 = host->on_any(Rhp::audit::ostream_sink{lines});
    host.start();

    const std::string source = "s4.level = 9 return 1";
    {
        Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
        REQUIRE(c.exec(source));
        Rhp::client<loop_cfg> unsigned_c{host.dial_at(at), k.as("patch")};
        CHECK_FALSE(unsigned_c.exec("return 2"));
        Rhp::client<loop_cfg> viewer{host.dial_at(at), k.as("observe")};
        CHECK_FALSE(viewer.load("nope.mod", "return {}"));
        CHECK(viewer.list()); // introspection is not audited
        REQUIRE(eventually([&] { return scripts.size() == 3; }));
    }
    Rhp::client<loop_cfg> intruder{host.dial_at(at), Rhp::security::psk_identity{"admin", k.patch}};
    CHECK(intruder.connect().error().code == errc::kAuth);
    REQUIRE(eventually([&] { return reverted.size() >= 2 && refused.size() == 1 && closed.size() == 3; }));

    const auto s = scripts.snapshot();
    CHECK(s[0].op == "exec");
    CHECK(s[0].identity == "patch");
    CHECK(s[0].granted == Rhp::role::kPatch);
    CHECK(s[0].signer == "dev");
    CHECK(s[0].hash == Rhp::security::to_hex(Rhp::security::blake2b_256(source)));
    CHECK(s[0].outcome.code == errc::kOk);
    CHECK(s[1].outcome.code == errc::kBadSignature);
    CHECK(s[1].signer.empty());
    CHECK(s[2].op == "load");
    CHECK(s[2].outcome.code == errc::kForbidden);
    CHECK(opened.size() == 3);
    CHECK(opened.snapshot()[0].peer.starts_with("loopback"));
    CHECK(refused.snapshot()[0].reason.code == errc::kAuth);
    bool patch_reverted = false;
    for (const auto& r : reverted.snapshot()) {
        patch_reverted = patch_reverted || (r.identity == "patch" && r.undone >= 1);
    }
    CHECK(patch_reverted);

    // A dropped subscription hears nothing more.
    s1.reset();
    Rhp::client<loop_cfg> again{host.dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(again.exec("return 3"));
    CHECK(again.exec<int>("return s4.level") == 0); // the patch identity's write was reverted
    std::this_thread::sleep_for(20ms);
    CHECK(scripts.size() == 3);

    host.stop();
    const std::string text = lines.str();
    CHECK(text.find(R"("event":"script_executed")") != std::string::npos);
    CHECK(text.find(R"("event":"auth_failed")") != std::string::npos);
    CHECK(text.find(R"("signer":"dev")") != std::string::npos);
}

TEST_CASE("stage4: a suspended request is audited with its final outcome", "[stage4][audit]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.audit_late", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    recorder<Rhp::event::script_executed> scripts;
    auto sub = host->on<Rhp::event::script_executed>(scripts.handler());
    host.start();
    {
        Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
        // Suspends first (reported "ok" so far), then fails in a later pump.
        const auto late = c.exec("rhp.next_frame() error('late failure')");
        REQUIRE_FALSE(late);
        CHECK(late.error().message.find("late failure") != std::string::npos);
        REQUIRE(c.exec("rhp.next_frame() return 1"));
        REQUIRE(eventually([&] { return scripts.size() == 2; }));
    }
    std::this_thread::sleep_for(20ms);
    const auto s = scripts.snapshot();
    REQUIRE(s.size() == 2); // one record per request, none early
    CHECK(s[0].op == "exec");
    CHECK(s[0].outcome.code != errc::kOk);
    CHECK(s[0].outcome.message.find("late failure") != std::string::npos);
    CHECK(s[1].outcome.code == errc::kOk);
    host.stop();
}

TEST_CASE("stage4: a request still suspended at revert is audited as cancelled", "[stage4][audit]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.audit_cut", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    recorder<Rhp::event::script_executed> scripts;
    auto sub = host->on<Rhp::event::script_executed>(scripts.handler());
    host.start();
    {
        std::atomic<bool> started{false};
        Rhp::client_options watch;
        watch.on_output = [&](std::uint64_t, std::string_view line) {
            if (line.find("started") != std::string_view::npos) {
                started = true;
            }
        };
        Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev(), watch};
        auto forever = c.async().exec("print('started') while true do rhp.next_frame() end");
        REQUIRE(eventually([&] { return started.load(); })); // it ran and suspended
        CHECK(scripts.size() == 0);
    } // the last session closes: the identity is reverted with the request still suspended
    REQUIRE(eventually([&] { return scripts.size() == 1; }));
    CHECK(scripts.snapshot()[0].outcome.code == errc::kCancelled);
    host.stop();
}

// ---- blobs --------------------------------------------------------------------------------------------------

TEST_CASE("stage4: blobs arrive whole at their sink / in chunks / role-checked", "[stage4][blob]") {
    using small_cfg = loop_cfg::limits<Rhp::limits{.max_blob = 4u << 20}>;
    keys k;
    const auto at = Rhp::endpoint::listen("s4.blob", 1);
    pumped_host<small_cfg> host{at, k.ring(), k.trusted()};
    std::mutex mutex;
    std::vector<std::byte> received;
    std::string received_name;
    std::string received_from;
    REQUIRE(host->on_blob("configs", [&](const Rhp::blob_view& b) -> Rhp::result<void> {
        const std::scoped_lock lock{mutex};
        received.assign(b.bytes.begin(), b.bytes.end());
        received_name = b.name;
        received_from = b.identity;
        return {};
    }));
    REQUIRE(host->on_blob("public", [](const Rhp::blob_view&) -> Rhp::result<void> { return {}; }, Rhp::role::kObserve));
    REQUIRE(host->on_blob("picky", [](const Rhp::blob_view& b) -> Rhp::result<void> {
        if (b.bytes.size() != 3) {
            return Rhp::fail(errc::kInvalidArgument, "three bytes, please", "picky");
        }
        return {};
    }));
    REQUIRE(host->on_blob("thrower", [](const Rhp::blob_view&) -> Rhp::result<void> { throw std::runtime_error{"sink broke"}; }));
    CHECK(host->on_blob("configs", [](const Rhp::blob_view&) -> Rhp::result<void> { return {}; }).error().code == errc::kAlreadyLoaded);
    recorder<Rhp::event::blob_received> events;
    auto sub = host->on<Rhp::event::blob_received>(events.handler());
    host.start();

    Rhp::client_options small_chunks;
    small_chunks.blob_chunk = 64 * 1024;
    small_chunks.blob_window = 3;
    Rhp::client<small_cfg> admin{host.dial_at(at), k.as("admin"), k.dev(), small_chunks};
    std::vector<std::byte> data(3u << 20);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 31u) ^ (i >> 9));
    }
    REQUIRE(admin.blob("configs", data, "level.bin"));
    {
        const std::scoped_lock lock{mutex};
        CHECK(received == data);
        CHECK(received_name == "level.bin");
        CHECK(received_from == "admin");
    }
    REQUIRE(eventually([&] { return events.size() == 1; }));
    CHECK(events.snapshot()[0].size == data.size());
    CHECK(events.snapshot()[0].hash == Rhp::security::to_hex(Rhp::security::blake2b_256(data)));

    CHECK(admin.blob("configs", {}, "empty.bin")); // zero bytes is a blob too
    CHECK(admin.blob("nowhere", data).error().code == errc::kNotFound);
    CHECK(admin.blob("configs", std::vector<std::byte>((4u << 20) + 1)).error().code == errc::kLimitExceeded);
    CHECK(admin.blob("picky", std::vector<std::byte>(5)).error().code == errc::kInvalidArgument);
    CHECK(admin.blob("picky", std::vector<std::byte>(3)));
    CHECK(admin.blob("thrower", std::vector<std::byte>(1)).error().code == errc::kRuntime);
    CHECK(admin.exec<int>("return 1") == 1); // refused blobs leave the session working

    Rhp::client<small_cfg> viewer{host.dial_at(at), k.as("observe")};
    CHECK(viewer.blob("configs", std::vector<std::byte>(10)).error().code == errc::kForbidden);
    CHECK(viewer.blob("public", std::vector<std::byte>(10)));
}

// ---- pin ------------------------------------------------------------------------------------------------------

TEST_CASE("stage4: a pinned module outlives its identity's sessions", "[stage4][pin]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.pin", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    {
        Rhp::client<loop_cfg> admin{host.dial_at(at), k.as("admin"), k.dev()};
        auto kept = admin.load("kept.mod", "s4.level = 5 return {get = function() return s4.level end}");
        REQUIRE(kept);
        REQUIRE(admin.load("dropped.mod", "return {}"));
        REQUIRE(admin.pin("kept.mod"));
        CHECK(admin.status("kept.mod")->pinned);
        CHECK(admin.revert("kept.mod").error().code == errc::kForbidden);
        CHECK(admin.unload("kept.mod").error().code == errc::kForbidden);
        for (const auto& m : *admin.list()) {
            if (m.scratch) {
                CHECK(admin.pin(m.id).error().code == errc::kInvalidArgument);
            }
        }
        Rhp::client<loop_cfg> patch{host.dial_at(at), k.as("patch"), k.dev()};
        CHECK(patch.pin("kept.mod").error().code == errc::kForbidden);
    }
    // The admin left: the pinned module and its effect stay, the rest is gone.
    REQUIRE(eventually([&] { return host->sessions() == 0; }));
    std::this_thread::sleep_for(20ms);
    CHECK(host->identities() == 1);
    // Game state is read through a client (the pump thread owns it).
    Rhp::client<loop_cfg> viewer{host.dial_at(at), k.as("observe")};
    CHECK(viewer.exec<int>("return s4.level") == 5);
    {
        Rhp::client<loop_cfg> admin{host.dial_at(at), k.as("admin"), k.dev()};
        auto modules = admin.list();
        REQUIRE(modules);
        bool kept = false;
        bool dropped = false;
        for (const auto& m : *modules) {
            kept = kept || (m.name == "kept.mod" && m.pinned);
            dropped = dropped || m.name == "dropped.mod";
        }
        CHECK(kept);
        CHECK_FALSE(dropped);
        CHECK(admin.call("kept.mod", "get") == Rhp::value_list{value{5}});
        REQUIRE(admin.unpin("kept.mod"));
    }
    // Unpinned: the next disconnect reverts it like anything else.
    REQUIRE(eventually([&] { return viewer.exec<int>("return s4.level") == 0 && host->identities() == 1; })); // the viewer's own
}

TEST_CASE("stage4: revert_all unloads pinned modules and closes sessionless identities", "[stage4][pin]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.pin_all", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    {
        Rhp::client<loop_cfg> admin{host.dial_at(at), k.as("admin"), k.dev()};
        REQUIRE(admin.load("kept.mod", "s4.level = 8 return {}"));
        REQUIRE(admin.pin("kept.mod"));
    }
    REQUIRE(eventually([&] { return host->sessions() == 0; }));
    Rhp::client<loop_cfg> other{host.dial_at(at), k.as("admin2"), k.dev()};
    CHECK(other.exec<int>("return s4.level") == 8);
    auto all = other.revert_all();
    REQUIRE(all);
    CHECK(all->undone >= 1);
    CHECK(other.exec<int>("return s4.level") == 0);
    CHECK(eventually([&] { return host->identities() == 1; })); // admin2's own
}

// ---- reverse mode ------------------------------------------------------------------------------------------------

TEST_CASE("stage4: reverse mode: the client listens and the host dials in", "[stage4][reverse]") {
    keys k;
    SECTION("loopback, and the host dials again for the next client") {
        const auto at = Rhp::endpoint::listen("s4.reverse", 1);
        pumped_host<fast_redial_cfg> host{at.reversed(), k.ring(), k.trusted()};
        host.start();
        CHECK(host->port() == 0);
        {
            Rhp::client<fast_redial_cfg> c{at, k.as("patch"), k.dev()};
            CHECK(c.port() == 0); // loopback listeners have no port
            CHECK(c.exec<int>("return 6 * 7") == 42);
            CHECK(c.info().identity == "patch");
            CHECK(host->sessions() == 1);
        }
        Rhp::client<fast_redial_cfg> next{at, k.as("admin"), k.dev()};
        CHECK(next.exec<int>("return 1") == 1);
    }
    SECTION("TCP on 127.0.0.1, any free port") {
        Rhp::client_options patient;
        patient.connect_timeout = 20s;
        Rhp::client<tcp_cfg> c{Rhp::endpoint::listen("127.0.0.1", 0), k.as("patch"), k.dev(), patient};
        const auto port = c.port();
        REQUIRE(port);
        REQUIRE(*port != 0);
        pumped_host<tcp_cfg> host{Rhp::endpoint::dial("127.0.0.1", *port), k.ring(), k.trusted()};
        host.start();
        CHECK(c.exec<int>("return 3") == 3);
    }
    SECTION("a listening client survives its host: calls fail, the next host serves") {
        const auto at = Rhp::endpoint::listen("s4.reverse_hosts", 1);
        Rhp::client_options brief;
        brief.connect_timeout = 300ms;
        Rhp::client<fast_redial_cfg> c{at, k.as("patch"), k.dev(), brief};
        REQUIRE(c.port());
        {
            pumped_host<fast_redial_cfg> first{at.reversed(), k.ring(), k.trusted()};
            first.start();
            CHECK(c.exec<int>("return 1") == 1);
        }
        auto lost = c.exec("return 2");
        if (!lost) {
            CHECK((lost.error().code == errc::kTransport || lost.error().code == errc::kTimeout || lost.error().code == errc::kCancelled));
        }
        pumped_host<fast_redial_cfg> second{at.reversed(), k.ring(), k.trusted()};
        second.start();
        CHECK(eventually([&] { return c.exec<int>("return 3") == 3; }));
    }
    SECTION("a client that dials has no port") {
        Rhp::client<loop_cfg> c{Rhp::endpoint::dial("s4.none", 1), k.as("patch")};
        CHECK(c.port().error().code == errc::kInvalidArgument);
    }
}

// ---- async --------------------------------------------------------------------------------------------------------

TEST_CASE("stage4: async calls: get / then / future / co_await", "[stage4][async]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.async", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};

    // The first call of the client is async: it connects on the way.
    CHECK(c.async().exec<int>("return 1 + 1").get() == 2);

    std::promise<Rhp::result<Rhp::value_list>> called;
    c.exec_async("return 'a', 'b'", [&](Rhp::result<Rhp::value_list> r) { called.set_value(std::move(r)); });
    CHECK(called.get_future().get() == Rhp::value_list{value{"a"}, value{"b"}});

    auto f = c.exec_future<int>("rhp.wait(2) return 5");
    CHECK(f.get() == 5);

    std::promise<int> sum;
    sum_over_network(c, sum);
    CHECK(sum.get_future().get() == 42);

    auto mod = c.async().load("async.mod", "return {twice = function(x) return x * 2 end}").get();
    REQUIRE(mod);
    CHECK(c.async().call(*mod, "twice", 21).get() == Rhp::value_list{value{42}});
    CHECK(c.async().status(*mod).get()->name == "async.mod");
    CHECK(c.async().list().get()->size() == 2);
    CHECK(c.async().describe().get()->find("---@class s4") != std::string::npos);
    CHECK(c.async().reload(*mod, "return {twice = function(x) return x * 3 end}").get());
    CHECK(c.async().rollback(*mod).get());
    CHECK(c.async().revert(*mod).get());
    CHECK(c.async().unload(*mod).get());

    // Many at once.
    std::vector<Rhp::pending<int>> many;
    for (int i = 0; i < 100; ++i) {
        many.push_back(c.async().exec<int>("return " + std::to_string(i)));
    }
    int ok = 0;
    for (int i = 0; i < 100; ++i) {
        ok += std::move(many[static_cast<std::size_t>(i)]).get() == i ? 1 : 0;
    }
    CHECK(ok == 100);

    // One async call cancelled by its request id.
    auto loop = c.async().exec("while true do end");
    std::this_thread::sleep_for(50ms);
    c.cancel(loop.request());
    CHECK(std::move(loop).get().error().code == errc::kCancelled);
    CHECK(c.exec<int>("return 9") == 9);
}

TEST_CASE("stage4: async errors: signing / timeouts / a closed client / zero_threads", "[stage4][async]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.async_err", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    {
        Rhp::client<loop_cfg> unsigned_c{host.dial_at(at), k.as("patch")};
        CHECK(unsigned_c.async().exec("return 1").get().error().code == errc::kBadSignature);
    }
    {
        Rhp::client_options quick;
        quick.request_timeout = 100ms;
        Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev(), quick};
        CHECK(c.async().exec("rhp.sleep(5000)").get().error().code == errc::kTimeout);
        CHECK(c.exec<int>("return 4") == 4);
    }
    {
        Rhp::client<loop_cfg> nobody{Rhp::endpoint::dial("s4.nobody", 1), k.as("patch"), k.dev()};
        CHECK(nobody.async().exec("return 1").get().error().code == errc::kNotFound);
        CHECK(nobody.async().exec("return 1").get().error().code == errc::kNotFound); // closed for good: answered at once
    }
    {
        using quiet_cfg = loop_cfg::io<Rhp::exec::zero_threads>;
        const auto quiet_at = Rhp::endpoint::listen("s4.async_zero", 1);
        pumped_host<quiet_cfg> quiet{quiet_at, k.ring(), k.trusted()};
        quiet.start();
        Rhp::client<quiet_cfg> c{quiet.dial_at(quiet_at), k.as("patch"), k.dev()};
        auto p = c.async().exec<int>("rhp.wait(3) return 8");
        CHECK(std::move(p).get() == 8); // get() runs the network itself
        std::optional<Rhp::result<int>> later;
        c.async().exec<int>("return 9").then([&](Rhp::result<int> r) { later = std::move(r); });
        CHECK(eventually([&] {
            c.poll();
            return later.has_value();
        }));
        CHECK(*later == 9);
    }
}

TEST_CASE("stage4: async calls under errors::throwing", "[stage4][async]") {
    using throwing_cfg = loop_cfg::errors<Rhp::errors::throwing>;
    keys k;
    const auto at = Rhp::endpoint::listen("s4.async_throw", 1);
    pumped_host<throwing_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    Rhp::client<throwing_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
    const int n = c.async().exec<int>("return 12").get();
    CHECK(n == 12);
    auto f = c.exec_future<int>("error('no')");
    CHECK_THROWS_AS(f.get(), Rhp::exception);
}

// ---- kill switch ------------------------------------------------------------------------------------------------------

TEST_CASE("stage4: set_enabled(false) refuses requests and connections until re-enabled", "[stage4][kill]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.kill", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(c.exec("return 1"));
    host->set_enabled(false);
    CHECK_FALSE(host->enabled());
    CHECK(c.exec("return 1").error().code == errc::kDisabled);
    Rhp::client_options quick;
    quick.connect_timeout = 2s;
    Rhp::client<loop_cfg> late{host.dial_at(at), k.as("patch"), k.dev(), quick};
    CHECK_FALSE(late.connect());
    host->set_enabled(true);
    CHECK(c.exec<int>("return 2") == 2);
}

// ---- review regressions --------------------------------------------------------------------------------------

namespace stage4_fixtures {

// Speaks the session protocol directly, to send blob chunks in an order the client never would.
struct raw_session final : Rhp::session::handler {
    Rhp::net::io_context io;
    std::unique_ptr<Rhp::session::session> s;
    bool ready = false;
    std::vector<std::pair<Rhp::wire::op, Rhp::wire::envelope>> replies;

    raw_session(const Rhp::endpoint& at, const Rhp::security::psk_identity& who) {
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
    void on_message(Rhp::session::session&, Rhp::wire::op code, value body) override { replies.emplace_back(code, *Rhp::from_value<Rhp::wire::envelope>(body)); }
    void on_closed(Rhp::session::session&, const Rhp::error&) override {}

    // Sends one chunk as request `req` and waits for its answer.
    std::pair<Rhp::wire::op, value> chunk(std::uint64_t req, std::uint64_t transfer, std::uint64_t total, std::uint64_t offset, std::size_t n) {
        Rhp::wire::blob_chunk c{transfer, "configs", "x.bin", total, offset, value::bytes(n, std::byte{7})};
        REQUIRE(s->send(Rhp::wire::op::kBlob, Rhp::to_value(Rhp::wire::envelope{req, 0, Rhp::to_value(c)})));
        REQUIRE(rhp_test::poll_until({&io}, [&] {
            for (const auto& [code, env] : replies) {
                if (env.req == req) {
                    return true;
                }
            }
            return false;
        }));
        for (const auto& [code, env] : replies) {
            if (env.req == req) {
                return {code, env.body};
            }
        }
        return {};
    }
};

} // namespace stage4_fixtures

TEST_CASE("stage4: a call that timed out or was cancelled before it was sent never runs", "[stage4][async][review]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.ghost", 1);
    Rhp::client_options brief;
    brief.request_timeout = 200ms;
    Rhp::client<fast_redial_cfg> c{at, k.as("patch"), k.dev(), brief};
    REQUIRE(c.port());
    // No host yet: both calls wait in the client's queue, then fail there.
    CHECK(c.async().exec("s4.level = 5").get().error().code == errc::kTimeout);
    auto second = c.async().exec("s4.level = s4.level + 100");
    c.cancel(second.request());
    const auto code = std::move(second).get().error().code;
    CHECK((code == errc::kCancelled || code == errc::kTimeout));
    // The host arrives: neither ran.
    pumped_host<fast_redial_cfg> host{at.reversed(), k.ring(), k.trusted()};
    host.start();
    CHECK(eventually([&] {
        auto level = c.exec<int>("return s4.level");
        return level && *level == 0;
    }));
}

TEST_CASE("stage4: a connection that never authenticates doesn't fail a listening client's queued calls", "[stage4][reverse][review]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.stray", 1);
    Rhp::client<fast_redial_cfg> c{at, k.as("patch"), k.dev()};
    REQUIRE(c.port());
    auto queued = c.async().exec<int>("return 11");
    {
        // A stray connection: it sends something that isn't RHP and hangs up. (The listening
        // client says nothing until the dialer has spoken: TLS or plaintext is the dialer's call.)
        Rhp::net::io_context io;
        std::unique_ptr<Rhp::net::link> stray;
        rhp_test::recorder seen;
        Rhp::net::loopback::dial(io, at.reversed(), [&](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
            REQUIRE(l);
            stray = std::move(*l);
            stray->start(seen);
        });
        REQUIRE(rhp_test::poll_until({&io}, [&] { return stray != nullptr; }));
        Rhp::utils::byte_buffer junk;
        junk.append(std::string_view{"GET / HTTP/1.1"});
        stray->send(std::move(junk));
        rhp_test::poll_for({&io}, 50ms);
        stray->close();
        rhp_test::poll_for({&io}, 50ms);
    }
    std::this_thread::sleep_for(50ms);
    CHECK_FALSE(queued.ready());
    pumped_host<fast_redial_cfg> host{at.reversed(), k.ring(), k.trusted()};
    host.start();
    CHECK(std::move(queued).get() == 11);
}

TEST_CASE("stage4: a new blob transfer replaces one the client gave up on", "[stage4][blob][review]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.blob_replace", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    std::atomic<std::size_t> delivered{0};
    REQUIRE(host->on_blob("configs", [&](const Rhp::blob_view& b) -> Rhp::result<void> {
        delivered = b.bytes.size();
        return {};
    }));
    host.start();
    raw_session raw{host.dial_at(at), k.as("admin")};
    CHECK(raw.chunk(1, 100, 8, 0, 4).first == Rhp::wire::op::kResult); // transfer 100: half of it
    CHECK(raw.chunk(2, 200, 4, 0, 4).first == Rhp::wire::op::kResult); // transfer 200 replaces it and completes
    CHECK(delivered == 4);
    const auto late = raw.chunk(3, 100, 8, 4, 4); // the abandoned transfer's next chunk
    CHECK(late.first == Rhp::wire::op::kError);
    CHECK(Rhp::from_value<Rhp::error>(late.second)->code == errc::kCancelled);
    CHECK(raw.chunk(4, 300, 2, 0, 2).first == Rhp::wire::op::kResult); // and the session goes on
}

TEST_CASE("stage4: a call running in a pinned module outlives the session that started it", "[stage4][pin][review]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.pin_call", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    {
        Rhp::client<loop_cfg> admin{host.dial_at(at), k.as("admin"), k.dev()};
        REQUIRE(admin.load("ticker", "s4.level = 3 return {run = function() while true do rhp.next_frame() end end}"));
        REQUIRE(admin.pin("ticker"));
        auto forever = admin.async().call("ticker", "run");
        std::this_thread::sleep_for(50ms);
        CHECK_FALSE(forever.ready());
    } // disconnect: the pinned module and its running call stay
    REQUIRE(eventually([&] { return host->sessions() == 0; }));
    Rhp::client<loop_cfg> viewer{host.dial_at(at), k.as("observe")};
    CHECK(viewer.exec<int>("return s4.level") == 3);
    Rhp::client<loop_cfg> admin{host.dial_at(at), k.as("admin"), k.dev()};
    auto status = admin.status("ticker");
    REQUIRE(status);
    CHECK(status->state == "active");
    CHECK(status->pinned);
    REQUIRE(admin.revert_all());
    CHECK(viewer.exec<int>("return s4.level") == 0);
}

TEST_CASE("stage4: revert_to is refused while the identity has pinned modules", "[stage4][pin][review]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.pin_revert_to", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    host.start();
    Rhp::client<loop_cfg> admin{host.dial_at(at), k.as("admin"), k.dev()};
    REQUIRE(admin.checkpoint("before"));
    REQUIRE(admin.load("patch.mod", "s4.level = 7 return {}"));
    REQUIRE(admin.pin("patch.mod"));
    CHECK(admin.revert_to("before").error().code == errc::kForbidden);
    CHECK(admin.exec<int>("return s4.level") == 7);
    REQUIRE(admin.unpin("patch.mod"));
    CHECK(admin.revert_to("before"));
    CHECK(admin.exec<int>("return s4.level") == 0);
}

TEST_CASE("stage4: refused connections are reported as auth_failed", "[stage4][audit][review]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s4.refused", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    recorder<Rhp::event::auth_failed> refused;
    auto sub = host->on<Rhp::event::auth_failed>(refused.handler());
    host.start();
    host->set_enabled(false);
    Rhp::client_options quick;
    quick.connect_timeout = 2s;
    Rhp::client<loop_cfg> c{host.dial_at(at), k.as("patch"), k.dev(), quick};
    CHECK_FALSE(c.connect());
    REQUIRE(eventually([&] { return refused.size() >= 1; }));
    CHECK(refused.snapshot()[0].reason.code == errc::kDisabled);
}
