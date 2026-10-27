#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "../unit/release/release_support.hpp"
#include <catch2/catch_test_macros.hpp>
#include <rhp_test/eventually.hpp>
#include <rhp_test/net_support.hpp>
#include <rhp_test/tls_fixtures.hpp>

#include <rhp/build_config.hpp>
#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>

using namespace std::chrono_literals;
using Rhp::errc;

namespace stage13_net_fixtures {

std::atomic<int> g_ticks{0};         // timers
std::atomic<int> g_tasks{0};         // rhp.spawn tasks
std::atomic<int> g_release_ticks{0}; // a release channel's timer
int g_level = 0;                     // set by a patch session (reverted with it)
int g_pinned = 0;                    // set by a pinned module (kept)

int tick() {
    return ++g_ticks;
}

int task() {
    return ++g_tasks;
}

int release_tick() {
    return ++g_release_ticks;
}

using s13_lib = Rhp::lib<"s13n">::fn<"tick", &tick>::fn<"task", &task>::fn<"release_tick", &release_tick>::var<"level", &g_level>::var<"pinned", &g_pinned>;

using loop_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;

struct keys {
    Rhp::security::key admin = *Rhp::security::key::generate();
    Rhp::security::key patch = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();

    [[nodiscard]] Rhp::security::keyring ring() const {
        return Rhp::security::keyring{{"admin", admin, Rhp::role::kAdmin}, {"patch", patch, Rhp::role::kPatch}};
    }
    [[nodiscard]] Rhp::security::trusted_signers trusted() const { return Rhp::security::trusted_signers{{"dev", developer.public_key()}}; }
    [[nodiscard]] Rhp::security::signing_key dev() const { return {"dev", developer}; }
    [[nodiscard]] Rhp::security::psk_identity as(std::string_view who) const {
        return who == "admin" ? Rhp::security::psk_identity{"admin", admin} : Rhp::security::psk_identity{"patch", patch};
    }
};

// A host pumped by its own "game" thread.
template <class Cfg>
class pumped_host {
public:
    template <class... Args>
    explicit pumped_host(Args&&... args) : host_(std::forward<Args>(args)...) {
        (void)host_.template install<s13_lib>();
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~pumped_host() {
        pump_.request_stop();
        pump_.join();
    }

    pumped_host(const pumped_host&) = delete;
    pumped_host& operator=(const pumped_host&) = delete;

    Rhp::host<Cfg>* operator->() { return &host_; }

    [[nodiscard]] Rhp::endpoint dial_at(const Rhp::endpoint& listen_at) {
        auto p = host_.port();
        REQUIRE(p);
        return listen_at.reversed().with_port(*p == 0 ? listen_at.port : *p);
    }

private:
    Rhp::host<Cfg> host_;
    std::jthread pump_;
};

using rhp_test::eventually;

// Events of one kind, kept for the test thread.
template <class E>
struct seen_events {
    std::mutex mutex;
    std::vector<E> list;

    auto handler() {
        return [this](const E& e) {
            const std::scoped_lock lock{mutex};
            list.push_back(e);
        };
    }
    std::size_t size() {
        const std::scoped_lock lock{mutex};
        return list.size();
    }
    std::vector<E> snapshot() {
        const std::scoped_lock lock{mutex};
        return list;
    }
};

// Raw connections a test holds open (stalled peers): each one's link and what it saw.
struct raw_peers {
    Rhp::net::io_context io;
    std::vector<std::unique_ptr<Rhp::net::link>> links;
    std::vector<std::unique_ptr<rhp_test::recorder>> seen;

    // Connects over transport T; returns its index.
    template <class T>
    std::size_t open(const Rhp::endpoint& at) {
        const std::size_t before = links.size();
        T::dial(io, at, [&](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
            REQUIRE(l);
            seen.push_back(std::make_unique<rhp_test::recorder>());
            (*l)->start(*seen.back());
            links.push_back(std::move(*l));
        });
        REQUIRE(rhp_test::poll_until({&io}, [&] { return links.size() == before + 1; }));
        return before;
    }

    // The peer sends a few bytes that don't make a frame yet.
    void speak(std::size_t i) { links.at(i)->send(rhp_test::buffer_of("RH")); }

    [[nodiscard]] bool closed(std::size_t i) const { return seen.at(i)->closed; }

    // Runs the context for a while (the host's answers and closes arrive).
    void settle(std::chrono::milliseconds d = 100ms) { rhp_test::poll_for({&io}, d); }
};

// ---- loopback whose dialed connections the test can cut ---------------------------------------------------
//
// Only the dialing side is wrapped, so cut_all() drops the clients' links (both ends see them close)
// and leaves the raw connections a test opens with plain loopback alone.

struct cut_registry {
    std::mutex mutex;
    std::vector<std::pair<std::weak_ptr<Rhp::net::io_context::poster>, std::weak_ptr<Rhp::net::link*>>> links;

    void add(const std::shared_ptr<Rhp::net::io_context::poster>& poster, const std::shared_ptr<Rhp::net::link*>& inner) {
        const std::scoped_lock lock{mutex};
        links.emplace_back(poster, inner);
    }

    void cut_all() {
        const std::scoped_lock lock{mutex};
        for (const auto& [poster, inner] : links) {
            if (const auto p = poster.lock()) {
                (void)p->post([inner] {
                    if (const auto l = inner.lock(); l != nullptr && *l != nullptr) {
                        (*l)->close();
                    }
                });
            }
        }
        links.clear();
    }
};

cut_registry& cuts() {
    static cut_registry r;
    return r;
}

class cut_link final : public Rhp::net::link_decorator {
public:
    cut_link(Rhp::net::io_context& io, std::unique_ptr<Rhp::net::link> inner) : link_decorator(std::move(inner)), self_(std::make_shared<Rhp::net::link*>(&this->inner())) {
        cuts().add(io.shared_poster(), self_);
    }
    ~cut_link() override { *self_ = nullptr; }

    cut_link(const cut_link&) = delete;
    cut_link& operator=(const cut_link&) = delete;

private:
    std::shared_ptr<Rhp::net::link*> self_;
};

struct dial_cuttable {
    static constexpr std::string_view name = "dial_cuttable";
    static constexpr bool network = false; // loopback underneath

    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::accept_fn on_accept) {
        return Rhp::net::loopback::listen(io, ep, std::move(on_accept));
    }

    static void dial(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::connect_fn on_connect) {
        Rhp::net::loopback::dial(io, ep, [&io, on_connect = std::move(on_connect)](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
            if (!l) {
                on_connect(std::move(l));
                return;
            }
            on_connect(std::unique_ptr<Rhp::net::link>{std::make_unique<cut_link>(io, std::move(*l))});
        });
    }
};

static_assert(Rhp::net::transport<dial_cuttable>);

} // namespace stage13_net_fixtures

using namespace stage13_net_fixtures;

// ---- admission ---------------------------------------------------------------------------------------------

TEST_CASE("stage13: one source can't take every unauthenticated slot", "[stage13][admission]") {
    using capped = tcp_cfg::limits<Rhp::limits{.pending_handshakes = 64, .handshakes_per_source = 2, .handshake_timeout_ms = 60'000, .first_byte_ms = 60'000}>;
    keys k;
    pumped_host<capped> host{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted()};
    seen_events<Rhp::event::auth_failed> refused;
    auto sub = host->on<Rhp::event::auth_failed>(refused.handler());
    const auto at = host.dial_at(Rhp::endpoint::listen("127.0.0.1", 0));
    raw_peers raw;
    const auto first = raw.open<Rhp::net::tcp>(at);
    raw.settle();
    const auto second = raw.open<Rhp::net::tcp>(at);
    raw.settle();
    // A third from 127.0.0.1 takes the slot of the oldest one that said nothing.
    const auto third = raw.open<Rhp::net::tcp>(at);
    REQUIRE(rhp_test::poll_until({&raw.io}, [&] { return raw.closed(first); }));
    raw.settle();
    CHECK_FALSE(raw.closed(second));
    CHECK_FALSE(raw.closed(third));
    // Once both have spoken, a new one from the same address is turned away.
    raw.speak(second);
    raw.speak(third);
    raw.settle();
    const auto fourth = raw.open<Rhp::net::tcp>(at);
    REQUIRE(rhp_test::poll_until({&raw.io}, [&] { return raw.closed(fourth); }));
    CHECK_FALSE(raw.closed(second));
    REQUIRE(eventually([&] { return refused.size() >= 2; }));
    for (const auto& e : refused.snapshot()) {
        CHECK(e.reason.code == errc::kLimitExceeded);
    }
}

TEST_CASE("stage13: a connection that sends nothing is dropped after first_byte_ms", "[stage13][admission]") {
    using quick = tcp_cfg::limits<Rhp::limits{.handshake_timeout_ms = 60'000, .first_byte_ms = 150}>;
    keys k;
    pumped_host<quick> host{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted()};
    seen_events<Rhp::event::auth_failed> refused;
    auto sub = host->on<Rhp::event::auth_failed>(refused.handler());
    const auto at = host.dial_at(Rhp::endpoint::listen("127.0.0.1", 0));
    raw_peers raw;
    const auto silent = raw.open<Rhp::net::tcp>(at);
    const auto talker = raw.open<Rhp::net::tcp>(at);
    raw.speak(talker);
    REQUIRE(rhp_test::poll_until({&raw.io}, [&] { return raw.closed(silent); }, 5s));
    raw.settle(300ms);
    CHECK_FALSE(raw.closed(talker)); // it spoke: the handshake deadline applies to it instead
    REQUIRE(eventually([&] { return refused.size() >= 1; }));
    CHECK(refused.snapshot()[0].reason.code == errc::kTimeout);
    // A real client is not slowed down.
    Rhp::client<quick> c{at, k.as("patch"), k.dev()};
    CHECK(c.exec<int>("return s13n.tick() * 0 + 7") == 7);
}

TEST_CASE("stage13: a resume gets through slots full of silent connections", "[stage13][admission][resume]") {
    constexpr Rhp::limits kFull{.pending_handshakes = 2, .handshake_timeout_ms = 60'000, .first_byte_ms = 60'000, .heartbeat_ms = 500, .backoff_min_ms = 5, .backoff_max_ms = 40};
    using full_cfg = Rhp::config<>::transport<dial_cuttable>::logger<Rhp::core::null_logger>::limits<kFull>;
    keys k;
    const auto at = Rhp::endpoint::listen("s13.resume_full", 1);
    pumped_host<full_cfg> host{at, k.ring(), k.trusted()};
    seen_events<Rhp::event::session_resumed> resumed;
    auto sub = host->on<Rhp::event::session_resumed>(resumed.handler());
    Rhp::client<full_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(c.exec<int>("return 1") == 1);
    const auto session = c.info().session;
    // Two connections that say nothing hold both unauthenticated slots.
    raw_peers raw;
    const auto a = raw.open<Rhp::net::loopback>(host.dial_at(at));
    const auto b = raw.open<Rhp::net::loopback>(host.dial_at(at));
    raw.settle();
    REQUIRE_FALSE(raw.closed(a));
    REQUIRE_FALSE(raw.closed(b));
    // The client's link dies; its redial takes a silent connection's slot and resumes the session.
    cuts().cut_all();
    CHECK(c.exec<int>("return 2") == 2);
    CHECK(c.info().resumes == 1);
    CHECK(c.info().session == session);
    CHECK(eventually([&] { return resumed.size() == 1; }));
    REQUIRE(rhp_test::poll_until({&raw.io}, [&] { return raw.closed(a); }));
    CHECK_FALSE(raw.closed(b));
}

TEST_CASE("stage13: auth_failed names the key that was tried", "[stage13][admission][audit]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s13.keyname", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    seen_events<Rhp::event::auth_failed> refused;
    auto sub = host->on<Rhp::event::auth_failed>(refused.handler());
    Rhp::client_options quick;
    quick.connect_timeout = 3s;
    {
        Rhp::client<loop_cfg> stranger{host.dial_at(at), Rhp::security::psk_identity{"nobody", *Rhp::security::key::generate()}, quick};
        CHECK_FALSE(stranger.connect());
    }
    {
        Rhp::client<loop_cfg> impostor{host.dial_at(at), Rhp::security::psk_identity{"patch", *Rhp::security::key::generate()}, quick};
        CHECK_FALSE(impostor.connect());
    }
    REQUIRE(eventually([&] { return refused.size() >= 2; }));
    const auto seen = refused.snapshot();
    CHECK(seen[0].key == "nobody");
    CHECK(seen[1].key == "patch");
    CHECK(seen[1].reason.code == errc::kAuth);
}

// ---- a listening client ---------------------------------------------------------------------------------

TEST_CASE("stage13: stalled connections don't keep a real host from a listening client", "[stage13][reverse][admission]") {
    // A handshake deadline long enough that a stalled connection holding the client would fail the test.
    using slow_cfg = tcp_cfg::limits<Rhp::limits{.handshake_timeout_ms = 60'000}>;
    keys k;
    Rhp::client_options patient;
    patient.connect_timeout = 10s;
    Rhp::client<slow_cfg> c{Rhp::endpoint::listen("127.0.0.1", 0), k.as("patch"), k.dev(), patient};
    const auto port = c.port();
    REQUIRE(port);
    const auto at = Rhp::endpoint::dial("127.0.0.1", *port);
    raw_peers raw;
    const auto silent = raw.open<Rhp::net::tcp>(at);
    const auto stalled = raw.open<Rhp::net::tcp>(at);
    raw.speak(stalled); // the start of a frame, and then nothing
    raw.settle();
    pumped_host<slow_cfg> host{at, k.ring(), k.trusted()}; // reverse mode: the host dials the client
    const auto started = std::chrono::steady_clock::now();
    CHECK(c.exec<int>("return 5") == 5);
    CHECK(std::chrono::steady_clock::now() - started < 5s);
    CHECK(c.info().identity == "patch");
    // The host that authenticated first is served; the connections still handshaking are closed.
    REQUIRE(rhp_test::poll_until({&raw.io}, [&] { return raw.closed(silent) && raw.closed(stalled); }));
    CHECK(c.exec<int>("return 6") == 6);
}

// ---- TLS host names ------------------------------------------------------------------------------------

#if RHP_TLS_HAS_OPENSSL || RHP_TLS_HAS_MBEDTLS

namespace stage13_net_fixtures {

// A network transport that reaches every name at 127.0.0.1, as a DNS entry would: the name dialed is
// only what TLS checks.
struct any_name_tcp {
    static constexpr std::string_view name = "any_name_tcp";
    static constexpr bool network = true;

    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::accept_fn on_accept) {
        return Rhp::net::tcp::listen(io, ep, std::move(on_accept));
    }

    static void dial(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::connect_fn on_connect) {
        Rhp::endpoint here = ep;
        here.host = "127.0.0.1";
        Rhp::net::tcp::dial(io, here, std::move(on_connect));
    }
};

static_assert(Rhp::net::transport<any_name_tcp>);

} // namespace stage13_net_fixtures

TEST_CASE("stage13: a CA-checked dial checks the host name unless it is an IP address", "[stage13][tls]") {
    using named_cfg = Rhp::config<>::transport<any_name_tcp>::logger<Rhp::core::null_logger>;
    keys k;
    Rhp::host_options with_cert;
    with_cert.tls.cert_pem = std::string{rhp_test::tls::kHostCertPem}; // issued for "game.test"
    with_cert.tls.key_pem = std::string{rhp_test::tls::kHostKeyPem};
    pumped_host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), with_cert};
    const auto port = *host->port();
    Rhp::client_options checked;
    checked.tls.ca_pem = std::string{rhp_test::tls::kCaPem};
    checked.connect_timeout = 3s;
    {
        Rhp::client<named_cfg> right{Rhp::endpoint::dial("game.test", port), k.as("patch"), k.dev(), checked};
        CHECK(right.exec<int>("return 3") == 3);
        CHECK(right.info().tls);
    }
    // Hex-looking names are names: the certificate isn't theirs.
    for (const std::string_view name : {"cafe1", "db1.de", "beef.test"}) {
        INFO(name);
        Rhp::client<named_cfg> wrong{Rhp::endpoint::dial(name, port), k.as("patch"), k.dev(), checked};
        CHECK_FALSE(wrong.connect());
    }
}

#endif

// ---- the kill switch ---------------------------------------------------------------------------------

namespace stage13_net_fixtures {

// A host pumped by its own thread, serving `releases` (when given) from its first pump.
class serving_host {
public:
    serving_host(const Rhp::endpoint& at, const keys& k, Rhp::release::manager* releases = nullptr) : host_(at, k.ring(), k.trusted()) {
        REQUIRE(host_.install<s13_lib>());
        if (releases != nullptr) {
            REQUIRE(host_.serve(*releases));
        }
        pump_ = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host_.pump();
                std::this_thread::sleep_for(1ms);
            }
        }};
    }

    ~serving_host() {
        pump_.request_stop();
        pump_.join();
    }

    serving_host(const serving_host&) = delete;
    serving_host& operator=(const serving_host&) = delete;

    Rhp::host<loop_cfg>* operator->() { return &host_; }

private:
    Rhp::host<loop_cfg> host_;
    std::jthread pump_;
};

// Whether `counter` stands still for a while (what ran just before the switch flipped has settled).
[[nodiscard]] bool stands_still(const std::atomic<int>& counter) {
    std::this_thread::sleep_for(50ms);
    const int before = counter.load();
    std::this_thread::sleep_for(200ms);
    return counter.load() == before;
}

} // namespace stage13_net_fixtures

TEST_CASE("stage13: set_enabled(false) closes every session and reverts identities except pinned modules", "[stage13][kill]") {
    g_level = 0;
    g_pinned = 0;
    keys k;
    const auto at = Rhp::endpoint::listen("s13.kill_sessions", 1);
    serving_host host{at, k};
    seen_events<Rhp::event::session_closed> closed;
    auto sub = host->on<Rhp::event::session_closed>(closed.handler());
    Rhp::client<loop_cfg> patcher{at.reversed(), k.as("patch"), k.dev()};
    REQUIRE(patcher.exec("s13n.level = 5"));
    {
        Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.dev()};
        const auto mod = admin.load("tests.s13.kept", "s13n.pinned = 7 return {}");
        REQUIRE(mod);
        REQUIRE(admin.pin(*mod));
        REQUIRE(eventually([&] { return host->sessions() == 2; }));

        host->set_enabled(false);
        CHECK(eventually([&] { return host->sessions() == 0; }));
        CHECK(eventually([&] { return !admin.connected() && !patcher.connected(); }));
        CHECK(admin.exec("return 1").error().code == errc::kDisabled);
        CHECK(eventually([&] { return closed.size() == 2; }));
        for (const auto& e : closed.snapshot()) {
            CHECK(e.reason.code == errc::kDisabled);
        }
        // The patch identity is reverted and gone; the admin one stays for its pinned module.
        CHECK(eventually([&] { return host->identities() == 1; }));
    }
    CHECK(patcher.exec("return 1").error().code == errc::kDisabled);
    Rhp::client_options quick;
    quick.connect_timeout = 1s;
    Rhp::client<loop_cfg> refused{at.reversed(), k.as("patch"), k.dev(), quick};
    CHECK_FALSE(refused.connect());

    host->set_enabled(true);
    Rhp::client<loop_cfg> back{at.reversed(), k.as("admin"), k.dev()};
    CHECK(back.exec<int>("return s13n.level") == 0);
    CHECK(back.exec<int>("return s13n.pinned") == 7);
    REQUIRE(back.revert_all());
    CHECK(back.exec<int>("return s13n.pinned") == 0);
}

TEST_CASE("stage13: a disabled host runs no handlers tasks or release channels", "[stage13][kill]") {
    const release_test::signer dev{"dev"};
    Rhp::release::manager_options options;
    options.app = "s13game";
    options.health_window = 20ms;
    Rhp::release::manager releases{release_test::trust_of({{&dev, {"game.*"}}}), options};
    REQUIRE(releases.install<s13_lib>());
    REQUIRE(releases.restore());
    const std::vector<release_test::module_source> ticker{{"ticker", "rhp.every(5, function() s13n.release_tick() end)"}};
    auto manifest = release_test::manifest_for("game.ticker", 1, ticker);
    manifest.app = "s13game";
    REQUIRE(releases.apply(release_test::envelope(manifest, ticker, {&dev})));

    keys k;
    const auto at = Rhp::endpoint::listen("s13.kill_scripts", 1);
    serving_host host{at, k, &releases};
    {
        Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.dev()};
        const auto mod = admin.load("tests.s13.busy", "rhp.every(5, function() s13n.tick() end) "
                                                      "rhp.spawn(function() while true do s13n.task() rhp.next_frame() end end) return {}");
        REQUIRE(mod);
        REQUIRE(admin.pin(*mod));
    }
    const int ticks = g_ticks.load();
    const int tasks = g_tasks.load();
    const int release_ticks = g_release_ticks.load();
    REQUIRE(eventually([&] { return g_ticks > ticks + 3 && g_tasks > tasks + 3 && g_release_ticks > release_ticks + 3; }));

    host->set_enabled(false);
    CHECK(stands_still(g_ticks));
    CHECK(stands_still(g_tasks));
    CHECK(stands_still(g_release_ticks));

    host->set_enabled(true);
    const int resumed_ticks = g_ticks.load();
    const int resumed_tasks = g_tasks.load();
    const int resumed_release = g_release_ticks.load();
    CHECK(eventually([&] { return g_ticks > resumed_ticks + 3 && g_tasks > resumed_tasks + 3 && g_release_ticks > resumed_release + 3; }));
    Rhp::client<loop_cfg> admin{at.reversed(), k.as("admin"), k.dev()};
    REQUIRE(admin.revert_all());
}

TEST_CASE("stage13: a disabled reverse-mode host stops dialing until it is enabled", "[stage13][kill][reverse]") {
    constexpr Rhp::limits kFastRedial{.backoff_min_ms = 5, .backoff_max_ms = 40};
    using redial_cfg = loop_cfg::limits<kFastRedial>;
    keys k;
    // Something to dial that never authenticates: each connection the host makes shows up here.
    Rhp::net::io_context io;
    std::vector<std::unique_ptr<Rhp::net::link>> accepted;
    std::vector<std::unique_ptr<rhp_test::recorder>> seen;
    auto listening = Rhp::net::loopback::listen(io, Rhp::endpoint::listen("s13.kill_dial", 1), [&](std::unique_ptr<Rhp::net::link> l) {
        seen.push_back(std::make_unique<rhp_test::recorder>());
        l->start(*seen.back());
        accepted.push_back(std::move(l));
    });
    REQUIRE(listening);
    pumped_host<redial_cfg> host{Rhp::endpoint::dial("s13.kill_dial", 1), k.ring(), k.trusted()};
    REQUIRE(rhp_test::poll_until({&io}, [&] { return accepted.size() == 1; }));

    host->set_enabled(false);
    REQUIRE(rhp_test::poll_until({&io}, [&] { return seen[0]->closed; })); // its session is closed
    rhp_test::poll_for({&io}, 400ms);                                      // backoff is 5-40 ms: it would have dialed by now
    CHECK(accepted.size() == 1);

    host->set_enabled(true);
    CHECK(rhp_test::poll_until({&io}, [&] { return accepted.size() == 2; }));
}

TEST_CASE("stage13: a listening client gets its host back after the kill switch", "[stage13][kill][reverse]") {
    constexpr Rhp::limits kFastRedial{.backoff_min_ms = 5, .backoff_max_ms = 40};
    using redial_cfg = loop_cfg::limits<kFastRedial>;
    keys k;
    const auto at = Rhp::endpoint::listen("s13.kill_reverse", 1);
    Rhp::client_options brief;
    brief.connect_timeout = 300ms;
    Rhp::client<redial_cfg> c{at, k.as("patch"), k.dev(), brief};
    REQUIRE(c.port());
    pumped_host<redial_cfg> host{at.reversed(), k.ring(), k.trusted()};
    REQUIRE(c.exec<int>("return 1") == 1);
    host->set_enabled(false);
    REQUIRE(eventually([&] { return !c.connected(); }));
    CHECK_FALSE(c.exec("return 2")); // nobody dials in while the host is off
    host->set_enabled(true);
    CHECK(eventually([&] { return c.exec<int>("return 3") == 3; }));
}

TEST_CASE("stage13: a listening client drops a connection that sends nothing", "[stage13][reverse][admission]") {
    using quick_cfg = tcp_cfg::limits<Rhp::limits{.handshake_timeout_ms = 60'000, .first_byte_ms = 150}>;
    keys k;
    Rhp::client<quick_cfg> c{Rhp::endpoint::listen("127.0.0.1", 0), k.as("patch"), k.dev()};
    const auto port = c.port();
    REQUIRE(port);
    raw_peers raw;
    const auto silent = raw.open<Rhp::net::tcp>(Rhp::endpoint::dial("127.0.0.1", *port));
    REQUIRE(rhp_test::poll_until({&raw.io}, [&] { return raw.closed(silent); }, 5s));
    // Neither the drop nor the wait failed anything: a host that comes now is served.
    pumped_host<quick_cfg> host{Rhp::endpoint::dial("127.0.0.1", *port), k.ring(), k.trusted()};
    CHECK(c.exec<int>("return 8") == 8);
}
