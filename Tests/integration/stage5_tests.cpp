#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>
#include <rhp_test/tls_fixtures.hpp>

#include <rhp/client/client.hpp>
#include <rhp/config/config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/log.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/event/events.hpp>
#include <rhp/host/host.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>
#include <rhp/net/tcp/tcp.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/keyring.hpp>
#include <rhp/security/psk_keyring.hpp>
#include <rhp/security/tls/auto_backend.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/codec/msgpack.hpp>

using namespace std::chrono_literals;
using Rhp::errc;
using Rhp::value;

namespace stage5_fixtures {

std::atomic<int> g_runs{0};
int g_keep = 0;

int bump() {
    return ++g_runs;
}

using s5_lib = Rhp::lib<"s5">::fn<"bump", &bump>::var<"keep", &g_keep>;

// ---- a transport whose connections the test can cut ------------------------------------------------------
//
// Loopback underneath. cut_all() drops every live connection the way a dead Wi-Fi link does: bytes in
// flight are lost, both ends see the link close, nobody says why. refuse_dials stops new connections.

struct cut_state {
    std::atomic<bool> dead{false};
    std::shared_ptr<Rhp::net::io_context::poster> poster;
    Rhp::net::link* inner = nullptr; // touched on the link's io thread only
};

struct cut_registry {
    std::mutex mutex;
    std::vector<std::weak_ptr<cut_state>> links;
    std::atomic<bool> refuse_dials{false};
    std::atomic<int> cuts{0};
    std::string redirect; // dial this channel name instead (guarded by mutex): a route through a relay

    std::string redirect_for(const std::string& host) {
        const std::scoped_lock lock{mutex};
        return redirect.empty() ? host : redirect;
    }
    void set_redirect(std::string to) {
        const std::scoped_lock lock{mutex};
        redirect = std::move(to);
    }

    void add(const std::shared_ptr<cut_state>& s) {
        const std::scoped_lock lock{mutex};
        std::erase_if(links, [](const auto& w) { return w.expired(); });
        links.push_back(s);
    }

    // Cuts every connection alive now; returns how many.
    int cut_all() {
        std::vector<std::shared_ptr<cut_state>> live;
        {
            const std::scoped_lock lock{mutex};
            for (const auto& w : links) {
                if (auto s = w.lock(); s != nullptr && !s->dead) {
                    live.push_back(std::move(s));
                }
            }
        }
        for (const auto& s : live) {
            s->dead = true;
            s->poster->post([s] {
                if (s->inner != nullptr) {
                    s->inner->close();
                }
            });
        }
        cuts += static_cast<int>(live.size());
        return static_cast<int>(live.size());
    }
};

cut_registry& registry() {
    static cut_registry r;
    return r;
}

class cut_link final : public Rhp::net::link, private Rhp::net::link_handler {
public:
    cut_link(Rhp::net::io_context& io, std::unique_ptr<Rhp::net::link> inner) : inner_(std::move(inner)), state_(std::make_shared<cut_state>()) {
        state_->poster = io.shared_poster();
        state_->inner = inner_.get();
        registry().add(state_);
    }

    ~cut_link() override { state_->inner = nullptr; }

    cut_link(const cut_link&) = delete;
    cut_link& operator=(const cut_link&) = delete;

    void start(Rhp::net::link_handler& h) override {
        handler_ = &h;
        inner_->start(*this);
    }
    void send(Rhp::utils::byte_buffer bytes) override {
        if (!state_->dead) {
            inner_->send(std::move(bytes));
        }
    }
    void close() noexcept override { inner_->close(); }
    [[nodiscard]] std::string peer() const override { return "cut:" + inner_->peer(); }
    [[nodiscard]] bool loopback() const noexcept override { return true; }

private:
    void on_bytes(Rhp::utils::bytes_view data) override {
        if (!state_->dead) {
            handler_->on_bytes(data);
        }
    }
    void on_closed(const Rhp::error& why) override { handler_->on_closed(why); }

    std::unique_ptr<Rhp::net::link> inner_;
    std::shared_ptr<cut_state> state_;
    Rhp::net::link_handler* handler_ = nullptr;
};

struct cuttable {
    static constexpr std::string_view name = "cuttable";

    static Rhp::result<std::unique_ptr<Rhp::net::listener>> listen(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::accept_fn on_accept) {
        return Rhp::net::loopback::listen(io, ep, [&io, on_accept = std::move(on_accept)](std::unique_ptr<Rhp::net::link> l) {
            on_accept(std::make_unique<cut_link>(io, std::move(l)));
        });
    }

    static void dial(Rhp::net::io_context& io, const Rhp::endpoint& ep, Rhp::net::connect_fn on_connect) {
        if (registry().refuse_dials) {
            io.post([on_connect = std::move(on_connect)] { on_connect(Rhp::fail(errc::kTransport, "dials refused by the test", "cuttable")); });
            return;
        }
        Rhp::endpoint target = ep;
        target.host = registry().redirect_for(ep.host);
        Rhp::net::loopback::dial(io, target, [&io, on_connect = std::move(on_connect)](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
            if (!l) {
                on_connect(std::move(l));
                return;
            }
            on_connect(std::unique_ptr<Rhp::net::link>{std::make_unique<cut_link>(io, std::move(*l))});
        });
    }
};

static_assert(Rhp::net::transport<cuttable>);

constexpr Rhp::limits kFast{.heartbeat_ms = 500, .backoff_min_ms = 5, .backoff_max_ms = 40};
using cut_cfg = Rhp::config<>::transport<cuttable>::logger<Rhp::core::null_logger>::limits<kFast>;
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
        (void)host_.template install<s5_lib>();
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
    E at(std::size_t i) {
        const std::scoped_lock lock{mutex};
        return list.at(i);
    }
};

} // namespace stage5_fixtures

using namespace stage5_fixtures;

// ---- resume --------------------------------------------------------------------------------------------

TEST_CASE("stage5: kill the socket mid-traffic and every call still runs exactly once", "[stage5][resume]") {
    keys k;
    g_runs = 0;
    const auto at = Rhp::endpoint::listen("s5.kill", 1);
    pumped_host<cut_cfg> host{at, k.ring(), k.trusted()};
    seen_events<Rhp::event::session_resumed> resumed;
    seen_events<Rhp::event::identity_reverted> reverted;
    auto sub1 = host->on<Rhp::event::session_resumed>(resumed.handler());
    auto sub2 = host->on<Rhp::event::identity_reverted>(reverted.handler());
    Rhp::client<cut_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(c.exec("s5.keep = 42"));

    constexpr int kCalls = 200;
    std::vector<Rhp::pending<int>> calls;
    calls.reserve(kCalls);
    std::jthread cutter{[] {
        for (int cut = 0; cut < 20; ++cut) {
            std::this_thread::sleep_for(25ms);
            registry().cut_all();
        }
    }};
    for (int i = 0; i < kCalls; ++i) {
        calls.push_back(c.async().exec<int>("return s5.bump()"));
        if (i % 20 == 0) {
            std::this_thread::sleep_for(5ms);
        }
    }
    std::set<int> answers;
    int failures = 0;
    for (auto& p : calls) {
        auto r = std::move(p).get();
        if (r) {
            answers.insert(*r);
        } else {
            ++failures;
            UNSCOPED_INFO(std::format("{}", r.error()));
        }
    }
    cutter.join();

    CHECK(failures == 0);
    CHECK(g_runs == kCalls);                                   // nothing ran twice, nothing was lost
    CHECK(answers.size() == static_cast<std::size_t>(kCalls)); // every call got its own run's answer
    CHECK(registry().cuts > 0);
    CHECK(c.info().resumes > 0);
    CHECK(eventually([&] { return resumed.size() > 0; }));
    CHECK(c.exec<int>("return s5.keep") == 42); // the identity was never reverted
    CHECK(reverted.size() == 0);
    CHECK(host->sessions() == 1);
}

TEST_CASE("stage5: a session that can't come back ends after resume_ms and is reverted", "[stage5][resume]") {
    keys k;
    constexpr Rhp::limits kShort{.heartbeat_ms = 500, .resume_ms = 300, .backoff_min_ms = 5, .backoff_max_ms = 20};
    using short_cfg = Rhp::config<>::transport<cuttable>::logger<Rhp::core::null_logger>::limits<kShort>;
    const auto at = Rhp::endpoint::listen("s5.expire", 1);
    pumped_host<short_cfg> host{at, k.ring(), k.trusted()};
    seen_events<Rhp::event::identity_reverted> reverted;
    auto sub = host->on<Rhp::event::identity_reverted>(reverted.handler());
    Rhp::client<short_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(c.exec("s5.keep = 7"));
    registry().refuse_dials = true;
    registry().cut_all();
    const auto started = std::chrono::steady_clock::now();
    auto r = c.exec("return 1");
    registry().refuse_dials = false;
    REQUIRE_FALSE(r);
    CHECK(r.error().code == errc::kTransport);
    CHECK(std::chrono::steady_clock::now() - started >= 250ms);
    CHECK_FALSE(c.connected());
    CHECK(eventually([&] { return reverted.size() == 1; }));
    CHECK(g_keep == 0); // the assignment was undone
}

TEST_CASE("stage5: resume_ms 0 ends a session with its link", "[stage5][resume]") {
    keys k;
    constexpr Rhp::limits kOff{.resume_ms = 0, .backoff_min_ms = 5, .backoff_max_ms = 20};
    using off_cfg = Rhp::config<>::transport<cuttable>::logger<Rhp::core::null_logger>::limits<kOff>;
    const auto at = Rhp::endpoint::listen("s5.noresume", 1);
    pumped_host<off_cfg> host{at, k.ring(), k.trusted()};
    Rhp::client<off_cfg> c{host.dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(c.exec("return 1"));
    registry().cut_all();
    CHECK(eventually([&] { return !c.connected(); }, 2s));
    CHECK(c.exec("return 1").error().code == errc::kTransport);
}

TEST_CASE("stage5: reverse mode resumes too (the host dials back)", "[stage5][resume][reverse]") {
    keys k;
    g_runs = 0;
    const auto at = Rhp::endpoint::listen("s5.reverse", 1);
    Rhp::client<cut_cfg> c{at, k.as("patch"), k.dev()};
    REQUIRE(c.port());
    pumped_host<cut_cfg> host{at.reversed(), k.ring(), k.trusted()};
    REQUIRE(c.connect());
    const auto first = c.info().session;
    for (int round = 0; round < 5; ++round) {
        registry().cut_all();
        CHECK(c.exec<int>("return s5.bump()") == round + 1);
    }
    CHECK(c.info().session == first); // the same session all along
    CHECK(c.info().resumes > 0);
    CHECK(g_runs == 5);
}

// ---- TLS ------------------------------------------------------------------------------------------------

#if RHP_TLS_HAS_OPENSSL || RHP_TLS_HAS_MBEDTLS

TEST_CASE("stage5: TLS over TCP on 127.0.0.1 with require_tls", "[stage5][tls]") {
    keys k;
    pumped_host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls), k.ring(), k.trusted()};
    seen_events<Rhp::event::session_opened> opened;
    auto sub = host->on<Rhp::event::session_opened>(opened.handler());
    const auto port = *host->port();
    Rhp::client<tcp_cfg> c{Rhp::endpoint::dial("127.0.0.1", port, Rhp::net::require_tls), k.as("patch"), k.dev()};
    CHECK(c.exec<int>("return 6 * 7") == 42);
    CHECK(c.info().tls);
    REQUIRE(eventually([&] { return opened.size() == 1; }));
    CHECK(opened.at(0).tls);

    // A plaintext client is refused by a host that requires TLS.
    Rhp::client_options quick;
    quick.connect_timeout = 3s;
    Rhp::client<tcp_cfg> plain{Rhp::endpoint::dial("127.0.0.1", port), k.as("patch"), k.dev(), quick};
    CHECK_FALSE(plain.connect());
}

TEST_CASE("stage5: a loopback host takes TLS and plaintext; the host can bring its own certificate", "[stage5][tls]") {
    keys k;
    Rhp::host_options with_cert;
    with_cert.tls.cert_pem = std::string{rhp_test::tls::kHostCertPem};
    with_cert.tls.key_pem = std::string{rhp_test::tls::kHostKeyPem};
    pumped_host<tcp_cfg> host{Rhp::endpoint::listen("127.0.0.1", 0), k.ring(), k.trusted(), with_cert};
    const auto port = *host->port();

    Rhp::client<tcp_cfg> plain{Rhp::endpoint::dial("127.0.0.1", port), k.as("patch"), k.dev()};
    CHECK(plain.exec<int>("return 1") == 1);
    CHECK_FALSE(plain.info().tls);

    Rhp::client_options verify;
    verify.tls.ca_pem = std::string{rhp_test::tls::kCaPem};
    verify.tls.server_name = "game.test";
    Rhp::client<tcp_cfg> checked{Rhp::endpoint::dial("127.0.0.1", port, Rhp::net::require_tls), k.as("patch"), k.dev(), verify};
    CHECK(checked.exec<int>("return 2") == 2);
    CHECK(checked.info().tls);

    Rhp::client_options wrong;
    wrong.tls.ca_pem = std::string{rhp_test::tls::kOtherCaPem};
    wrong.connect_timeout = 3s;
    Rhp::client<tcp_cfg> distrusting{Rhp::endpoint::dial("127.0.0.1", port, Rhp::net::require_tls), k.as("patch"), k.dev(), wrong};
    CHECK_FALSE(distrusting.connect());
}

TEST_CASE("stage5: TLS over a custom transport, through cuts, still exactly once", "[stage5][tls][resume]") {
    keys k;
    g_runs = 0;
    const auto at = Rhp::endpoint::listen("s5.tls_cut", 1, Rhp::net::require_tls);
    pumped_host<cut_cfg> host{at, k.ring(), k.trusted()};
    Rhp::client<cut_cfg> c{Rhp::endpoint::dial("s5.tls_cut", 1, Rhp::net::require_tls), k.as("patch"), k.dev()};
    REQUIRE(c.connect());
    CHECK(c.info().tls);
    for (int round = 0; round < 10; ++round) {
        auto a = c.async().exec<int>("return s5.bump()");
        registry().cut_all();
        auto b = c.async().exec<int>("return s5.bump()");
        CHECK(std::move(a).get());
        CHECK(std::move(b).get());
    }
    CHECK(g_runs == 20);
    CHECK(c.info().resumes > 0);
    CHECK(c.info().tls);
}

namespace stage5_fixtures {

// A relay that terminates TLS on both sides: it accepts the client's TLS (with its own certificate)
// and opens its own TLS to the host, passing the plaintext along — what a man in the middle with a
// certificate the client doesn't check would do.
class tls_relay final {
public:
    tls_relay(const Rhp::endpoint& front, const Rhp::endpoint& back, bool terminate) : back_(back), terminate_(terminate) {
        auto server = Rhp::security::tls::auto_backend::server({});
        auto client = Rhp::security::tls::auto_backend::client({});
        REQUIRE(server);
        REQUIRE(client);
        server_ = *server;
        client_ = *client;
        auto l = Rhp::net::loopback::listen(io_, front, [this](std::unique_ptr<Rhp::net::link> l) { accept(std::move(l)); });
        REQUIRE(l);
        listener_ = std::move(*l);
        thread_ = std::jthread{[this](std::stop_token stop) { io_.run(std::move(stop)); }};
    }

    ~tls_relay() {
        thread_.request_stop();
        thread_.join();
        pipes_.clear();
        listener_.reset();
    }

    tls_relay(const tls_relay&) = delete;
    tls_relay& operator=(const tls_relay&) = delete;

private:
    struct side final : Rhp::net::link_handler {
        std::unique_ptr<Rhp::net::link> link;
        side* other = nullptr;
        std::vector<Rhp::utils::byte_buffer> held; // until the other side exists

        void on_bytes(Rhp::utils::bytes_view data) override {
            Rhp::utils::byte_buffer b;
            b.append(data);
            if (other != nullptr && other->link != nullptr) {
                other->link->send(std::move(b));
            } else {
                held.push_back(std::move(b));
            }
        }
        void on_closed(const Rhp::error&) override {
            if (other != nullptr && other->link != nullptr) {
                other->link->close();
            }
        }
    };

    struct pipe {
        side front;
        side back;
    };

    void accept(std::unique_ptr<Rhp::net::link> l) {
        auto p = std::make_unique<pipe>();
        pipe& ref = *p;
        pipes_.push_back(std::move(p));
        ref.front.other = &ref.back;
        ref.back.other = &ref.front;
        ref.front.link = terminate_ ? Rhp::session::tls_server(std::move(l), server_, false) : std::move(l);
        ref.front.link->start(ref.front);
        Rhp::net::loopback::dial(io_, back_, [this, &ref](Rhp::result<std::unique_ptr<Rhp::net::link>> b) {
            if (!b) {
                ref.front.link->close();
                return;
            }
            if (terminate_) {
                auto engine = client_->make_engine();
                if (!engine) {
                    ref.front.link->close();
                    return;
                }
                ref.back.link = Rhp::session::tls_client(std::move(*b), std::move(*engine));
            } else {
                ref.back.link = std::move(*b);
            }
            ref.back.link->start(ref.back);
            for (auto& held : ref.front.held) {
                ref.back.link->send(std::move(held));
            }
            ref.front.held.clear();
        });
    }

    Rhp::net::io_context io_;
    Rhp::endpoint back_;
    bool terminate_;
    std::shared_ptr<Rhp::security::tls::context> server_;
    std::shared_ptr<Rhp::security::tls::context> client_;
    std::unique_ptr<Rhp::net::listener> listener_;
    std::vector<std::unique_ptr<pipe>> pipes_;
    std::jthread thread_;
};

} // namespace stage5_fixtures

TEST_CASE("stage5: a relay that terminates TLS can't pass the PSK handshake; a plain relay can", "[stage5][tls][security]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s5.mitm_host", 1, Rhp::net::require_tls);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    Rhp::client_options quick;
    quick.connect_timeout = 5s;
    {
        tls_relay mitm{Rhp::endpoint::listen("s5.mitm_front", 1), Rhp::endpoint::dial("s5.mitm_host", 1), true};
        Rhp::client<loop_cfg> victim{Rhp::endpoint::dial("s5.mitm_front", 1, Rhp::net::require_tls), k.as("patch"), k.dev(), quick};
        auto r = victim.connect();
        REQUIRE_FALSE(r);
        CHECK(r.error().code == errc::kAuth);
    }
    {
        tls_relay dumb{Rhp::endpoint::listen("s5.plain_front", 1), Rhp::endpoint::dial("s5.mitm_host", 1), false};
        Rhp::client<loop_cfg> through{Rhp::endpoint::dial("s5.plain_front", 1, Rhp::net::require_tls), k.as("patch"), k.dev(), quick};
        CHECK(through.exec<int>("return 5") == 5);
        CHECK(through.info().tls);
    }
}

TEST_CASE("stage5: a resume through a relay that terminates TLS is refused; through a plain relay it works", "[stage5][tls][resume][security]") {
    keys k;
    g_runs = 0;
    constexpr Rhp::limits kShort{.heartbeat_ms = 500, .resume_ms = 1'500, .backoff_min_ms = 5, .backoff_max_ms = 40};
    using short_cfg = Rhp::config<>::transport<cuttable>::logger<Rhp::core::null_logger>::limits<kShort>;
    const auto at = Rhp::endpoint::listen("s5.rr_host", 1, Rhp::net::require_tls);
    pumped_host<short_cfg> host{at, k.ring(), k.trusted()};
    seen_events<Rhp::event::session_resumed> resumed;
    auto sub = host->on<Rhp::event::session_resumed>(resumed.handler());
    {
        // The session starts direct; after the cut every dial lands on a TLS-terminating relay.
        tls_relay mitm{Rhp::endpoint::listen("s5.rr_mitm", 1), Rhp::endpoint::dial("s5.rr_host", 1), true};
        Rhp::client<short_cfg> c{Rhp::endpoint::dial("s5.rr_host", 1, Rhp::net::require_tls), k.as("patch"), k.dev()};
        REQUIRE(c.exec<int>("return s5.bump()") == 1);
        registry().set_redirect("s5.rr_mitm");
        registry().cut_all();
        auto r = c.exec<int>("return s5.bump()");
        registry().set_redirect({});
        CHECK_FALSE(r);
        CHECK(resumed.size() == 0);
        CHECK(g_runs == 1); // the call never reached the host through the relay
    }
    {
        tls_relay dumb{Rhp::endpoint::listen("s5.rr_plain", 1), Rhp::endpoint::dial("s5.rr_host", 1), false};
        Rhp::client<short_cfg> c{Rhp::endpoint::dial("s5.rr_host", 1, Rhp::net::require_tls), k.as("patch"), k.dev()};
        REQUIRE(c.exec<int>("return 1") == 1);
        registry().set_redirect("s5.rr_plain");
        registry().cut_all();
        CHECK(c.exec<int>("return s5.bump()") == 2);
        registry().set_redirect({});
        CHECK(c.info().resumes > 0);
        CHECK(eventually([&] { return resumed.size() > 0; }));
    }
}

TEST_CASE("stage5: over TLS the host's goodbye still arrives at once", "[stage5][tls][resume]") {
    keys k;
    auto host = std::make_unique<pumped_host<tcp_cfg>>(Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls), k.ring(), k.trusted());
    const auto port = *(*host)->port();
    Rhp::client<tcp_cfg> c{Rhp::endpoint::dial("127.0.0.1", port, Rhp::net::require_tls), k.as("patch"), k.dev()};
    REQUIRE(c.exec("return 1"));
    const auto started = std::chrono::steady_clock::now();
    host.reset();
    CHECK(eventually([&] { return !c.connected(); }, 3s));
    CHECK(std::chrono::steady_clock::now() - started < 3s);
}

#endif

TEST_CASE("stage5: which connections get TLS", "[stage5][tls][policy]") {
    using Rhp::net::is_loopback_host;
    CHECK(is_loopback_host("127.0.0.1"));
    CHECK(is_loopback_host("127.255.0.9"));
    CHECK(is_loopback_host("::1"));
    CHECK(is_loopback_host("[::1]"));
    CHECK(is_loopback_host("localhost"));
    CHECK(is_loopback_host("::ffff:127.0.0.1"));
    CHECK_FALSE(is_loopback_host("10.0.0.5"));
    CHECK_FALSE(is_loopback_host("0.0.0.0"));
    CHECK_FALSE(is_loopback_host("127.0.0"));
    CHECK_FALSE(is_loopback_host("127.0.0.1.evil.example"));
    CHECK_FALSE(is_loopback_host("game.lan"));

    const auto none = Rhp::security::tls::backend_ops_for<Rhp::security::tls::none>;
    // Without a backend: loopback and insecure_lan work, anything that needs TLS is refused.
    CHECK(Rhp::session::channel_policy::make(Rhp::endpoint::dial("127.0.0.1", 1), true, none, {}));
    CHECK(Rhp::session::channel_policy::make(Rhp::endpoint::dial("10.0.0.5", 1, Rhp::net::insecure_lan), true, none, {}));
    CHECK(Rhp::session::channel_policy::make(Rhp::endpoint::dial("10.0.0.5", 1), true, none, {}).error().code == errc::kForbidden);
    CHECK(Rhp::session::channel_policy::make(Rhp::endpoint::listen("0.0.0.0", 1), true, none, {}).error().code == errc::kForbidden);
    CHECK(Rhp::session::channel_policy::make(Rhp::endpoint::listen("chan", 1, Rhp::net::require_tls), false, none, {}).error().code == errc::kForbidden);
    CHECK(Rhp::session::channel_policy::make(Rhp::endpoint::listen("chan", 1), false, none, {})); // a local transport

#if RHP_TLS_HAS_OPENSSL || RHP_TLS_HAS_MBEDTLS
    const auto tls = Rhp::security::tls::backend_ops_for<Rhp::security::tls::auto_backend>;
    auto remote = Rhp::session::channel_policy::make(Rhp::endpoint::dial("10.0.0.5", 1), true, tls, {});
    REQUIRE(remote);
    CHECK(remote->tls());
    CHECK(remote->transport_endpoint().tls == Rhp::net::tls_mode::kRequire); // so TCP lets it through
    auto local = Rhp::session::channel_policy::make(Rhp::endpoint::dial("127.0.0.1", 1), true, tls, {});
    REQUIRE(local);
    CHECK_FALSE(local->tls());
    auto lan = Rhp::session::channel_policy::make(Rhp::endpoint::dial("10.0.0.5", 1, Rhp::net::insecure_lan), true, tls, {});
    REQUIRE(lan);
    CHECK_FALSE(lan->tls());
    auto any = Rhp::session::channel_policy::make(Rhp::endpoint::listen("0.0.0.0", 1), true, tls, {});
    REQUIRE(any);
    CHECK(any->tls());
#endif
}

TEST_CASE("stage5: a host that shuts down tells its clients at once", "[stage5][resume]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s5.goodbye", 1);
    auto host = std::make_unique<pumped_host<cut_cfg>>(at, k.ring(), k.trusted());
    Rhp::client<cut_cfg> c{host->dial_at(at), k.as("patch"), k.dev()};
    REQUIRE(c.exec("return 1"));
    const auto started = std::chrono::steady_clock::now();
    host.reset();
    CHECK(eventually([&] { return !c.connected(); }, 3s));
    CHECK(std::chrono::steady_clock::now() - started < 3s); // not the resume window plus redials
    CHECK(c.exec("return 1").error().code == errc::kTransport);
}

TEST_CASE("stage5: a peer can't hide a failed login by closing with kOk", "[stage5][security]") {
    keys k;
    const auto at = Rhp::endpoint::listen("s5.kok", 1);
    pumped_host<loop_cfg> host{at, k.ring(), k.trusted()};
    seen_events<Rhp::event::auth_failed> failed;
    auto sub = host->on<Rhp::event::auth_failed>(failed.handler());
    Rhp::net::io_context io;
    std::unique_ptr<Rhp::net::link> raw;
    rhp_test::recorder seen;
    Rhp::net::loopback::dial(io, at.reversed(), [&](Rhp::result<std::unique_ptr<Rhp::net::link>> l) {
        REQUIRE(l);
        raw = std::move(*l);
        raw->start(seen);
    });
    REQUIRE(rhp_test::poll_until({&io}, [&] { return raw != nullptr; }));
    Rhp::utils::byte_buffer payload;
    REQUIRE(Rhp::wire::msgpack::encode(Rhp::to_value(Rhp::make_error(errc::kOk, "nothing to see", "x")), payload));
    Rhp::wire::frame_header h;
    h.code = Rhp::wire::op::kError;
    Rhp::utils::byte_buffer frame;
    REQUIRE(Rhp::wire::encode_frame(h, payload.view(), frame, nullptr, 4096));
    raw->send(std::move(frame));
    rhp_test::poll_for({&io}, 100ms);
    CHECK(eventually([&] { return failed.size() == 1; }));
}
