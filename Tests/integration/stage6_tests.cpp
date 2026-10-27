#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/net/detail/http.hpp>
#include <rhp/rhp.hpp>
#include <rhp/security/tls/auto_backend.hpp>
#include <rhp/session/secure_link.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace stage6_fixtures {

std::atomic<int> counter{0};
int bump(int by) {
    counter.fetch_add(by);
    return by;
}
void unbump(int by) {
    counter.fetch_sub(by);
}
int read() {
    return counter.load();
}
using lib = Rhp::lib<"stage6">::fn<"bump", &bump, Rhp::undo<&unbump>>::fn<"value", &read>;

struct keys {
    Rhp::security::key secret = *Rhp::security::key::generate();
    Rhp::security::ed25519_secret_key developer = *Rhp::security::ed25519_secret_key::generate();
    Rhp::security::keyring ring() const { return {{"patch", secret, Rhp::role::kPatch}, {"observe", secret, Rhp::role::kObserve}, {"admin", secret, Rhp::role::kAdmin}}; }
    Rhp::security::psk_identity identity() const { return {"patch", secret}; }
    Rhp::security::trusted_signers trust() const { return {{"dev", developer.public_key()}}; }
    Rhp::security::signing_key signing() const { return {"dev", developer}; }
    // The X-RHP-Signature header for `source`.
    std::string signature(std::string_view source) const {
        auto signed_by = signing().sign(source);
        REQUIRE(signed_by);
        auto header = Rhp::security::http_signature_header(*signed_by);
        REQUIRE(header);
        return *header;
    }
};

template <Rhp::configuration Cfg>
struct running_host {
    Rhp::host<Cfg> host;
    std::jthread pump;
    running_host(const keys& key, Rhp::endpoint ep = Rhp::endpoint::listen("127.0.0.1", 0), Rhp::host_options options = {}, std::optional<Rhp::net::advertise_options> advertise = {})
        : host(ep, key.ring(), key.trust(), std::move(options)) {
        const auto port = host.port();
        const auto setup = port ? std::string{"host ok"} : std::format("{}", port.error());
        INFO(setup);
        REQUIRE(port);
        REQUIRE(host.template install<lib>());
        if (advertise) {
            REQUIRE(host.advertise(std::move(*advertise)));
        }
        pump = std::jthread{[this](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host.pump();
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
        }};
    }
    ~running_host() {
        pump.request_stop();
        pump.join();
    }
};

using cfg = Rhp::config<>::logger<Rhp::core::null_logger>;

// A TCP address that stays bound for the whole test: until open_to() it drops every connection
// (a dial that reaches nobody), then it relays each one to the given local port. No port number
// is ever released and bound again, so another process can't take it in between.
class tcp_gate final {
public:
    tcp_gate() {
        auto l = Rhp::net::tcp::listen(io_, Rhp::endpoint::listen("127.0.0.1", 0), [this](std::unique_ptr<Rhp::net::link> link) { accept(std::move(link)); });
        REQUIRE(l);
        listener_ = std::move(*l);
        thread_ = std::jthread{[this](std::stop_token stop) { io_.run(std::move(stop)); }};
    }

    ~tcp_gate() {
        thread_.request_stop();
        thread_.join();
        pipes_.clear();
        listener_.reset();
    }

    tcp_gate(const tcp_gate&) = delete;
    tcp_gate& operator=(const tcp_gate&) = delete;

    [[nodiscard]] std::uint16_t port() const { return static_cast<std::uint16_t>(listener_->port()); }
    void open_to(std::uint16_t target) { target_.store(target); }

private:
    struct side final : Rhp::net::link_handler {
        std::unique_ptr<Rhp::net::link> link;
        side* other = nullptr;
        std::vector<Rhp::utils::byte_buffer> held; // until the other side is connected

        void on_bytes(Rhp::utils::bytes_view data) override {
            Rhp::utils::byte_buffer b;
            b.append(data);
            if (other->link != nullptr) {
                other->link->send(std::move(b));
            } else {
                held.push_back(std::move(b));
            }
        }
        void on_closed(const Rhp::error&) override {
            if (other->link != nullptr) {
                other->link->close();
            }
        }
    };

    struct pipe {
        side front;
        side back;
    };

    // On the gate's thread.
    void accept(std::unique_ptr<Rhp::net::link> link) {
        const std::uint16_t target = target_.load();
        if (target == 0) {
            return; // destroyed: the dialer sees the connection drop
        }
        auto p = std::make_unique<pipe>();
        pipe& ref = *p;
        pipes_.push_back(std::move(p));
        ref.front.other = &ref.back;
        ref.back.other = &ref.front;
        ref.front.link = std::move(link);
        ref.front.link->start(ref.front);
        Rhp::net::tcp::dial(io_, Rhp::endpoint::dial("127.0.0.1", target), [&ref](Rhp::result<std::unique_ptr<Rhp::net::link>> back) {
            if (!back) {
                ref.front.link->close();
                return;
            }
            ref.back.link = std::move(*back);
            ref.back.link->start(ref.back);
            for (auto& held : ref.front.held) {
                ref.back.link->send(std::move(held));
            }
            ref.front.held.clear();
        });
    }

    Rhp::net::io_context io_;
    std::atomic<std::uint16_t> target_{0};
    std::unique_ptr<Rhp::net::listener> listener_;
    std::vector<std::unique_ptr<pipe>> pipes_;
    std::jthread thread_;
};

template <Rhp::net::transport T>
void authenticated_transport(Rhp::endpoint ep) {
    using transport_cfg = cfg::transport<T>;
    keys key;
    running_host<transport_cfg> server{key, ep};
    auto port = server.host.port();
    REQUIRE(port);
    Rhp::client<transport_cfg> client{ep.reversed().with_port(*port), key.identity(), key.signing()};
    REQUIRE(client.connect());
    auto module = client.load("tests.stage6.transport", "stage6.bump(3); return { get = function() return stage6.value() end }");
    REQUIRE(module);
    CHECK(counter.load() == 3);
    auto result = client.call(*module, "get");
    REQUIRE(result);
    REQUIRE(result->size() == 1);
    CHECK(*Rhp::from_value<int>(result->front()) == 3);
    REQUIRE(client.unload(*module));
    CHECK(counter.load() == 0);
    Rhp::client<transport_cfg> unsigned_client{ep.reversed().with_port(*port), key.identity()};
    auto refused = unsigned_client.template exec<int>("return 1");
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == Rhp::errc::kBadSignature);
}

template <Rhp::net::transport T>
void reverse_transport(Rhp::endpoint ep) {
    using transport_cfg = cfg::transport<T>;
    keys key;
    Rhp::client<transport_cfg> client{ep, key.identity(), key.signing()};
    auto port = client.port();
    const auto setup = port ? std::string{"client listener ok"} : std::format("{}", port.error());
    INFO(setup);
    REQUIRE(port);
    running_host<transport_cfg> server{key, ep.reversed().with_port(*port)};
    REQUIRE(client.connect());
    auto result = client.template exec<int>("return 42");
    REQUIRE(result);
    CHECK(*result == 42);
}

struct http_result {
    unsigned status = 0;
    Rhp::value body;
    std::string proof;     // X-RHP-Proof
    bool verified = false; // the proof checks out for this request (security::verify_http_answer)
};

// A host clock a test can move: steady_clock plus an offset (config<>::clock).
inline std::atomic<std::int64_t> g_clock_shift_ms{0};
struct shifted_clock {
    [[nodiscard]] std::chrono::steady_clock::time_point now() const noexcept {
        return std::chrono::steady_clock::now() + std::chrono::milliseconds{g_clock_shift_ms.load()};
    }
};

// A TLS client context that doesn't check the host's certificate (the case channel binding is for).
[[nodiscard]] std::unique_ptr<Rhp::net::link> tls_over(std::unique_ptr<Rhp::net::link> plain) {
    static const auto context = [] {
        auto c = Rhp::security::tls::auto_backend::client({});
        REQUIRE(c);
        return *c;
    }();
    auto engine = context->make_engine();
    REQUIRE(engine);
    return Rhp::session::tls_client(std::move(plain), std::move(*engine));
}

struct http_call {
    std::string_view method = "POST";
    std::string_view target = "/exec";
    std::string_view body = {};
    bool sign = true;
    std::string identity = "patch";
    std::string_view content_type = "text/plain";
    std::string_view request_token = {}; // X-RHP-Request
    std::string* reuse_proof = nullptr;  // first call stores its Authorization, later calls resend it
    bool tls = false;                    // TLS without checking the certificate
    bool bind = false;                   // X-RHP-Channel: tls-exporter (needs tls)
};

// One raw HTTP/1.1 exchange with the host's gateway.
class http_client {
public:
    http_client(unsigned short port, const keys& key, const http_call& call) : identity_{call.identity, key.secret} {
        Rhp::net::tcp::dial(io_, Rhp::endpoint::dial("127.0.0.1", port), [&](auto connected) {
            REQUIRE(connected);
            link_ = call.tls ? tls_over(std::move(*connected)) : std::move(*connected);
        });
        REQUIRE(rhp_test::poll_until({&io_}, [&] { return link_ != nullptr; }));
        link_->start(response_);
        if (call.tls) {
            // The binding exists once the handshake finished.
            REQUIRE(rhp_test::poll_until({&io_}, [&] { return !link_->channel_binding().empty() || response_.closed; }));
            REQUIRE_FALSE(response_.closed);
        }
        const auto signature = call.sign ? key.signature(call.body) : std::string{};
        const std::string_view channel = call.bind ? Rhp::security::kHttpChannelTlsExporter : std::string_view{};
        const Rhp::security::http_proof proof{{}, call.method, call.target, signature, call.content_type, Rhp::utils::as_bytes(call.body), channel, call.bind ? link_->channel_binding() : std::span<const std::byte>{}};
        auto authorization = Rhp::security::http_authorization(identity_, proof);
        REQUIRE(authorization);
        if (call.reuse_proof != nullptr) {
            if (call.reuse_proof->empty()) {
                *call.reuse_proof = *authorization;
            } else {
                authorization = *call.reuse_proof;
            }
        }
        Rhp::utils::byte_buffer request;
        request.append(std::format("{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {}\r\nContent-Length: {}\r\nAuthorization: {}\r\n", call.method, call.target,
                                   call.content_type, call.body.size(), *authorization));
        if (!signature.empty()) {
            request.append(std::format("X-RHP-Signature: {}\r\n", signature));
        }
        if (!call.request_token.empty()) {
            request.append(std::format("X-RHP-Request: {}\r\n", call.request_token));
        }
        if (call.bind) {
            request.append(std::format("X-RHP-Channel: {}\r\n", channel));
        }
        authorization_ = *authorization;
        request.append("\r\n");
        request.append(call.body);
        link_->send(std::move(request));
    }

    // Runs `meanwhile` while waiting, then parses the answer.
    http_result finish(const std::function<void()>& meanwhile = {}) {
        REQUIRE(rhp_test::poll_until({&io_}, [&] {
            if (!response_.closed && meanwhile) {
                meanwhile();
            }
            return response_.closed;
        }));
        auto head = Rhp::net::detail::parse_http_head(response_.text(), 4u << 20);
        REQUIRE(head);
        REQUIRE(*head);
        const auto& parsed = **head;
        const auto space = parsed.first_line.find(' ');
        REQUIRE(space != std::string::npos);
        const auto status = static_cast<unsigned>(std::stoi(parsed.first_line.substr(space + 1, 3)));
        const auto bytes = response_.received.view().subspan(parsed.bytes, parsed.content_length);
        http_result out{status, {}, std::string{parsed.header("x-rhp-proof")}, false};
        out.verified = Rhp::security::verify_http_answer(identity_, authorization_, {status, parsed.header("content-type"), bytes}, out.proof).has_value();
        if (parsed.content_length != 0) {
            auto body = Rhp::wire::msgpack::decode(bytes);
            REQUIRE(body);
            out.body = std::move(*body);
        }
        return out;
    }

    // Hangs up without waiting for the answer.
    void abandon() { link_.reset(); }

private:
    Rhp::security::psk_identity identity_;
    std::string authorization_;
    Rhp::net::io_context io_;
    std::unique_ptr<Rhp::net::link> link_;
    rhp_test::recorder response_;
};

// A TCP relay in front of the host's HTTP port. `terminate`: it accepts the client's TLS with its
// own certificate and opens its own TLS to the host (a man in the middle the client doesn't
// detect without checking certificates). `tamper`: it flips the last byte of every answer chunk.
class http_relay final {
public:
    http_relay(unsigned short host_port, bool terminate, bool tamper) : host_port_(host_port), terminate_(terminate), tamper_(tamper) {
        auto server = Rhp::security::tls::auto_backend::server({});
        REQUIRE(server);
        server_ = *server;
        auto l = Rhp::net::tcp::listen(io_, Rhp::endpoint::listen("127.0.0.1", 0), [this](std::unique_ptr<Rhp::net::link> l) { accept(std::move(l)); });
        REQUIRE(l);
        listener_ = std::move(*l);
        thread_ = std::jthread{[this](std::stop_token stop) { io_.run(std::move(stop)); }};
    }

    ~http_relay() {
        thread_.request_stop();
        thread_.join();
        pipes_.clear();
        listener_.reset();
    }

    http_relay(const http_relay&) = delete;
    http_relay& operator=(const http_relay&) = delete;

    [[nodiscard]] unsigned short port() const { return listener_->port(); }

private:
    struct side final : Rhp::net::link_handler {
        std::unique_ptr<Rhp::net::link> link;
        side* other = nullptr;
        bool tamper = false;
        std::vector<std::byte> answer;             // tamper: the whole answer, changed when it ends
        std::vector<Rhp::utils::byte_buffer> held; // until the other side exists

        void on_bytes(Rhp::utils::bytes_view data) override {
            if (data.empty()) {
                return; // a TLS handshake finished
            }
            if (tamper) {
                answer.insert(answer.end(), data.begin(), data.end());
                return;
            }
            Rhp::utils::byte_buffer b;
            b.append(data);
            if (other != nullptr && other->link != nullptr) {
                other->link->send(std::move(b));
            } else {
                held.push_back(std::move(b));
            }
        }
        void on_closed(const Rhp::error&) override {
            if (other == nullptr || other->link == nullptr) {
                return;
            }
            if (!answer.empty()) {
                answer.back() ^= std::byte{0x01}; // the last byte of the body
                Rhp::utils::byte_buffer b;
                b.append(std::span<const std::byte>{answer});
                other->link->send(std::move(b));
            }
            other->link->close();
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
        ref.back.tamper = tamper_;
        ref.front.link = terminate_ ? Rhp::session::tls_server(std::move(l), server_, false) : std::move(l);
        ref.front.link->start(ref.front);
        Rhp::net::tcp::dial(io_, Rhp::endpoint::dial("127.0.0.1", host_port_), [this, &ref](Rhp::result<std::unique_ptr<Rhp::net::link>> b) {
            if (!b) {
                ref.front.link->close();
                return;
            }
            ref.back.link = terminate_ ? tls_over(std::move(*b)) : std::move(*b);
            ref.back.link->start(ref.back);
            for (auto& held : ref.front.held) {
                ref.back.link->send(std::move(held));
            }
            ref.front.held.clear();
        });
    }

    unsigned short host_port_;
    bool terminate_;
    bool tamper_;
    Rhp::net::io_context io_;
    std::shared_ptr<Rhp::security::tls::context> server_;
    std::unique_ptr<Rhp::net::listener> listener_;
    std::vector<std::unique_ptr<pipe>> pipes_;
    std::jthread thread_;
};

http_result http(unsigned short port, const keys& key, const http_call& call, const std::function<void()>& meanwhile = {}) {
    http_client client{port, key, call};
    return client.finish(meanwhile);
}

} // namespace stage6_fixtures

TEST_CASE("stage6: signed scripts over WebSocket and UDP", "[integration][stage6]") {
    stage6_fixtures::authenticated_transport<Rhp::net::websocket>(Rhp::endpoint::listen("127.0.0.1", 0));
    stage6_fixtures::authenticated_transport<Rhp::net::udp_reliable>(Rhp::endpoint::listen("127.0.0.1", 0));
}

TEST_CASE("stage6: authenticated local IPC", "[integration][stage6][ipc]") {
    const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto name = Rhp::platform::kOs == Rhp::platform::os_kind::kWindows ? "rhp-stage6-" + unique : Rhp::platform::kOs == Rhp::platform::os_kind::kAndroid ? "@rhp-stage6-" + unique
                                                                                                                                                               : (std::filesystem::temp_directory_path() / ("rhp-" + unique)).string();
    SECTION("normal mode") {
        stage6_fixtures::authenticated_transport<Rhp::net::local_ipc>(Rhp::endpoint::listen(name, 0));
    }
    SECTION("reverse mode") {
        stage6_fixtures::reverse_transport<Rhp::net::local_ipc>(Rhp::endpoint::listen(name, 0));
    }
}

TEST_CASE("stage6: HTTP shares identities and completes suspended requests", "[integration][stage6][http]") {
    using namespace stage6_fixtures;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    auto port = server.host.gateway_port();
    REQUIRE(port);
    auto loaded = http(*port, key, {.target = "/modules/tests.http.shared", .body = "stage6.bump(7); return { get = function() return stage6.value() end }"});
    REQUIRE(loaded.status == 200);
    Rhp::client<cfg> client{Rhp::endpoint::dial("127.0.0.1", *server.host.port()), key.identity(), key.signing()};
    auto shared = client.call("tests.http.shared", "get");
    REQUIRE(shared);
    CHECK(*Rhp::from_value<int>(shared->front()) == 7);
    auto yielded = http(*port, key, {.body = "rhp.next_frame(); return stage6.value()"});
    REQUIRE(yielded.status == 200);
    CHECK(yielded.verified); // a suspended request's late answer is signed too
    REQUIRE(yielded.body.is_array());
    CHECK(*Rhp::from_value<int>(yielded.body.get_if<Rhp::value::array>()->front()) == 7);
    CHECK(http(*port, key, {.body = "return 1", .sign = false}).status == 403);
    CHECK(http(*port, key, {.body = "stage6.bump(1)", .sign = false, .identity = "observe"}).status == 403);
    Rhp::utils::byte_buffer args;
    REQUIRE(Rhp::wire::msgpack::encode(Rhp::value::array{}, args));
    const std::string arguments{reinterpret_cast<const char*>(args.view().data()), args.size()};
    auto called = http(*port, key, {.target = "/modules/tests.http.shared/call/get", .body = arguments, .sign = false, .content_type = "application/msgpack; charset=binary"});
    REQUIRE(called.status == 200);
    CHECK(*Rhp::from_value<int>(called.body.get_if<Rhp::value::array>()->front()) == 7);
    auto bad_signer = key;
    bad_signer.developer = *Rhp::security::ed25519_secret_key::generate();
    CHECK(http(*port, bad_signer, {.body = "return 1"}).status == 403);
    std::string proof;
    CHECK(http(*port, key, {.method = "GET", .target = "/modules", .sign = false, .reuse_proof = &proof}).status == 200);
    CHECK(http(*port, key, {.method = "GET", .target = "/modules", .sign = false, .reuse_proof = &proof}).status == 401);
    REQUIRE(http(*port, key, {.target = "/modules/tests.http.shared", .body = "stage6.bump(2); rhp.next_frame(); return { get = function() return stage6.value() end }"}).status == 200);
    auto reloaded = client.call("tests.http.shared", "get");
    REQUIRE(reloaded);
    REQUIRE(reloaded->size() == 1);
    CHECK(*Rhp::from_value<int>(reloaded->front()) == 2);
    CHECK(http(*port, key, {.method = "GET", .target = "/modules/tests.http.shared", .sign = false}).status == 200);
    CHECK(http(*port, key, {.target = "/modules/tests.http.shared/revert", .sign = false}).status == 200);
    CHECK(counter.load() == 0);
    CHECK(http(*port, key, {.method = "DELETE", .target = "/modules/tests.http.shared", .sign = false}).status == 200);
    CHECK(counter.load() == 0);
}

TEST_CASE("stage6: HTTP answers carry a proof for their own request", "[integration][stage6][http][security]") {
    using namespace stage6_fixtures;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    const auto ok = http(*port, key, {.body = "return 42"});
    CHECK(ok.status == 200);
    CHECK_FALSE(ok.proof.empty());
    CHECK(ok.verified);
    // Refusals after the proof checked out are signed as well.
    const auto refused = http(*port, key, {.body = "return 1", .sign = false});
    CHECK(refused.status == 403);
    CHECK(refused.verified);
    const auto missing = http(*port, key, {.method = "GET", .target = "/nowhere", .sign = false});
    CHECK(missing.status == 404);
    CHECK(missing.verified);
    // Without a valid proof there is no answer key: nothing to sign with.
    std::string proof;
    REQUIRE(http(*port, key, {.method = "GET", .target = "/modules", .sign = false, .reuse_proof = &proof}).verified);
    const auto replayed = http(*port, key, {.method = "GET", .target = "/modules", .sign = false, .reuse_proof = &proof});
    CHECK(replayed.status == 401);
    CHECK(replayed.proof.empty());
    CHECK_FALSE(replayed.verified);
}

TEST_CASE("stage6: HTTP channel binding refuses a relay that terminates TLS", "[integration][stage6][http][tls][security]") {
    using namespace stage6_fixtures;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls);
    running_host<cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    // Direct: the client's exporter value is the host's.
    const auto direct = http(*port, key, {.body = "return 42", .tls = true, .bind = true});
    CHECK(direct.status == 200);
    CHECK(direct.verified);
    {
        // A relay with its own certificate: two TLS connections, two bindings.
        http_relay mitm{*port, true, false};
        const auto bound = http(mitm.port(), key, {.body = "stage6.bump(1); return 1", .tls = true, .bind = true});
        CHECK(bound.status == 401);
        CHECK_FALSE(bound.verified);
        CHECK(counter.load() == 0); // nothing ran
        // Unbound, the request gets through, and so does an honest answer.
        const auto unbound = http(mitm.port(), key, {.body = "return 42", .tls = true});
        CHECK(unbound.status == 200);
        CHECK(unbound.verified);
    }
    {
        // A relay that changes the answer: the proof gives it away.
        http_relay forger{*port, true, true};
        const auto forged = http(forger.port(), key, {.body = "return 42", .tls = true});
        CHECK(forged.status == 200);
        CHECK_FALSE(forged.verified);
        REQUIRE(forged.body.is_array());
        CHECK(*Rhp::from_value<int>(forged.body.get_if<Rhp::value::array>()->front()) == 43);
    }
    // A plain relay passes TLS through untouched: binding still matches end to end.
    http_relay plain{*port, false, false};
    const auto passed = http(plain.port(), key, {.body = "return 42", .tls = true, .bind = true});
    CHECK(passed.status == 200);
    CHECK(passed.verified);
}

TEST_CASE("stage6: HTTP idle expiry follows the host clock", "[integration][stage6][http]") {
    using namespace stage6_fixtures;
    using clock_cfg = cfg::clock<shifted_clock>::limits<Rhp::limits{.gateway_idle_ms = 3'600'000}>;
    g_clock_shift_ms = 0;
    const Rhp::utils::scope_guard unshift{[] { g_clock_shift_ms = 0; }};
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<clock_cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    std::atomic<int> http_closed{0};
    auto watch = server.host.on<Rhp::event::session_closed>([&](const Rhp::event::session_closed& e) {
        if (e.peer == "http") {
            http_closed.fetch_add(1);
        }
    });
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    REQUIRE(http(*port, key, {.target = "/modules/tests.http.clocked", .body = "stage6.bump(4); return {}"}).status == 200);
    CHECK(counter.load() == 4);
    rhp_test::poll_for({}, std::chrono::milliseconds{100});
    CHECK(http_closed.load() == 0); // an hour of idle time hasn't passed on the host's clock
    g_clock_shift_ms = 2 * 3'600'000;
    // Expired and reverted without waiting an hour (the revert runs just after session_closed).
    REQUIRE(rhp_test::poll_until({}, [&] { return http_closed.load() == 1 && counter.load() == 0; }, std::chrono::seconds{3}));
    // Proof freshness stays on the system clock: a client signing with real time is still accepted.
    const auto fresh = http(*port, key, {.body = "return 1"});
    CHECK(fresh.status == 200);
    CHECK(fresh.verified);
}

TEST_CASE("stage6: a host can require channel-bound HTTP proofs", "[integration][stage6][http][tls][security]") {
    using namespace stage6_fixtures;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls);
    options.http_require_binding = true;
    running_host<cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    std::atomic<int> refused{0};
    auto watch = server.host.on<Rhp::event::auth_failed>([&](const Rhp::event::auth_failed&) { refused.fetch_add(1); });
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    const auto unbound = http(*port, key, {.body = "stage6.bump(1); return 1", .tls = true});
    CHECK(unbound.status == 401);
    CHECK(unbound.verified); // a genuine refusal, signed for the request it refuses
    CHECK(counter.load() == 0);
    CHECK(rhp_test::poll_until({}, [&] { return refused.load() == 1; })); // and audited as one
    const auto bound = http(*port, key, {.body = "return 42", .tls = true, .bind = true});
    CHECK(bound.status == 200);
    CHECK(bound.verified);
}

TEST_CASE("stage6: HTTP audit records name the caller of each request", "[integration][stage6][http][audit]") {
    using namespace stage6_fixtures;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    std::mutex mutex;
    std::vector<Rhp::event::script_executed> scripts;
    std::vector<Rhp::event::session_opened> opened;
    auto s1 = server.host.on<Rhp::event::script_executed>([&](const Rhp::event::script_executed& e) {
        const std::scoped_lock lock{mutex};
        scripts.push_back(e);
    });
    auto s2 = server.host.on<Rhp::event::session_opened>([&](const Rhp::event::session_opened& e) {
        const std::scoped_lock lock{mutex};
        opened.push_back(e);
    });
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    REQUIRE(http(*port, key, {.body = "return 1"}).status == 200);
    REQUIRE(http(*port, key, {.body = "return 2"}).status == 200);
    REQUIRE(rhp_test::poll_until({}, [&] {
        const std::scoped_lock lock{mutex};
        return scripts.size() == 2;
    }));
    const std::scoped_lock lock{mutex};
    REQUIRE(opened.size() == 1); // one logical session for the key
    CHECK(scripts[0].session == scripts[1].session);
    CHECK(scripts[0].peer.starts_with("127.0.0.1:"));
    CHECK(scripts[1].peer.starts_with("127.0.0.1:"));
    CHECK(scripts[0].peer != scripts[1].peer); // two connections, two callers
    CHECK(scripts[0].peer == opened[0].peer);
}

TEST_CASE("stage6: TLS is preserved over WebSocket and reliable UDP", "[integration][stage6][tls]") {
    stage6_fixtures::authenticated_transport<Rhp::net::websocket>(Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls));
    stage6_fixtures::authenticated_transport<Rhp::net::udp_reliable>(Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls));
}

TEST_CASE("stage6: reverse mode preserves TLS and WebSocket roles", "[integration][stage6][tls]") {
    stage6_fixtures::reverse_transport<Rhp::net::websocket>(Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls));
    stage6_fixtures::reverse_transport<Rhp::net::udp_reliable>(Rhp::endpoint::listen("127.0.0.1", 0, Rhp::net::require_tls));
}

TEST_CASE("stage6: HTTP cancels an abandoned request and expires the idle identity", "[integration][stage6][http]") {
    using namespace stage6_fixtures;
    using idle_cfg = cfg::limits<Rhp::limits{.gateway_idle_ms = 150}>;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<idle_cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    std::atomic<int> http_closed{0};
    auto watch = server.host.on<Rhp::event::session_closed>([&](const Rhp::event::session_closed& e) {
        if (e.peer == "http") {
            http_closed.fetch_add(1);
        }
    });
    auto port = server.host.gateway_port();
    REQUIRE(port);
    {
        // Longer than the idle limit while connected: the identity stays (a request is in flight).
        http_client slow{*port, key, {.body = "stage6.bump(5); rhp.sleep(400); return 1"}};
        const auto done = slow.finish();
        CHECK(done.status == 200);
        CHECK(http_closed.load() == 0);
    }
    // Then idle: session_closed is published before the identity's revert runs, so wait for both.
    REQUIRE(rhp_test::poll_until({}, [&] { return http_closed.load() == 1 && counter.load() == 0; }, std::chrono::seconds{3}));
    http_client abandoned{*port, key, {.body = "stage6.bump(5); rhp.sleep(60000); return 1"}};
    REQUIRE(rhp_test::poll_until({}, [&] { return counter.load() == 5; }, std::chrono::seconds{3}));
    abandoned.abandon();
    REQUIRE(rhp_test::poll_until({}, [&] { return http_closed.load() == 2 && counter.load() == 0; }, std::chrono::seconds{3}));
}

// A host with HTTP requests in flight and no native session goes away: they are answered.
template <Rhp::configuration Cfg>
void shutdown_answers_http() {
    using namespace stage6_fixtures;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    auto server = std::make_unique<running_host<Cfg>>(key, Rhp::endpoint::listen("127.0.0.1", 0), options);
    const auto port = server->host.gateway_port();
    REQUIRE(port);
    http_client waiting{*port, key, {.body = "stage6.bump(5); rhp.sleep(60000); return 1"}};
    REQUIRE(rhp_test::poll_until({}, [&] { return counter.load() == 5; }, std::chrono::seconds{3}));
    server.reset(); // no native session is open: the goodbye still waits for the gateway's answers
    const auto answer = waiting.finish();
    CHECK(answer.status == 500);
    CHECK(answer.verified);
    const auto err = Rhp::from_value<Rhp::error>(answer.body);
    REQUIRE(err);
    CHECK(err->code == Rhp::errc::kTransport);
    CHECK(err->message == "the host is shutting down");
    CHECK(counter.load() == 0);
}

TEST_CASE("stage6: a host shutting down answers the HTTP requests in flight", "[integration][stage6][http]") {
    SECTION("with its own I/O thread") {
        shutdown_answers_http<stage6_fixtures::cfg>();
    }
    SECTION("with zero threads") {
        shutdown_answers_http<stage6_fixtures::cfg::io<Rhp::exec::zero_threads>>();
    }
}

TEST_CASE("stage6: authenticated HTTP requests release the handshake budget", "[integration][stage6][http]") {
    using namespace stage6_fixtures;
    using small_cfg = cfg::limits<Rhp::limits{.pending_handshakes = 1}>;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<small_cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    bool cancelled = false;
    auto result = http(*port, key, {.body = "stage6.bump(5); rhp.sleep(60000); return 1", .request_token = "long-job"}, [&] {
        if (!cancelled && counter.load() == 5) {
            cancelled = true;
            CHECK(http(*port, key, {.method = "GET", .target = "/describe", .sign = false}).status == 200);
            CHECK(http(*port, key, {.target = "/cancel/no-such-job", .sign = false}).status == 404);
            CHECK(http(*port, key, {.target = "/cancel/long-job", .sign = false}).status == 200);
        }
    });
    REQUIRE(cancelled);
    auto err = Rhp::from_value<Rhp::error>(result.body);
    REQUIRE(err);
    CHECK(err->code == Rhp::errc::kCancelled);
    CHECK(counter.load() == 0);
}

TEST_CASE("stage6: HTTP expiry preserves another session of the identity", "[integration][stage6][http]") {
    using namespace stage6_fixtures;
    using idle_cfg = cfg::limits<Rhp::limits{.gateway_idle_ms = 150}>;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<idle_cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    std::atomic<int> http_closed{0};
    auto watch = server.host.on<Rhp::event::session_closed>([&](const Rhp::event::session_closed& e) {
        if (e.peer == "http") {
            http_closed.fetch_add(1);
        }
    });
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    {
        Rhp::client<cfg> native{Rhp::endpoint::dial("127.0.0.1", *server.host.port()), key.identity(), key.signing()};
        REQUIRE(native.connect());
        REQUIRE(http(*port, key, {.target = "/modules/tests.http.retained", .body = "stage6.bump(7); return { get = function() return stage6.value() end }"}).status == 200);
        REQUIRE(rhp_test::poll_until({}, [&] { return http_closed.load() == 1; }, std::chrono::seconds{3}));
        auto retained = native.call("tests.http.retained", "get");
        REQUIRE(retained);
        REQUIRE(retained->size() == 1);
        CHECK(*Rhp::from_value<int>(retained->front()) == 7);
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
    while (counter.load() != 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    CHECK(counter.load() == 0);
}

TEST_CASE("stage6: HTTP expiry preserves pinned modules", "[integration][stage6][http]") {
    using namespace stage6_fixtures;
    using idle_cfg = cfg::limits<Rhp::limits{.gateway_idle_ms = 150}>;
    keys key;
    Rhp::host_options options;
    options.gateway = Rhp::endpoint::listen("127.0.0.1", 0);
    running_host<idle_cfg> server{key, Rhp::endpoint::listen("127.0.0.1", 0), options};
    std::atomic<int> http_closed{0};
    auto watch = server.host.on<Rhp::event::session_closed>([&](const Rhp::event::session_closed& e) {
        if (e.peer == "http") {
            http_closed.fetch_add(1);
        }
    });
    const auto port = server.host.gateway_port();
    REQUIRE(port);
    {
        Rhp::client<cfg> admin{Rhp::endpoint::dial("127.0.0.1", *server.host.port()), Rhp::security::psk_identity{"admin", key.secret}, key.signing()};
        REQUIRE(admin.connect());
        REQUIRE(http(*port, key, {.target = "/modules/tests.http.pinned", .body = "stage6.bump(9); return { get = function() return stage6.value() end }", .identity = "admin"}).status == 200);
        REQUIRE(admin.pin("tests.http.pinned"));
    }
    REQUIRE(rhp_test::poll_until({}, [&] { return http_closed.load() == 1; }, std::chrono::seconds{3}));
    CHECK(counter.load() == 9);
    Rhp::client<cfg> admin{Rhp::endpoint::dial("127.0.0.1", *server.host.port()), Rhp::security::psk_identity{"admin", key.secret}, key.signing()};
    auto retained = admin.call("tests.http.pinned", "get");
    REQUIRE(retained);
    REQUIRE(retained->size() == 1);
    CHECK(*Rhp::from_value<int>(retained->front()) == 9);
    REQUIRE(admin.unpin("tests.http.pinned"));
    REQUIRE(admin.unload("tests.http.pinned"));
    CHECK(counter.load() == 0);
}

TEST_CASE("stage6: fleet retains a fast result alongside a slow deadline", "[integration][stage6][fleet]") {
    using namespace stage6_fixtures;
    keys key;
    running_host<cfg> fast{key};
    running_host<cfg> slow{key};
    Rhp::client<cfg> seed{Rhp::endpoint::dial("127.0.0.1", *slow.host.port()), key.identity(), key.signing()};
    REQUIRE(seed.exec("slow = true"));
    Rhp::fleet_options options;
    options.timeout = std::chrono::milliseconds{1500};
    Rhp::fleet<cfg::errors<Rhp::errors::throwing>> fleet{key.identity(), key.signing(), options};
    Rhp::net::service_record record;
    record.address = "127.0.0.1";
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    record.name = "fast";
    record.port = *fast.host.port();
    REQUIRE_NOTHROW(fleet.add(record));
    record.name = "slow";
    record.port = *slow.host.port();
    REQUIRE_NOTHROW(fleet.add(record));
    auto results = fleet.exec<int>("if slow then rhp.sleep(60000) end; return 42");
    REQUIRE(results.size() == 2);
    REQUIRE(results.front().outcome);
    CHECK(*results.front().outcome == 42);
    REQUIRE_FALSE(results.back().outcome);
    CHECK(results.back().outcome.error().code == Rhp::errc::kTimeout);
}

TEST_CASE("stage6: fleet preserves errors deadlines and terminal recovery", "[integration][stage6][fleet]") {
    using namespace stage6_fixtures;
    keys key;
    running_host<cfg> live{key};
    Rhp::net::service_record record;
    record.name = "live";
    record.address = "127.0.0.1";
    record.port = *live.host.port();
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    Rhp::fleet_options options;
    options.timeout = std::chrono::milliseconds{1500}; // the last broadcast waits it out
    Rhp::fleet<cfg> fleet{key.identity(), key.signing(), options};
    REQUIRE(fleet.add(record));
    // A held address that drops connections makes the dial fail; later it leads to a real host.
    tcp_gate gate;
    record.name = "recover";
    record.port = gate.port();
    REQUIRE(fleet.add(record));
    auto mixed = fleet.exec<int>("return 42");
    REQUIRE(mixed.size() == 2);
    CHECK(mixed.front().outcome);
    CHECK_FALSE(mixed.back().outcome);
    REQUIRE(mixed.back().outcome.error().code == Rhp::errc::kTransport);
    running_host<cfg> recovered{key};
    gate.open_to(*recovered.host.port());
    REQUIRE(fleet.add(record));
    auto results = fleet.exec<int>("return 43");
    REQUIRE(results.size() == 2);
    for (const auto& result : results) {
        const auto diagnostic = result.outcome ? std::string{"ok"} : std::format("{}: {}", result.host.name, result.outcome.error());
        INFO(diagnostic);
        REQUIRE(result.outcome);
        CHECK(*result.outcome == 43);
    }
    auto timeout = fleet.exec<int>("rhp.sleep(60000); return 1");
    REQUIRE(timeout.size() == 2);
    REQUIRE_FALSE(timeout.front().outcome);
    REQUIRE_FALSE(timeout.back().outcome);
    CHECK(timeout.front().outcome.error().code == Rhp::errc::kTimeout);
    CHECK(timeout.back().outcome.error().code == Rhp::errc::kTimeout);
}

TEST_CASE("stage6: zero-thread fleet progresses all members during discovery", "[integration][stage6][fleet][multicast]") {
    using namespace stage6_fixtures;
    using short_cfg = cfg::io<Rhp::exec::zero_threads>::discovery<Rhp::net::mdns_wire>::limits<Rhp::limits{.heartbeat_ms = 100, .heartbeat_misses = 3, .resume_ms = 200}>;
    keys key;
    using host_cfg = cfg::discovery<Rhp::net::mdns_wire>::limits<Rhp::limits{.heartbeat_ms = 100, .heartbeat_misses = 3, .resume_ms = 200}>;
    running_host<host_cfg> server{key};
    Rhp::net::service_record record;
    record.name = "zero";
    record.address = "127.0.0.1";
    record.port = *server.host.port();
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    Rhp::fleet<short_cfg> fleet{key.identity(), key.signing()};
    REQUIRE(fleet.add(record));
    auto initial = fleet.exec<int>("stage6.bump(1); return stage6.value()");
    REQUIRE(initial.size() == 1);
    REQUIRE(initial.front().outcome);
    Rhp::net::browse_options browse;
    browse.app = "no-such-test-application";
    browse.duration = std::chrono::milliseconds{750};
    REQUIRE(fleet.discover(browse));
    CHECK(counter.load() == 1);
    auto after = fleet.exec<int>("return stage6.value()");
    REQUIRE(after.front().outcome);
    CHECK(*after.front().outcome == 1);
}

TEST_CASE("stage6: fleet discovers and collects every signed result", "[integration][stage6][fleet][multicast]") {
    using namespace stage6_fixtures;
    using discovered_cfg = cfg::discovery<Rhp::net::mdns_wire>;
    keys key;
    const auto app = "fleet-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    Rhp::net::advertise_options a;
    a.name = "fleet-first";
    a.app = app;
    Rhp::net::advertise_options b = a;
    b.name = "fleet-second";
    running_host<discovered_cfg> first{key, Rhp::endpoint::listen("127.0.0.1", 0), {}, a};
    running_host<discovered_cfg> second{key, Rhp::endpoint::listen("127.0.0.1", 0), {}, b};
    Rhp::fleet<discovered_cfg> fleet{key.identity(), key.signing()};
    Rhp::net::browse_options browse;
    browse.app = app;
    browse.duration = std::chrono::milliseconds{2000};
    auto discovered = fleet.discover(browse);
    REQUIRE(discovered);
    REQUIRE(fleet.size() == 2);
    auto results = fleet.exec<int>("return 42");
    REQUIRE(results.size() == 2);
    for (const auto& entry : results) {
        REQUIRE(entry.outcome);
        CHECK(*entry.outcome == 42);
        CHECK(entry.host.libs.empty()); // explicit library-name opt-in is separate
    }
    CHECK(first.host.discovery_status());
    CHECK(second.host.discovery_status());
}
