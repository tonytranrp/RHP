#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/net/address.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/security/tls/auto_backend.hpp>
#include <rhp/security/tls/tls.hpp>
#include <rhp/session/secure_link.hpp>

using namespace std::chrono_literals;
using Rhp::endpoint;
using Rhp::errc;
using Rhp::net::ip_address;
using Rhp::session::channel_policy;

namespace channel_policy_fixtures {

// A link from a given address; the test makes it deliver bytes. on_closed is posted, as for real links.
class policy_link final : public Rhp::net::link {
public:
    policy_link(Rhp::net::io_context& io, std::optional<ip_address> from, bool on_this_machine = false) : io_(io), from_(from), loopback_(on_this_machine) {}

    void start(Rhp::net::link_handler& handler) override { handler_ = &handler; }
    void send(Rhp::utils::byte_buffer) override {}
    void close() noexcept override {
        if (!closed_ && handler_ != nullptr) {
            closed_ = true;
            io_.post([h = handler_] { h->on_closed({}); });
        }
    }
    [[nodiscard]] std::string peer() const override { return "fake:1"; }
    [[nodiscard]] bool loopback() const noexcept override { return loopback_; }
    [[nodiscard]] std::optional<ip_address> address() const noexcept override { return from_; }

    void deliver(std::string_view text) { handler_->on_bytes(Rhp::utils::as_bytes(text)); }

private:
    Rhp::net::io_context& io_;
    std::optional<ip_address> from_;
    bool loopback_ = false;
    bool closed_ = false;
    Rhp::net::link_handler* handler_ = nullptr;
};

constexpr auto kNone = Rhp::security::tls::backend_ops_for<Rhp::security::tls::none>;

[[nodiscard]] Rhp::result<std::unique_ptr<Rhp::net::link>> wrap(const channel_policy& policy, Rhp::net::io_context& io, std::optional<ip_address> from,
                                                                bool on_this_machine = false) {
    return policy.wrap(std::unique_ptr<Rhp::net::link>{std::make_unique<policy_link>(io, from, on_this_machine)});
}

} // namespace channel_policy_fixtures

using namespace channel_policy_fixtures;

TEST_CASE("channel_policy: insecure_lan dials only local literal addresses", "[session][tls][policy]") {
    for (const std::string_view local : {"10.0.0.5", "172.16.0.1", "192.168.1.20", "169.254.10.1", "fd00::1", "fe80::1", "[fe80::1]", "printer.lan"}) {
        INFO(local);
        CHECK(channel_policy::make(endpoint::dial(local, 7777, Rhp::net::insecure_lan), true, kNone, {}));
    }
    for (const std::string_view far : {"8.8.8.8", "203.0.113.9", "100.64.0.1", "2001:db8::1", "[2001:db8::1]"}) {
        INFO(far);
        const auto refused = channel_policy::make(endpoint::dial(far, 7777, Rhp::net::insecure_lan), true, kNone, {});
        REQUIRE_FALSE(refused);
        CHECK(refused.error().code == errc::kForbidden);
        CHECK(refused.error().message.find("insecure_lan") != std::string::npos);
    }
    // Local transports and loopback are plaintext anyway.
    CHECK(channel_policy::make(endpoint::dial("8.8.8.8", 1, Rhp::net::insecure_lan), false, kNone, {}));
    CHECK(channel_policy::make(endpoint::dial("127.0.0.1", 1, Rhp::net::insecure_lan), true, kNone, {}));
}

TEST_CASE("channel_policy: an insecure_lan dial that resolved to a public address is refused", "[session][tls][policy]") {
    Rhp::net::io_context io;
    const auto policy = channel_policy::make(endpoint::dial("printer.lan", 7777, Rhp::net::insecure_lan), true, kNone, {});
    REQUIRE(policy);
    CHECK(wrap(*policy, io, ip_address::v4(192, 168, 1, 20)));
    CHECK(wrap(*policy, io, ip_address::v4(127, 0, 0, 1)));
    const auto far = wrap(*policy, io, ip_address::v4(203, 0, 113, 9));
    REQUIRE_FALSE(far);
    CHECK(far.error().code == errc::kForbidden);
    CHECK(far.error().message.find("insecure_lan") != std::string::npos);
    CHECK_FALSE(wrap(*policy, io, ip_address::v4(100, 64, 0, 1)));
    CHECK_FALSE(wrap(*policy, io, std::nullopt)); // a transport that doesn't say where: not local
    CHECK(wrap(*policy, io, std::nullopt, true)); // ... unless the link is on this machine
}

TEST_CASE("channel_policy: an insecure_lan listener takes plaintext only from local peers", "[session][tls][policy]") {
    Rhp::net::io_context io;
    SECTION("without TLS a peer elsewhere is refused at once") {
        const auto policy = channel_policy::make(endpoint::listen("0.0.0.0", 7777, Rhp::net::insecure_lan), true, kNone, {});
        REQUIRE(policy);
        CHECK(wrap(*policy, io, ip_address::v4(10, 1, 2, 3)));
        CHECK(wrap(*policy, io, ip_address::parse("fe80::2")));
        CHECK(wrap(*policy, io, std::nullopt, true));
        const auto far = wrap(*policy, io, ip_address::v4(8, 8, 4, 4));
        REQUIRE_FALSE(far);
        CHECK(far.error().code == errc::kForbidden);
        CHECK(far.error().message.find("insecure_lan") != std::string::npos);
        CHECK_FALSE(wrap(*policy, io, ip_address::v4(100, 100, 1, 1)));
        CHECK_FALSE(wrap(*policy, io, std::nullopt));
    }
    SECTION("a local transport and a loopback address take anyone") {
        const auto local = channel_policy::make(endpoint::listen("chan", 1, Rhp::net::insecure_lan), false, kNone, {});
        REQUIRE(local);
        CHECK(wrap(*local, io, ip_address::v4(8, 8, 4, 4)));
    }
#if RHP_TLS_HAS_OPENSSL || RHP_TLS_HAS_MBEDTLS
    SECTION("with TLS a peer elsewhere must start TLS") {
        const auto tls = Rhp::security::tls::backend_ops_for<Rhp::security::tls::auto_backend>;
        const auto policy = channel_policy::make(endpoint::listen("0.0.0.0", 7777, Rhp::net::insecure_lan), true, tls, {});
        REQUIRE(policy);
        CHECK(policy->tls());
        auto far = std::make_unique<policy_link>(io, ip_address::v4(8, 8, 4, 4));
        policy_link* raw = far.get();
        auto wrapped = policy->wrap(std::unique_ptr<Rhp::net::link>{std::move(far)});
        REQUIRE(wrapped);
        rhp_test::recorder seen;
        (*wrapped)->start(seen);
        raw->deliver("RHP plaintext");
        REQUIRE(rhp_test::poll_until({&io}, [&] { return seen.closed; }));
        CHECK(seen.reason.code == errc::kForbidden);
        CHECK(seen.reason.message.find("insecure_lan") != std::string::npos);
        CHECK(seen.received.empty());

        auto near = std::make_unique<policy_link>(io, ip_address::v4(192, 168, 0, 7));
        policy_link* near_raw = near.get();
        auto near_wrapped = policy->wrap(std::unique_ptr<Rhp::net::link>{std::move(near)});
        REQUIRE(near_wrapped);
        rhp_test::recorder near_seen;
        (*near_wrapped)->start(near_seen);
        near_raw->deliver("RHP plaintext");
        CHECK(near_seen.text() == "RHP plaintext");
        CHECK_FALSE(near_seen.closed);
    }
#endif
}
