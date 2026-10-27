#include <memory>
#include <string>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/core/error.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/tcp/tcp.hpp>

using Rhp::endpoint;
using Rhp::errc;
using Rhp::net::io_context;
// Not `using Rhp::net::link`: POSIX declares ::link().
using net_link = Rhp::net::link;
using Rhp::net::tcp;
using rhp_test::buffer_of;
using rhp_test::poll_until;
using rhp_test::recorder;

namespace {

Rhp::result<std::unique_ptr<net_link>> dial(io_context& io, const endpoint& ep) {
    bool done = false;
    Rhp::result<std::unique_ptr<net_link>> out = Rhp::fail(errc::kTimeout, "no dial result");
    tcp::dial(io, ep, [&](Rhp::result<std::unique_ptr<net_link>> r) {
        done = true;
        out = std::move(r);
    });
    (void)poll_until({&io}, [&] { return done; });
    return out;
}

} // namespace

TEST_CASE("tcp: listen on port 0, dial, talk, close", "[net][tcp]") {
    io_context io;
    std::unique_ptr<net_link> accepted;
    auto listener = tcp::listen(io, endpoint::listen("127.0.0.1", 0), [&](std::unique_ptr<net_link> a) { accepted = std::move(a); });
    REQUIRE(listener);
    const auto port = (*listener)->port();
    REQUIRE(port != 0);

    auto dialed = dial(io, endpoint::dial("127.0.0.1", port));
    REQUIRE(dialed);
    REQUIRE(poll_until({&io}, [&] { return accepted != nullptr; }));

    recorder at_host;
    recorder at_client;
    accepted->start(at_host);
    (*dialed)->start(at_client);
    // Larger than one read buffer, to see the stream reassembled.
    const std::string big(200'000, 'z');
    (*dialed)->send(buffer_of(big));
    accepted->send(buffer_of("pong"));
    REQUIRE(poll_until({&io}, [&] { return at_host.received.size() == big.size() && at_client.text() == "pong"; }));
    CHECK(at_host.text() == big);
    CHECK(accepted->peer().starts_with("127.0.0.1:"));

    (*dialed)->send(buffer_of("last words"));
    (*dialed)->close();
    REQUIRE(poll_until({&io}, [&] { return at_host.closed && at_client.closed; }));
    CHECK(at_host.text().ends_with("last words")); // close() writes what is queued first
    CHECK(at_host.reason.code == errc::kTransport);
    CHECK(at_client.reason.code == errc::kOk);
}

TEST_CASE("tcp: localhost and IPv6 loopback are allowed", "[net][tcp]") {
    io_context io;
    auto by_name = tcp::listen(io, endpoint::listen("localhost", 0), [](std::unique_ptr<net_link>) {});
    CHECK(by_name);
    // ::1 may be unavailable (IPv6 disabled); only a kForbidden would be wrong.
    auto v6 = tcp::listen(io, endpoint::listen("::1", 0), [](std::unique_ptr<net_link>) {});
    if (!v6) {
        CHECK(v6.error().code != errc::kForbidden);
    }
}

TEST_CASE("tcp: non-loopback addresses need insecure_lan", "[net][tcp]") {
    io_context io;
    auto any = tcp::listen(io, endpoint::listen("0.0.0.0", 0), [](std::unique_ptr<net_link>) {});
    REQUIRE_FALSE(any);
    CHECK(any.error().code == errc::kForbidden);
    auto lan = tcp::listen(io, endpoint::listen("0.0.0.0", 0, Rhp::net::insecure_lan), [](std::unique_ptr<net_link>) {});
    CHECK(lan);

    auto remote = dial(io, endpoint::dial("192.0.2.1", 9)); // TEST-NET-1: never routed
    REQUIRE_FALSE(remote);
    CHECK(remote.error().code == errc::kForbidden);
}

TEST_CASE("tcp: a port in use and a closed port fail cleanly", "[net][tcp]") {
    io_context io;
    auto first = tcp::listen(io, endpoint::listen("127.0.0.1", 0), [](std::unique_ptr<net_link>) {});
    REQUIRE(first);
    const auto port = (*first)->port();
    auto second = tcp::listen(io, endpoint::listen("127.0.0.1", port), [](std::unique_ptr<net_link>) {});
    REQUIRE_FALSE(second);
    CHECK(second.error().code == errc::kTransport);

    first->reset();
    auto refused = dial(io, endpoint::dial("127.0.0.1", port));
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == errc::kTransport);
}
