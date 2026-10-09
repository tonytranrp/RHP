#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/core/error.hpp>
#include <rhp/net/endpoint.hpp>
#include <rhp/net/io_context.hpp>
#include <rhp/net/link.hpp>
#include <rhp/net/loopback/loopback.hpp>

using Rhp::endpoint;
using Rhp::errc;
using Rhp::net::io_context;
// Not `using Rhp::net::link`: POSIX declares ::link().
using net_link = Rhp::net::link;
using Rhp::net::loopback;
using rhp_test::buffer_of;
using rhp_test::poll_until;
using rhp_test::recorder;

namespace {

struct pair {
    io_context host_io;
    io_context client_io;
    std::unique_ptr<Rhp::net::listener> listener;
    std::unique_ptr<net_link> accepted;
    std::unique_ptr<net_link> dialed;
    Rhp::error dial_error;
    bool dial_done = false;

    explicit pair(const std::string& name) {
        auto l = loopback::listen(host_io, endpoint::listen(name, 1), [this](std::unique_ptr<net_link> a) { accepted = std::move(a); });
        REQUIRE(l);
        listener = std::move(*l);
        loopback::dial(client_io, endpoint::dial(name, 1), [this](Rhp::result<std::unique_ptr<net_link>> d) {
            dial_done = true;
            if (d) {
                dialed = std::move(*d);
            } else {
                dial_error = d.error();
            }
        });
        REQUIRE(poll_until({&host_io, &client_io}, [this] { return accepted != nullptr && dialed != nullptr; }));
    }
};

} // namespace

TEST_CASE("loopback: bytes flow both ways in order", "[net][loopback]") {
    pair p{"loopback_tests.flow"};
    recorder at_host;
    recorder at_client;
    p.accepted->start(at_host);
    p.dialed->start(at_client);
    p.dialed->send(buffer_of("hel"));
    p.dialed->send(buffer_of("lo"));
    p.accepted->send(buffer_of("world"));
    REQUIRE(poll_until({&p.host_io, &p.client_io}, [&] { return at_host.text() == "hello" && at_client.text() == "world"; }));
    CHECK(p.accepted->peer().starts_with("loopback:"));
}

TEST_CASE("loopback: bytes sent before start() are kept", "[net][loopback]") {
    pair p{"loopback_tests.early"};
    p.dialed->send(buffer_of("early"));
    rhp_test::poll_for({&p.host_io, &p.client_io}, std::chrono::milliseconds{20});
    recorder at_host;
    p.accepted->start(at_host);
    REQUIRE(poll_until({&p.host_io, &p.client_io}, [&] { return at_host.text() == "early"; }));
}

TEST_CASE("loopback: close reaches the peer after queued bytes", "[net][loopback]") {
    pair p{"loopback_tests.close"};
    recorder at_host;
    recorder at_client;
    p.accepted->start(at_host);
    p.dialed->start(at_client);
    p.dialed->send(buffer_of("bye"));
    p.dialed->close();
    REQUIRE(poll_until({&p.host_io, &p.client_io}, [&] { return at_host.closed && at_client.closed; }));
    CHECK(at_host.text() == "bye");
    CHECK(at_host.reason.code == errc::kTransport);
    CHECK(at_client.reason.code == errc::kOk);
    p.accepted->send(buffer_of("ignored")); // after the peer closed: dropped, no crash
}

TEST_CASE("loopback: destroying one end closes the other", "[net][loopback]") {
    pair p{"loopback_tests.destroy"};
    recorder at_host;
    p.accepted->start(at_host);
    p.dialed.reset();
    REQUIRE(poll_until({&p.host_io, &p.client_io}, [&] { return at_host.closed; }));
    CHECK(at_host.reason.code == errc::kTransport);
}

TEST_CASE("loopback: channel names are exclusive and must exist", "[net][loopback]") {
    io_context io;
    auto first = loopback::listen(io, endpoint::listen("loopback_tests.names", 1), [](std::unique_ptr<net_link>) {});
    REQUIRE(first);
    auto second = loopback::listen(io, endpoint::listen("loopback_tests.names", 1), [](std::unique_ptr<net_link>) {});
    REQUIRE_FALSE(second);
    CHECK(second.error().code == errc::kAlreadyLoaded);
    auto other_port = loopback::listen(io, endpoint::listen("loopback_tests.names", 2), [](std::unique_ptr<net_link>) {});
    CHECK(other_port);

    Rhp::error err;
    bool done = false;
    loopback::dial(io, endpoint::dial("loopback_tests.nobody", 1), [&](Rhp::result<std::unique_ptr<net_link>> r) {
        done = true;
        if (!r) {
            err = r.error();
        }
    });
    REQUIRE(poll_until({&io}, [&] { return done; }));
    CHECK(err.code == errc::kNotFound);

    first->reset(); // the name is free again
    CHECK(loopback::listen(io, endpoint::listen("loopback_tests.names", 1), [](std::unique_ptr<net_link>) {}));
}

TEST_CASE("loopback: ends on two threads", "[net][loopback]") {
    pair p{"loopback_tests.threads"};
    recorder at_client;
    p.dialed->start(at_client);
    std::string expected;
    for (int i = 0; i < 200; ++i) {
        expected += std::to_string(i) + ",";
    }
    // The host end lives on another thread from here on.
    std::jthread host_thread{[&p](std::stop_token stop) {
        recorder at_host;
        p.accepted->start(at_host);
        for (int i = 0; i < 200; ++i) {
            p.accepted->send(buffer_of(std::to_string(i) + ","));
        }
        p.host_io.run(stop);
        p.accepted.reset(); // destroyed on its own thread
    }};
    REQUIRE(poll_until({&p.client_io}, [&] { return at_client.text() == expected; }));
    host_thread.request_stop();
    host_thread.join();
    REQUIRE(poll_until({&p.client_io}, [&] { return at_client.closed; }));
}
