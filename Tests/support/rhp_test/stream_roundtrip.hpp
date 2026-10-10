#pragma once

#include <format>
#include <memory>
#include <string>

#include <catch2/catch_message.hpp>
#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>

#include <rhp/net/endpoint.hpp>

namespace rhp_test {

// A transport's byte-stream contract end to end: dial a listener, move a large message and a small
// one each way, then close. With `release_on_close` the dialer drops its link right after close():
// the transport must still deliver the final bytes.
template <Rhp::net::transport T>
void stream_roundtrip(Rhp::endpoint ep, bool release_on_close = false) {
    Rhp::net::io_context io;
    std::unique_ptr<Rhp::net::link> accepted;
    auto listener = T::listen(io, ep, [&](std::unique_ptr<Rhp::net::link> l) { accepted = std::move(l); });
    const auto setup = listener ? std::string{"listener ok"} : std::format("{}", listener.error());
    INFO(setup);
    REQUIRE(listener);
    ep.port = (*listener)->port();
    Rhp::result<std::unique_ptr<Rhp::net::link>> connected = Rhp::fail(Rhp::errc::kTimeout);
    bool done = false;
    T::dial(io, ep.reversed(), [&](auto r) {
        connected = std::move(r);
        done = true;
    });
    REQUIRE(poll_until({&io}, [&] { return done && accepted != nullptr; }));
    REQUIRE(connected);
    recorder host;
    recorder client;
    accepted->start(host);
    (*connected)->start(client);
    const std::string big(200000, 'x');
    (*connected)->send(buffer_of(big));
    (*connected)->send(buffer_of("last"));
    accepted->send(buffer_of("reply"));
    REQUIRE(poll_until({&io}, [&] { return host.received.size() == big.size() + 4 && client.text() == "reply"; }));
    CHECK(host.text() == big + "last");
    CHECK(accepted->loopback());
    (*connected)->send(buffer_of("goodbye"));
    (*connected)->close();
    if (release_on_close) {
        connected->reset();
    }
    REQUIRE(poll_until({&io}, [&] { return host.closed && (release_on_close || client.closed); }));
    CHECK(host.text() == big + "lastgoodbye");
}

} // namespace rhp_test
