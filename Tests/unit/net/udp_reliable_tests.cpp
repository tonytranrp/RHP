#include <chrono>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/datagram_relay.hpp>
#include <rhp_test/net_support.hpp>
#include <rhp_test/stream_roundtrip.hpp>

#include <rhp/net/udp_reliable/detail/packet.hpp>
#include <rhp/net/udp_reliable/udp_reliable.hpp>

namespace rudp = Rhp::net::detail::rudp;

TEST_CASE("udp_reliable: packets round trip and corruption is detected", "[net][udp_reliable]") {
    const rudp::packet_header header{rudp::packet_kind::kData, 0x1234, 7, 6, 0b101};
    Rhp::utils::byte_buffer packet;
    rudp::encode_packet(packet, header, Rhp::utils::as_bytes("payload"));
    CHECK(packet.size() == rudp::kHeaderBytes + 7 + rudp::kTrailerBytes);
    const auto decoded = rudp::decode_packet(packet.view());
    REQUIRE(decoded);
    CHECK(decoded->header.kind == rudp::packet_kind::kData);
    CHECK(decoded->header.token == 0x1234);
    CHECK(decoded->header.seq == 7);
    CHECK(decoded->header.ack == 6);
    CHECK(decoded->header.sack == 0b101);
    CHECK(decoded->payload.size() == 7);
    for (std::size_t i = 0; i < packet.size(); ++i) {
        auto flipped = packet;
        flipped.mutable_view()[i] ^= std::byte{0x10};
        CHECK_FALSE(rudp::decode_packet(flipped.view()));
    }
    CHECK_FALSE(rudp::decode_packet(packet.view().first(packet.size() - 1)));
    Rhp::utils::byte_buffer ack_with_payload;
    rudp::encode_packet(ack_with_payload, {rudp::packet_kind::kAck, 1, 0, 0, 0}, Rhp::utils::as_bytes("x"));
    CHECK_FALSE(rudp::decode_packet(ack_with_payload.view()));
    Rhp::utils::byte_buffer zero_token;
    rudp::encode_packet(zero_token, {rudp::packet_kind::kHello, 0, 0, 0, 0});
    CHECK_FALSE(rudp::decode_packet(zero_token.view()));
}

TEST_CASE("udp_reliable: ordered stream and close", "[net][udp_reliable]") {
    rhp_test::stream_roundtrip<Rhp::net::udp_reliable>(Rhp::endpoint::listen("127.0.0.1", 0));
}

TEST_CASE("udp_reliable: close drains final bytes after the owner releases the link", "[net][udp_reliable]") {
    rhp_test::stream_roundtrip<Rhp::net::udp_reliable>(Rhp::endpoint::listen("127.0.0.1", 0), true);
}

TEST_CASE("udp_reliable: non-loopback addresses need insecure_lan or TLS", "[net][udp_reliable]") {
    Rhp::net::io_context io;
    auto refused = Rhp::net::udp_reliable::listen(io, Rhp::endpoint::listen("0.0.0.0", 0), [](auto) {});
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == Rhp::errc::kForbidden);
}

TEST_CASE("udp_reliable: recovers loss corruption duplication and reordering", "[net][udp_reliable]") {
    Rhp::net::io_context io;
    std::unique_ptr<Rhp::net::link> accepted;
    auto listener = Rhp::net::udp_reliable::listen(io, Rhp::endpoint::listen("127.0.0.1", 0), [&](auto link) { accepted = std::move(link); });
    REQUIRE(listener);
    rhp_test::datagram_faults faults;
    faults.drop_data = true;
    faults.corrupt = true;
    faults.duplicate = true;
    faults.reorder = true;
    faults.drop_fin_ack = true;
    rhp_test::datagram_relay relay{io, (*listener)->port(), faults};
    std::unique_ptr<Rhp::net::link> client;
    Rhp::net::udp_reliable::dial(io, Rhp::endpoint::dial("127.0.0.1", relay.port()), [&](auto result) { REQUIRE(result); client = std::move(*result); });
    REQUIRE(rhp_test::poll_until({&io}, [&] { return accepted && client; }));
    rhp_test::recorder host;
    rhp_test::recorder at_client;
    accepted->start(host);
    // Bytes arriving before start() must survive the transport's packet processing.
    accepted->send(rhp_test::buffer_of("before-start"));
    rhp_test::poll_for({&io}, std::chrono::milliseconds{20});
    client->start(at_client);
    REQUIRE(rhp_test::poll_until({&io}, [&] { return at_client.text() == "before-start"; }));
    const std::string bytes(100000, 'z');
    client->send(rhp_test::buffer_of(bytes));
    REQUIRE(rhp_test::poll_until({&io}, [&] { return host.text() == bytes; }, std::chrono::seconds{20}));
    client->close();
    REQUIRE(rhp_test::poll_until({&io}, [&] { return host.closed; }));
    accepted.reset(); // lost FIN ACK is answered even after the handler/link is gone
    REQUIRE(rhp_test::poll_until({&io}, [&] { return at_client.closed; }));
    CHECK(at_client.reason.code == Rhp::errc::kOk);
}


TEST_CASE("udp_reliable: a dialed receiver answers a FIN whose ACK was lost", "[net][udp_reliable]") {
    Rhp::net::io_context io;
    std::unique_ptr<Rhp::net::link> accepted;
    auto listener = Rhp::net::udp_reliable::listen(io, Rhp::endpoint::listen("127.0.0.1", 0), [&](auto link) { accepted = std::move(link); });
    REQUIRE(listener);
    rhp_test::datagram_faults faults;
    faults.drop_fin_ack = true;
    rhp_test::datagram_relay relay{io, (*listener)->port(), faults};
    std::unique_ptr<Rhp::net::link> client;
    Rhp::net::udp_reliable::dial(io, Rhp::endpoint::dial("127.0.0.1", relay.port()), [&](auto result) { REQUIRE(result); client = std::move(*result); });
    REQUIRE(rhp_test::poll_until({&io}, [&] { return accepted && client; }));
    rhp_test::recorder host;
    rhp_test::recorder at_client;
    accepted->start(host);
    client->start(at_client);
    accepted->send(rhp_test::buffer_of("last bytes"));
    accepted->close();
    REQUIRE(rhp_test::poll_until({&io}, [&] { return at_client.closed; }));
    CHECK(at_client.text() == "last bytes");
    client.reset();
    REQUIRE(rhp_test::poll_until({&io}, [&] { return host.closed; }));
    CHECK(host.reason.code == Rhp::errc::kOk);
}

