#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/datagram_relay.hpp>
#include <rhp_test/net_support.hpp>
#include <rhp_test/stream_roundtrip.hpp>

#include <rhp/net/udp_reliable/detail/cookie.hpp>
#include <rhp/net/udp_reliable/detail/packet.hpp>
#include <rhp/net/udp_reliable/udp_reliable.hpp>
#include <rhp/utils/crc32c.hpp>

namespace rudp = Rhp::net::detail::rudp;

TEST_CASE("udp_reliable: SipHash-2-4 matches the reference vectors", "[net][udp_reliable][cookie]") {
    rudp::cookie_key key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(i);
    }
    std::array<std::byte, 15> message{};
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::byte>(i);
    }
    // The paper's example (15 bytes) and the first and ninth entries of its vectors.h.
    CHECK(rudp::siphash24(key, message) == 0xa129'ca61'49be'45e5u);
    CHECK(rudp::siphash24(key, {}) == 0x726f'db47'dd0e'0e31u);
    CHECK(rudp::siphash24(key, Rhp::utils::bytes_view{message}.first(8)) == 0x93f5'f579'9a93'2462u);
}

TEST_CASE("udp_reliable: cookies are bound to the source and live one to two periods", "[net][udp_reliable][cookie]") {
    const auto t0 = std::chrono::steady_clock::now();
    auto jar = rudp::cookie_jar::make(t0);
    REQUIRE(jar);
    const rudp::hello_source from{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}, 50'000, 0x1234};
    const std::uint64_t cookie = jar->issue(t0, from);
    CHECK(jar->valid(t0, from, cookie));
    CHECK_FALSE(jar->valid(t0, from, cookie + 1));
    CHECK_FALSE(jar->valid(t0, from, 0));
    auto other_port = from;
    other_port.port = 50'001;
    auto other_token = from;
    other_token.token = 0x1235;
    auto other_address = from;
    other_address.address[15] = 2;
    CHECK_FALSE(jar->valid(t0, other_port, cookie));
    CHECK_FALSE(jar->valid(t0, other_token, cookie));
    CHECK_FALSE(jar->valid(t0, other_address, cookie));
    // The next period still takes it (and issues a new one); the one after doesn't.
    const auto period = rudp::cookie_jar::kCookiePeriod;
    CHECK(jar->valid(t0 + period + std::chrono::seconds{1}, from, cookie));
    const std::uint64_t later = jar->issue(t0 + period + std::chrono::seconds{1}, from);
    CHECK(later != cookie);
    CHECK_FALSE(jar->valid(t0 + 2 * period + std::chrono::seconds{1}, from, cookie));
    CHECK(jar->valid(t0 + 2 * period + std::chrono::seconds{1}, from, later));
    // A jump of several periods forgets everything.
    CHECK_FALSE(jar->valid(t0 + 9 * period, from, later));
    // Another listener's secret makes other cookies.
    auto other = rudp::cookie_jar::make(t0);
    REQUIRE(other);
    CHECK(other->issue(t0, from) != cookie);
}

TEST_CASE("udp_reliable: a Hello without its cookie creates nothing", "[net][udp_reliable][cookie]") {
    Rhp::net::io_context io;
    int accepted = 0;
    std::unique_ptr<Rhp::net::link> kept;
    auto listener = Rhp::net::udp_reliable::listen(io, Rhp::endpoint::listen("127.0.0.1", 0), [&](auto link) {
        ++accepted;
        kept = std::move(link);
    });
    REQUIRE(listener);
    const auto port = (*listener)->port();
    const auto hello = [](std::uint64_t token, std::uint64_t cookie) {
        Rhp::utils::byte_buffer packet;
        rudp::encode_packet(packet, {rudp::packet_kind::kHello, token, 0, cookie, 0});
        return packet;
    };
    // The kind of reply that came back last, and the cookie it carried.
    const auto last = [](const rhp_test::datagram_probe& probe) {
        const auto decoded = rudp::decode_packet(probe.received().back().view());
        REQUIRE(decoded);
        return decoded->header;
    };
    rhp_test::datagram_probe probe{io};
    probe.send(port, hello(77, 0).view());
    REQUIRE(rhp_test::poll_until({&io}, [&] { return probe.received().size() == 1; }));
    const auto offer = last(probe);
    CHECK(offer.kind == rudp::packet_kind::kCookie);
    CHECK(offer.token == 77);
    CHECK(offer.ack != 0);
    // A wrong cookie, or the right one from another port (a spoofer that guessed it), gets another offer.
    probe.send(port, hello(77, offer.ack + 1).view());
    REQUIRE(rhp_test::poll_until({&io}, [&] { return probe.received().size() == 2; }));
    CHECK(last(probe).kind == rudp::packet_kind::kCookie);
    rhp_test::datagram_probe elsewhere{io};
    elsewhere.send(port, hello(77, offer.ack).view());
    REQUIRE(rhp_test::poll_until({&io}, [&] { return elsewhere.received().size() == 1; }));
    CHECK(last(elsewhere).kind == rudp::packet_kind::kCookie);
    rhp_test::poll_for({&io}, std::chrono::milliseconds{20});
    CHECK(accepted == 0);
    // Echoed from where it was sent: Welcome, and a link.
    probe.send(port, hello(77, offer.ack).view());
    REQUIRE(rhp_test::poll_until({&io}, [&] { return accepted == 1; }));
    REQUIRE(rhp_test::poll_until({&io}, [&] { return probe.received().size() == 3; }));
    CHECK(last(probe).kind == rudp::packet_kind::kWelcome);
    CHECK(kept->address() == Rhp::net::ip_address::v4(127, 0, 0, 1));
    // A Hello of revision 1 (which had no cookies) is dropped unanswered.
    Rhp::utils::byte_buffer old = hello(78, 0);
    old.mutable_view()[4] = std::byte{1};
    const auto body = old.view().first(old.size() - rudp::kTrailerBytes);
    Rhp::utils::store_le<std::uint32_t>(old.mutable_view().last<rudp::kTrailerBytes>(), Rhp::utils::crc32c(body));
    rhp_test::datagram_probe ancient{io};
    ancient.send(port, old.view());
    rhp_test::poll_for({&io}, std::chrono::milliseconds{50});
    CHECK(ancient.received().empty());
}

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
