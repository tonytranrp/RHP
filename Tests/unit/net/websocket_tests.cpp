#include <array>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <rhp_test/net_support.hpp>
#include <rhp_test/stream_roundtrip.hpp>

#include <rhp/net/tcp/tcp.hpp>
#include <rhp/net/websocket/detail/protocol.hpp>
#include <rhp/net/websocket/websocket.hpp>

namespace {

namespace ws = Rhp::net::detail::ws;

Rhp::utils::bytes_view bytes_of(std::string_view text) {
    return Rhp::utils::as_bytes(text);
}

// True when the codec refuses this frame start (padded so length fields are never "incomplete").
bool refused(std::initializer_list<unsigned char> head, ws::role from) {
    std::vector<std::byte> bytes;
    for (const auto b : head) {
        bytes.push_back(std::byte{b});
    }
    bytes.resize(bytes.size() + 16);
    return !ws::decode_header(bytes, from);
}

} // namespace

TEST_CASE("websocket: the accept key matches RFC 6455", "[net][websocket]") {
    CHECK(ws::accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST_CASE("websocket: frames round trip through the codec", "[net][websocket]") {
    const ws::masking_key mask{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    for (const std::size_t size : {std::size_t{0}, std::size_t{125}, std::size_t{126}, std::size_t{65535}, std::size_t{65536}}) {
        const std::string payload(size, 'p');
        Rhp::utils::byte_buffer frame;
        ws::encode_frame(frame, ws::opcode::kBinary, bytes_of(payload), mask);
        auto header = ws::decode_header(frame.view(), ws::role::kClient);
        REQUIRE(header);
        REQUIRE(*header);
        const auto& h = **header;
        CHECK(h.op == ws::opcode::kBinary);
        CHECK(h.fin);
        CHECK(h.payload == size);
        CHECK(h.bytes + size == frame.size());
        REQUIRE(h.mask);
        auto body = frame.mutable_view().subspan(h.bytes);
        ws::apply_mask(body, *h.mask);
        CHECK(std::string_view{reinterpret_cast<const char*>(body.data()), body.size()} == payload);
        for (std::size_t n = 0; n < h.bytes; ++n) {
            auto partial = ws::decode_header(frame.view().first(n), ws::role::kClient);
            REQUIRE(partial);
            CHECK_FALSE(*partial); // every prefix of a header is "incomplete", never an error
        }
    }
}

TEST_CASE("websocket: the codec refuses protocol violations", "[net][websocket]") {
    CHECK(refused({0x82, 0x01}, ws::role::kClient));                                // a client frame without a mask
    CHECK(refused({0x82, 0x81}, ws::role::kServer));                                // a masked server frame
    CHECK(refused({0xc2, 0x81}, ws::role::kClient));                                // reserved bit
    CHECK(refused({0x81, 0x81}, ws::role::kClient));                                // text
    CHECK(refused({0x83, 0x81}, ws::role::kClient));                                // unknown opcode
    CHECK(refused({0x09, 0x80}, ws::role::kClient));                                // fragmented ping
    CHECK(refused({0x89, 0xfe, 0x00, 0x7e}, ws::role::kClient));                    // ping longer than 125
    CHECK(refused({0x82, 0xfe, 0x00, 0x10}, ws::role::kClient));                    // 16 in the 2-byte form
    CHECK(refused({0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, ws::role::kClient)); // 65535 in the 8-byte form
    CHECK(refused({0x82, 0xff, 0, 0, 0, 0, 0x02, 0, 0, 0}, ws::role::kClient));    // over 16 MiB
}

TEST_CASE("websocket: close payloads carry a sendable status and UTF-8", "[net][websocket]") {
    CHECK(ws::valid_close_payload({}));
    CHECK(ws::valid_close_payload(ws::close_payload(ws::close_code::kNormal)));
    CHECK(ws::valid_close_payload(bytes_of(std::string_view{"\x0b\xb8" "caf\xc3\xa9", 7})));      // 3000 and UTF-8 text
    CHECK_FALSE(ws::valid_close_payload(bytes_of(std::string_view{"\x03", 1})));                // half a status
    CHECK_FALSE(ws::valid_close_payload(bytes_of(std::string_view{"\x03\xed", 2})));            // 1005 is local-only
    CHECK_FALSE(ws::valid_close_payload(bytes_of(std::string_view{"\x07\xd0", 2})));            // 2000 is unassigned
    CHECK_FALSE(ws::valid_close_payload(bytes_of(std::string_view{"\x03\xe8\xc3", 3})));        // truncated UTF-8
    CHECK_FALSE(ws::valid_close_payload(bytes_of(std::string_view{"\x03\xe8\xed\xa0\x80", 5}))); // a surrogate
}

TEST_CASE("websocket: ordered stream", "[net][websocket]") {
    rhp_test::stream_roundtrip<Rhp::net::websocket>(Rhp::endpoint::listen("127.0.0.1", 0));
}

TEST_CASE("websocket: close drains final bytes after the owner releases the link", "[net][websocket]") {
    rhp_test::stream_roundtrip<Rhp::net::websocket>(Rhp::endpoint::listen("127.0.0.1", 0), true);
}

TEST_CASE("websocket: interoperates with an RFC 6455 client sending masked fragments", "[net][websocket]") {
    Rhp::net::io_context io;
    rhp_test::recorder at_host;
    rhp_test::recorder raw_response;
    std::unique_ptr<Rhp::net::link> server;
    auto listener = Rhp::net::websocket::listen(io, Rhp::endpoint::listen("127.0.0.1", 0), [&](auto link) {
        server = std::move(link);
        server->start(at_host);
    });
    REQUIRE(listener);
    std::unique_ptr<Rhp::net::link> raw;
    Rhp::net::tcp::dial(io, Rhp::endpoint::dial("127.0.0.1", (*listener)->port()), [&](auto result) { REQUIRE(result); raw = std::move(*result); });
    REQUIRE(rhp_test::poll_until({&io}, [&] { return raw && server; }));
    raw->start(raw_response);
    Rhp::utils::byte_buffer bytes;
    bytes.append("GET /rhp HTTP/1.1\r\nHost: example\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    const auto frame = [&](unsigned char opcode, std::string_view text) {
        const std::array<std::byte, 4> mask{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
        bytes.append(std::as_bytes(std::span{&opcode, 1}));
        const auto length = static_cast<std::byte>(0x80 | text.size());
        bytes.append({&length, 1});
        bytes.append(mask);
        for (std::size_t i = 0; i < text.size(); ++i) {
            const auto byte = static_cast<std::byte>(static_cast<unsigned char>(text[i])) ^ mask[i % 4];
            bytes.append({&byte, 1});
        }
    };
    frame(0x82, "test"); // coalesced with the HTTP upgrade
    frame(0x02, "ab");
    frame(0x89, "?"); // interleaved control frame
    frame(0x80, "cd");
    raw->send(std::move(bytes));
    REQUIRE(rhp_test::poll_until({&io}, [&] { return at_host.text() == "testabcd" && raw_response.text().find("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != std::string::npos; }));
    SECTION("unmasked client data") {
        const std::array<std::byte, 3> invalid{std::byte{0x82}, std::byte{1}, std::byte{'x'}};
        Rhp::utils::byte_buffer wrong;
        wrong.append(invalid);
        raw->send(std::move(wrong));
    }
    SECTION("unassigned close status") {
        frame(0x88, std::string_view{"\x07\xd0", 2}); // 2000 has no negotiated protocol definition
        raw->send(std::move(bytes));
    }
    REQUIRE(rhp_test::poll_until({&io}, [&] { return at_host.closed; }));
    CHECK(at_host.reason.code == Rhp::errc::kProtocol);
    CHECK(at_host.text() == "testabcd");
}
