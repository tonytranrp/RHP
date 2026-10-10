#include "fuzz_support.hpp"

#include <rhp/net/detail/http.hpp>
#include <rhp/net/mdns/detail/dns.hpp>
#include <rhp/net/udp_reliable/detail/packet.hpp>
#include <rhp/net/websocket/detail/protocol.hpp>
#include <rhp/wire/ops.hpp>

// The network parsers that read bytes from strangers: HTTP heads, DNS packets, WebSocket frame
// headers and reliable-UDP packets. Each must refuse or bound what it accepts, never crash.
std::vector<std::string> rhp_fuzz_seeds() {
    Rhp::net::service_record record;
    record.name = "fuzz";
    record.host = "fuzz.rhp.local";
    record.address = "127.0.0.1";
    record.port = 7777;
    record.protocol_revision = Rhp::wire::kProtocolRevision;
    auto dns = Rhp::net::detail::dns_service_packet(record, 120);
    RHP_FUZZ_CHECK(dns);
    Rhp::utils::byte_buffer frame;
    Rhp::net::detail::ws::encode_frame(frame, Rhp::net::detail::ws::opcode::kBinary, Rhp::utils::as_bytes("payload"), Rhp::net::detail::ws::masking_key{});
    Rhp::utils::byte_buffer packet;
    Rhp::net::detail::rudp::encode_packet(packet, {Rhp::net::detail::rudp::packet_kind::kData, 1, 1, 0, 0}, Rhp::utils::as_bytes("payload"));
    const auto text = [](const Rhp::utils::byte_buffer& b) { return std::string{reinterpret_cast<const char*>(b.view().data()), b.size()}; };
    return {"GET /rhp HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            "POST /exec HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nreturn 1",
            "POST /exec HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 100\r\n\r\n",
            text(*dns),
            text(frame),
            text(packet)};
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    const Rhp::utils::bytes_view bytes{reinterpret_cast<const std::byte*>(data), size};
    if (const auto http = Rhp::net::detail::parse_http_head(text, 4096); http && *http) {
        RHP_FUZZ_CHECK((**http).bytes <= size);
        RHP_FUZZ_CHECK((**http).content_length <= 4096);
        RHP_FUZZ_CHECK((**http).fields.size() <= Rhp::net::detail::kMaxHttpFields);
    }
    if (const auto dns = Rhp::net::detail::read_dns(bytes)) {
        RHP_FUZZ_CHECK(dns->questions.size() + dns->records.size() <= Rhp::net::detail::kMaxDnsEntries);
        for (const auto& record : dns->records) {
            RHP_FUZZ_CHECK(record.name.size() <= 254);
            RHP_FUZZ_CHECK(record.txt.size() <= 64);
        }
    }
    for (const auto from : {Rhp::net::detail::ws::role::kClient, Rhp::net::detail::ws::role::kServer}) {
        if (const auto header = Rhp::net::detail::ws::decode_header(bytes, from); header && *header) {
            RHP_FUZZ_CHECK((**header).bytes <= Rhp::net::detail::ws::kMaxHeaderBytes && (**header).bytes <= size);
            RHP_FUZZ_CHECK((**header).payload <= Rhp::net::detail::ws::kMaxMessage);
            RHP_FUZZ_CHECK((**header).mask.has_value() == (from == Rhp::net::detail::ws::role::kClient));
        }
    }
    (void)Rhp::net::detail::ws::valid_close_payload(bytes);
    if (const auto packet = Rhp::net::detail::rudp::decode_packet(bytes)) {
        RHP_FUZZ_CHECK(packet->payload.size() <= Rhp::net::detail::rudp::kMaxPayload);
        RHP_FUZZ_CHECK(packet->header.token != 0);
    }
    return 0;
}
