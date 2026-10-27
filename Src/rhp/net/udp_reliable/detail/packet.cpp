#include <rhp/net/udp_reliable/detail/packet.hpp>
#include <rhp/utils/crc32c.hpp>

namespace Rhp::net::detail::rudp {

namespace {

template <std::unsigned_integral T>
[[nodiscard]] T load(utils::bytes_view in, std::size_t at) noexcept {
    return utils::load_le<T>(in.subspan(at).first<sizeof(T)>());
}

} // namespace

void encode_packet(utils::byte_buffer& out, const packet_header& header, utils::bytes_view payload) {
    const auto start = out.size();
    out.reserve(start + kHeaderBytes + payload.size() + kTrailerBytes);
    out.append_le(kMagic);
    out.append_le(kRevision);
    out.append_le(static_cast<std::uint8_t>(header.kind));
    out.append_le(static_cast<std::uint16_t>(payload.size()));
    out.append_le(header.token);
    out.append_le(header.seq);
    out.append_le(header.ack);
    out.append_le(header.sack);
    out.append(payload);
    out.append_le(utils::crc32c(out.view().subspan(start)));
}

std::optional<packet> decode_packet(utils::bytes_view datagram) noexcept {
    if (datagram.size() < kHeaderBytes + kTrailerBytes || datagram.size() > kMaxPacket) {
        return std::nullopt;
    }
    const auto body = datagram.first(datagram.size() - kTrailerBytes);
    const auto kind = std::to_integer<std::uint8_t>(datagram[5]);
    const auto size = load<std::uint16_t>(datagram, 6);
    packet out;
    out.header.kind = static_cast<packet_kind>(kind);
    out.header.token = load<std::uint64_t>(datagram, 8);
    out.header.seq = load<std::uint64_t>(datagram, 16);
    out.header.ack = load<std::uint64_t>(datagram, 24);
    out.header.sack = load<std::uint64_t>(datagram, 32);
    const bool valid = load<std::uint32_t>(datagram, 0) == kMagic && std::to_integer<std::uint8_t>(datagram[4]) == kRevision &&
                       kind >= static_cast<std::uint8_t>(packet_kind::kHello) && kind <= static_cast<std::uint8_t>(packet_kind::kCookie) &&
                       out.header.token != 0 && size == body.size() - kHeaderBytes && (out.header.kind == packet_kind::kData || size == 0) &&
                       load<std::uint32_t>(datagram, body.size()) == utils::crc32c(body);
    if (!valid) {
        return std::nullopt;
    }
    out.payload = body.subspan(kHeaderBytes);
    return out;
}

} // namespace Rhp::net::detail::rudp
