#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include <rhp/utils/byte_buffer.hpp>

// Sans-IO packet format of the reliable UDP transport (independent of the RHP protocol revision):
//
//   offset  size  field
//        0     4  magic "RUDP" (little-endian 0x50445552)
//        4     1  packet revision (1)
//        5     1  kind
//        6     2  payload length
//        8     8  connection token (random, nonzero; chosen by the dialer)
//       16     8  sequence number (0 for hello/welcome/ack)
//       24     8  cumulative ACK: every sequence <= this one arrived
//       32     8  selective ACK: bit i set = sequence ack + 1 + i arrived
//       40     n  payload (data only, n <= kMaxPayload)
//     40+n     4  CRC-32C of everything before it
//
// The CRC catches corruption only; authentication is the session's job (PSK MAC or TLS).
namespace Rhp::net::detail::rudp {

enum class packet_kind : std::uint8_t {
    kHello = 1,
    kWelcome = 2,
    kData = 3,
    kAck = 4,
    kFin = 5
};

inline constexpr std::uint32_t kMagic = 0x50445552;
inline constexpr std::uint8_t kRevision = 1;
inline constexpr std::size_t kHeaderBytes = 40;
inline constexpr std::size_t kTrailerBytes = 4;
// Payload that keeps a packet under the 576-byte IPv4 minimum reassembly size.
inline constexpr std::size_t kMaxPayload = 480;
inline constexpr std::size_t kMaxPacket = kHeaderBytes + kMaxPayload + kTrailerBytes;
// Width of the selective-ACK bitmap: also the receive window and the largest send window.
inline constexpr std::size_t kWindow = 64;

struct packet_header {
    packet_kind kind = packet_kind::kAck;
    std::uint64_t token = 0;
    std::uint64_t seq = 0;
    std::uint64_t ack = 0;
    std::uint64_t sack = 0;
};

struct packet {
    packet_header header;
    utils::bytes_view payload; // borrows the datagram
};

// Appends one packet to `out`.
void encode_packet(utils::byte_buffer& out, const packet_header& header, utils::bytes_view payload = {});

// Decodes a datagram: nullopt for anything malformed (size, magic, revision, kind, zero token,
// payload on a non-data packet, CRC).
[[nodiscard]] std::optional<packet> decode_packet(utils::bytes_view datagram) noexcept;

} // namespace Rhp::net::detail::rudp
