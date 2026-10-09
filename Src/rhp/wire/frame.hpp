#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/ops.hpp>

namespace Rhp::wire {

// Frame layout (little-endian):
//
//   0       4      5      6    8       16      24       28
//   | "RHP\0" | rev | flags | op | seq    | ack    | length | payload (length bytes) | crc32c 4B | [mac 32B]
//
// The CRC covers header + payload. The MAC (flag kMac) covers header + payload as well, so a
// corrupted frame fails the CRC first (→ nack, resend) and only a forged one fails the MAC.
inline constexpr std::array<std::byte, 4> kMagic{std::byte{'R'}, std::byte{'H'}, std::byte{'P'}, std::byte{0}};
inline constexpr std::size_t kHeaderSize = 28;
inline constexpr std::size_t kCrcSize = 4;
inline constexpr std::size_t kMacSize = 32;

using mac_bytes = std::array<std::byte, kMacSize>;

struct frame_header {
    std::uint8_t revision = kProtocolRevision;
    std::uint8_t flags = 0;
    op code = op::kPing;
    std::uint64_t seq = 0; // 0 = unsequenced
    std::uint64_t ack = 0; // cumulative: every sequenced frame up to this one arrived
    std::uint32_t length = 0;

    [[nodiscard]] bool operator==(const frame_header&) const = default;
};

// Computes and checks the per-frame MAC. Implemented by the authenticator's session keys
// (Rhp::security); the wire layer only knows this interface.
class frame_sealer {
public:
    virtual ~frame_sealer() = default;

    // MAC over header + payload of an outgoing frame.
    [[nodiscard]] virtual mac_bytes seal(utils::bytes_view sealed) const noexcept = 0;
    // Constant-time check of an incoming frame's MAC.
    [[nodiscard]] virtual bool verify(utils::bytes_view sealed, std::span<const std::byte, kMacSize> mac) const noexcept = 0;

protected:
    frame_sealer() = default;
    frame_sealer(const frame_sealer&) = default;
    frame_sealer& operator=(const frame_sealer&) = default;
};

void write_header(std::span<std::byte, kHeaderSize> out, const frame_header& header) noexcept;
[[nodiscard]] frame_header read_header(std::span<const std::byte, kHeaderSize> in) noexcept;

// Appends one whole frame to `out`. `header.length` is set from the payload; kMac is set when a
// sealer is given and cleared otherwise. Fails with kLimitExceeded if the payload exceeds max_payload.
result<void> encode_frame(frame_header header, utils::bytes_view payload, utils::byte_buffer& out, const frame_sealer* sealer,
                          std::uint32_t max_payload);

// A frame the decoder found. Views point into the decoder and stay valid until its next call.
struct frame_view {
    frame_header header;
    utils::bytes_view payload;
    utils::bytes_view sealed;       // header + payload: what the CRC and the MAC cover
    std::span<const std::byte> mac; // empty without kMac
};

enum class decode_status : std::uint8_t {
    kFrame,       // `frame` is valid
    kNeedMore,    // not a whole frame buffered yet
    kBadMagic,    // garbage skipped up to the next "RHP\0" (or the end of the buffer)
    kBadRevision, // a frame of another protocol revision (consumed)
    kTooLarge,    // length > max_payload: the stream can't be trusted any more
    kBadCrc,      // a whole frame whose CRC failed (consumed; `frame.header` may be corrupt)
};

struct decode_result {
    decode_status status = decode_status::kNeedMore;
    frame_view frame{};
};

// Incremental decoder for a byte stream: feed() whatever arrived, then call next() until kNeedMore.
// The length is checked against max_payload before anything is allocated for the payload.
class frame_decoder {
public:
    explicit frame_decoder(std::uint32_t max_payload) noexcept : max_payload_(max_payload) {}

    void feed(utils::bytes_view data);
    [[nodiscard]] decode_result next();

    // Changes the payload limit for frames not yet decoded (a session raises it after the handshake).
    void set_max_payload(std::uint32_t max_payload) noexcept { max_payload_ = max_payload; }

    [[nodiscard]] std::size_t buffered() const noexcept { return buffer_.size() - read_; }

private:
    void compact();

    std::uint32_t max_payload_;
    std::vector<std::byte> buffer_;
    std::size_t read_ = 0;     // start of unread data
    std::size_t consumed_ = 0; // bytes the frame returned by the last next() occupies (dropped on the next call)
};

} // namespace Rhp::wire
