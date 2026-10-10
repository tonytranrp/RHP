#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <rhp/core/result.hpp>
#include <rhp/net/detail/http.hpp>
#include <rhp/utils/byte_buffer.hpp>

// Sans-IO RFC 6455 pieces of the WebSocket transport: frame headers, masking, close payloads and the
// HTTP upgrade. No sockets here, so the codec is unit-tested and fuzzed on its own.
namespace Rhp::net::detail::ws {

enum class opcode : std::uint8_t {
    kContinuation = 0x0,
    kText = 0x1,
    kBinary = 0x2,
    kClose = 0x8,
    kPing = 0x9,
    kPong = 0xA
};

[[nodiscard]] constexpr bool is_control(opcode op) noexcept {
    return (static_cast<std::uint8_t>(op) & 0x8) != 0;
}

// Close status codes RHP sends (RFC 6455 §7.4.1).
enum class close_code : std::uint16_t {
    kNormal = 1000,
    kProtocolError = 1002,
    kUnsupportedData = 1003,
    kMessageTooBig = 1009
};

// Which end of the connection: clients mask every frame they send, servers never do.
enum class role : std::uint8_t {
    kClient,
    kServer
};

[[nodiscard]] constexpr role peer_of(role self) noexcept {
    return self == role::kClient ? role::kServer : role::kClient;
}

using masking_key = std::array<std::byte, 4>;

inline constexpr std::string_view kPath = "/rhp";
inline constexpr std::size_t kMaxHeaderBytes = 14;     // 2 + 8-byte length + 4-byte mask
inline constexpr std::size_t kMaxControlPayload = 125; // RFC 6455 §5.5
inline constexpr std::size_t kMaxMessage = 16u << 20;  // per message and pre-upgrade queue

struct frame_header {
    opcode op = opcode::kBinary;
    bool fin = true;
    std::optional<masking_key> mask;
    std::uint64_t payload = 0;
    std::size_t bytes = 0; // header length on the wire
};

// Decodes the header of a frame `from` sent. nullopt until the whole header is there; kProtocol
// for reserved bits, wrong masking, unknown or text opcodes, fragmented or long control frames and
// non-minimal lengths; kLimitExceeded beyond kMaxMessage.
[[nodiscard]] result<std::optional<frame_header>> decode_header(utils::bytes_view input, role from);

// Appends one complete frame; `mask` is set exactly when the sender is a client.
void encode_frame(utils::byte_buffer& out, opcode op, utils::bytes_view payload, std::optional<masking_key> mask);

// XORs `payload` with the key, `offset` bytes into the frame's payload.
constexpr void apply_mask(std::span<std::byte> payload, const masking_key& mask, std::uint64_t offset = 0) noexcept {
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] ^= mask[static_cast<std::size_t>((offset + i) % mask.size())];
    }
}

// A Close payload: empty, or a sendable status code followed by UTF-8 text.
[[nodiscard]] bool valid_close_payload(utils::bytes_view payload) noexcept;
[[nodiscard]] std::array<std::byte, 2> close_payload(close_code code) noexcept;

// The server's Sec-WebSocket-Accept for a client key (base64 SHA-1, RFC 6455 §4.2.2).
[[nodiscard]] std::string accept_key(std::string_view client_key);

[[nodiscard]] std::string upgrade_request(std::string_view host, std::string_view key);
[[nodiscard]] std::string upgrade_response(std::string_view client_key);

// Validates the client's upgrade (GET /rhp, version 13, a 16-byte key) and returns that key.
[[nodiscard]] result<std::string> accept_upgrade(const http_head& request);
// Validates the server's 101 answer to `key`; extensions and subprotocols are refused.
[[nodiscard]] result<void> check_upgrade_response(const http_head& response, std::string_view key);

} // namespace Rhp::net::detail::ws
