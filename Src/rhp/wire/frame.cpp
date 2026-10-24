#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/wire/frame.hpp>

namespace Rhp::wire {

namespace {

constexpr std::size_t kKeepCapacity = 256u * 1024u;

template <std::size_t Offset, std::unsigned_integral T>
void put_field(std::span<std::byte, kHeaderSize> out, T value) noexcept {
    utils::store_le<T>(out.subspan<Offset, sizeof(T)>(), value);
}

template <std::size_t Offset, std::unsigned_integral T>
[[nodiscard]] T get_field(std::span<const std::byte, kHeaderSize> in) noexcept {
    return utils::load_le<T>(in.subspan<Offset, sizeof(T)>());
}

} // namespace

void write_header(std::span<std::byte, kHeaderSize> out, const frame_header& header) noexcept {
    std::ranges::copy(kMagic, out.begin());
    put_field<4>(out, header.revision);
    put_field<5>(out, header.flags);
    put_field<6>(out, static_cast<std::uint16_t>(header.code));
    put_field<8>(out, header.seq);
    put_field<16>(out, header.ack);
    put_field<24>(out, header.length);
}

frame_header read_header(std::span<const std::byte, kHeaderSize> in) noexcept {
    frame_header h;
    h.revision = get_field<4, std::uint8_t>(in);
    h.flags = get_field<5, std::uint8_t>(in);
    h.code = static_cast<op>(get_field<6, std::uint16_t>(in));
    h.seq = get_field<8, std::uint64_t>(in);
    h.ack = get_field<16, std::uint64_t>(in);
    h.length = get_field<24, std::uint32_t>(in);
    return h;
}

result<void> encode_frame(frame_header header, utils::bytes_view payload, utils::byte_buffer& out, const frame_sealer* sealer,
                          std::uint32_t max_payload) {
    if (payload.size() > max_payload) {
        return fail(errc::kLimitExceeded, std::format("{} payload of {} bytes exceeds the {}-byte frame limit", header.code, payload.size(), max_payload),
                    "wire.frame");
    }
    header.length = static_cast<std::uint32_t>(payload.size());
    const auto mac_bit = static_cast<std::uint8_t>(frame_flag::kMac);
    header.flags = sealer != nullptr ? static_cast<std::uint8_t>(header.flags | mac_bit) : static_cast<std::uint8_t>(header.flags & ~mac_bit);

    const std::size_t start = out.size();
    out.reserve(start + kHeaderSize + payload.size() + kCrcSize + (sealer != nullptr ? kMacSize : 0)); // one allocation at most
    out.resize(start + kHeaderSize);
    write_header(std::span<std::byte, kHeaderSize>{out.mutable_view().data() + start, kHeaderSize}, header);
    out.append(payload);
    const utils::bytes_view sealed = out.view().subspan(start, kHeaderSize + payload.size());
    if (!has(header.flags, frame_flag::kCrcOmitted)) {
        out.append_le(utils::crc32c(sealed));
    }
    if (sealer != nullptr) {
        // `sealed` may dangle after the CRC append reallocated: take it again.
        const mac_bytes mac = sealer->seal(out.view().subspan(start, kHeaderSize + payload.size()));
        out.append(mac);
    }
    return {};
}

// ---- frame_decoder --------------------------------------------------------------------------------

void frame_decoder::feed(utils::bytes_view data) {
    compact();
    buffer_.insert(buffer_.end(), data.begin(), data.end());
}

void frame_decoder::compact() {
    read_ += std::exchange(consumed_, 0);
    if (read_ == 0) {
        return;
    }
    if (read_ >= buffer_.size()) {
        buffer_.clear();
        read_ = 0;
        // Don't keep a big frame's worth of memory around for every idle connection.
        if (buffer_.capacity() > kKeepCapacity) {
            buffer_.shrink_to_fit();
        }
        return;
    }
    // Move the unread tail down once it is the smaller part, so a large buffer isn't shifted per frame.
    if (read_ >= buffer_.size() / 2) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(read_));
        read_ = 0;
    }
}

decode_result frame_decoder::next() {
    compact();
    const std::span<const std::byte> data{buffer_.data() + read_, buffer_.size() - read_};
    if (data.size() < kMagic.size()) {
        // A partial magic is checked once complete.
        return {};
    }
    if (!std::ranges::equal(data.first<4>(), kMagic)) {
        // Resynchronize on the next magic; keep a possible partial magic at the very end.
        std::size_t skip = 1;
        while (skip < data.size()) {
            const std::size_t left = std::min(data.size() - skip, kMagic.size());
            if (std::ranges::equal(data.subspan(skip, left), std::span{kMagic}.first(left))) {
                break;
            }
            ++skip;
        }
        consumed_ = skip;
        return {decode_status::kBadMagic, {}};
    }
    if (data.size() < kHeaderSize) {
        return {};
    }
    const frame_header header = read_header(data.first<kHeaderSize>());
    if (header.length > max_payload_) {
        // Nothing after this point can be trusted to be a frame boundary.
        consumed_ = data.size();
        return {decode_status::kTooLarge, frame_view{header, {}, {}, {}}};
    }
    const bool with_crc = !has(header.flags, frame_flag::kCrcOmitted);
    const bool with_mac = has(header.flags, frame_flag::kMac);
    const std::size_t total = kHeaderSize + header.length + (with_crc ? kCrcSize : 0) + (with_mac ? kMacSize : 0);
    if (data.size() < total) {
        return {};
    }
    consumed_ = total;
    const utils::bytes_view sealed = data.first(kHeaderSize + header.length);
    frame_view frame{header, sealed.subspan(kHeaderSize), sealed, {}};
    if (with_crc) {
        const std::uint32_t expected = utils::load_le<std::uint32_t>(data.subspan(sealed.size()).first<kCrcSize>());
        if (utils::crc32c(sealed) != expected) {
            return {decode_status::kBadCrc, frame};
        }
    }
    if (header.revision != kProtocolRevision) {
        return {decode_status::kBadRevision, frame};
    }
    if (with_mac) {
        frame.mac = data.subspan(sealed.size() + (with_crc ? kCrcSize : 0), kMacSize);
    }
    return {decode_status::kFrame, frame};
}

} // namespace Rhp::wire
