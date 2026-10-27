// Frames: the decoder takes arbitrary bytes in arbitrary pieces. Every frame it reports has a length
// within the limit and views inside the buffer, and encoding its header and payload again decodes to
// the same frame.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/ops.hpp>

#include "fuzz_support.hpp"

namespace {

constexpr std::uint32_t kMax = 4096;

std::string frame(Rhp::wire::op code, std::uint64_t seq, const Rhp::value& body, std::uint8_t flags = 0, bool mac = false) {
    Rhp::utils::byte_buffer payload;
    (void)Rhp::wire::msgpack::encode(body, payload);
    Rhp::wire::frame_header h;
    h.code = code;
    h.seq = seq;
    h.ack = seq > 0 ? seq - 1 : 0;
    h.flags = flags;
    Rhp::utils::byte_buffer out;
    (void)Rhp::wire::encode_frame(h, payload.view(), out, nullptr, kMax);
    if (mac) { // a MAC trailer the decoder only has to carry
        out.mutable_view()[5] = static_cast<std::byte>(static_cast<std::uint8_t>(out.view()[5]) | Rhp::wire::frame_flag::kMac);
        out.append(std::string(32, '\x5a'));
    }
    return {reinterpret_cast<const char*>(out.view().data()), out.size()};
}

} // namespace

std::vector<std::string> rhp_fuzz_seeds() {
    Rhp::value::map hello;
    hello.emplace_back("rev", Rhp::value{std::int64_t{Rhp::wire::kProtocolRevision}});
    hello.emplace_back("platform", Rhp::value{std::string{"linux"}});
    const std::string a = frame(Rhp::wire::op::kHello, 0, Rhp::value{hello});
    const std::string b = frame(Rhp::wire::op::kExec, 7, Rhp::value{std::string{"return 1"}}, 0, true);
    const std::string c = frame(Rhp::wire::op::kPing, 3, Rhp::value{}, static_cast<std::uint8_t>(Rhp::wire::frame_flag::kCrcOmitted));
    const std::string d = frame(Rhp::wire::op::kResume, 9, Rhp::value{hello}, 0, true);
    return {a, b, c, d, a + b + c, b + b, "RHP", std::string("\0RHP\0", 5) + a, "garbage before" + c};
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto* bytes = reinterpret_cast<const std::byte*>(data);
    Rhp::wire::frame_decoder decoder{kMax};
    // The first byte picks how the rest is cut into feeds (a stream arrives in any pieces).
    const std::size_t piece = size == 0 ? 1 : 1 + std::to_integer<std::size_t>(bytes[0]) % 97;
    std::size_t at = size == 0 ? 0 : 1;
    int frames = 0;
    while (at < size) {
        const std::size_t n = std::min(piece, size - at);
        decoder.feed(Rhp::utils::bytes_view{bytes + at, n});
        at += n;
        for (int guard = 0; guard < 10'000; ++guard) {
            const Rhp::wire::decode_result r = decoder.next();
            if (r.status == Rhp::wire::decode_status::kNeedMore) {
                break;
            }
            if (r.status == Rhp::wire::decode_status::kTooLarge) {
                RHP_FUZZ_CHECK(r.frame.header.length > kMax);
                return 0; // the stream can't be trusted any more
            }
            if (r.status != Rhp::wire::decode_status::kFrame) {
                continue;
            }
            ++frames;
            const Rhp::wire::frame_view& f = r.frame;
            RHP_FUZZ_CHECK(f.header.length <= kMax);
            RHP_FUZZ_CHECK(f.payload.size() == f.header.length);
            RHP_FUZZ_CHECK(f.sealed.size() == Rhp::wire::kHeaderSize + f.header.length);
            RHP_FUZZ_CHECK(f.mac.empty() || f.mac.size() == Rhp::wire::kMacSize);
            // Encode it again (without the MAC) and decode that: the same frame.
            Rhp::wire::frame_header h = f.header;
            h.flags = static_cast<std::uint8_t>(h.flags & ~static_cast<std::uint8_t>(Rhp::wire::frame_flag::kMac));
            Rhp::utils::byte_buffer again;
            RHP_FUZZ_CHECK(Rhp::wire::encode_frame(h, f.payload, again, nullptr, kMax).has_value());
            Rhp::wire::frame_decoder second{kMax};
            second.feed(again.view());
            const Rhp::wire::decode_result back = second.next();
            RHP_FUZZ_CHECK(back.status == Rhp::wire::decode_status::kFrame);
            RHP_FUZZ_CHECK(back.frame.header.code == h.code && back.frame.header.seq == h.seq && back.frame.header.ack == h.ack);
            RHP_FUZZ_CHECK(std::ranges::equal(back.frame.payload, f.payload));
        }
    }
    (void)frames;
    return 0;
}
