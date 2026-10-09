#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/ops.hpp>

using Rhp::errc;
using Rhp::wire::decode_status;
using Rhp::wire::frame_decoder;
using Rhp::wire::frame_header;
using Rhp::wire::op;

namespace {

constexpr std::uint32_t kMax = 1024;

// A toy MAC (not secure): the XOR of all bytes, repeated. Enough to see that the decoder hands
// back the right spans and that a sealer's output lands in the frame.
class xor_sealer final : public Rhp::wire::frame_sealer {
public:
    [[nodiscard]] Rhp::wire::mac_bytes seal(Rhp::utils::bytes_view sealed) const noexcept override {
        std::byte x{0x5a};
        for (const std::byte b : sealed) {
            x ^= b;
        }
        Rhp::wire::mac_bytes out{};
        out.fill(x);
        return out;
    }
    [[nodiscard]] bool verify(Rhp::utils::bytes_view sealed, std::span<const std::byte, Rhp::wire::kMacSize> mac) const noexcept override {
        const auto expected = seal(sealed);
        return std::ranges::equal(expected, mac);
    }
};

Rhp::utils::byte_buffer frame(op code, std::uint64_t seq, std::string_view payload, const Rhp::wire::frame_sealer* sealer = nullptr) {
    frame_header h;
    h.code = code;
    h.seq = seq;
    h.ack = 7;
    Rhp::utils::byte_buffer out;
    REQUIRE(Rhp::wire::encode_frame(h, Rhp::utils::as_bytes(payload), out, sealer, kMax));
    return out;
}

std::string_view text(Rhp::utils::bytes_view b) {
    return {reinterpret_cast<const char*>(b.data()), b.size()};
}

} // namespace

TEST_CASE("frame: header layout is the documented 28 bytes", "[wire][frame]") {
    STATIC_REQUIRE(Rhp::wire::kHeaderSize == 28);
    const auto f = frame(op::kExec, 0x0102030405060708ull, "hi");
    const auto v = f.view();
    REQUIRE(v.size() == 28 + 2 + 4);
    CHECK(v[0] == std::byte{'R'});
    CHECK(v[3] == std::byte{0});
    CHECK(v[4] == std::byte{Rhp::wire::kProtocolRevision});
    CHECK(v[6] == std::byte{16}); // op exec, little-endian
    CHECK(v[8] == std::byte{0x08});
    CHECK(v[15] == std::byte{0x01});
    CHECK(v[16] == std::byte{7});
    CHECK(v[24] == std::byte{2});
    const auto crc = Rhp::utils::load_le<std::uint32_t>(v.subspan(30).first<4>());
    CHECK(crc == Rhp::utils::crc32c(v.first(30)));
}

TEST_CASE("frame: decodes byte by byte and several at once", "[wire][frame]") {
    Rhp::utils::byte_buffer stream;
    stream.append(frame(op::kExec, 1, "first").view());
    stream.append(frame(op::kResult, 2, "").view());
    stream.append(frame(op::kPing, 0, "third!").view());

    SECTION("one byte at a time") {
        frame_decoder d{kMax};
        std::vector<std::string> got;
        for (const std::byte b : stream.view()) {
            d.feed(std::span{&b, 1});
            for (;;) {
                const auto r = d.next();
                if (r.status == decode_status::kNeedMore) {
                    break;
                }
                REQUIRE(r.status == decode_status::kFrame);
                got.emplace_back(text(r.frame.payload));
            }
        }
        CHECK(got == std::vector<std::string>{"first", "", "third!"});
        CHECK(d.buffered() == 0);
    }
    SECTION("all at once") {
        frame_decoder d{kMax};
        d.feed(stream.view());
        auto a = d.next();
        REQUIRE(a.status == decode_status::kFrame);
        CHECK(a.frame.header.code == op::kExec);
        CHECK(a.frame.header.seq == 1);
        CHECK(a.frame.header.ack == 7);
        auto b = d.next();
        REQUIRE(b.status == decode_status::kFrame);
        CHECK(b.frame.header.code == op::kResult);
        auto c = d.next();
        REQUIRE(c.status == decode_status::kFrame);
        CHECK(text(c.frame.payload) == "third!");
        CHECK(d.next().status == decode_status::kNeedMore);
    }
}

TEST_CASE("frame: a corrupt byte fails the CRC and the stream continues", "[wire][frame]") {
    auto bad = frame(op::kExec, 1, "payload");
    bad.mutable_view()[30] ^= std::byte{0x01};
    frame_decoder d{kMax};
    d.feed(bad.view());
    d.feed(frame(op::kExec, 2, "next").view());
    const auto r = d.next();
    CHECK(r.status == decode_status::kBadCrc);
    const auto ok = d.next();
    REQUIRE(ok.status == decode_status::kFrame);
    CHECK(ok.frame.header.seq == 2);
}

TEST_CASE("frame: garbage before a frame is skipped", "[wire][frame]") {
    frame_decoder d{kMax};
    const std::string_view junk = "xxRHjunkRH";
    d.feed(Rhp::utils::as_bytes(junk));
    d.feed(frame(op::kPong, 0, "").view());
    int bad = 0;
    for (;;) {
        const auto r = d.next();
        if (r.status == decode_status::kBadMagic) {
            ++bad;
            continue;
        }
        REQUIRE(r.status == decode_status::kFrame);
        CHECK(r.frame.header.code == op::kPong);
        break;
    }
    CHECK(bad >= 1);
}

TEST_CASE("frame: length is checked before allocating", "[wire][frame]") {
    frame_header h;
    h.code = op::kExec;
    h.length = 0xffff'ffffu;
    std::array<std::byte, Rhp::wire::kHeaderSize> raw{};
    Rhp::wire::write_header(raw, h);
    frame_decoder d{kMax};
    d.feed(raw);
    const auto r = d.next();
    CHECK(r.status == decode_status::kTooLarge);
    CHECK(r.frame.header.length == 0xffff'ffffu);

    Rhp::utils::byte_buffer out;
    const std::string big(kMax + 1, 'x');
    auto encoded = Rhp::wire::encode_frame(frame_header{}, Rhp::utils::as_bytes(big), out, nullptr, kMax);
    REQUIRE_FALSE(encoded);
    CHECK(encoded.error().code == errc::kLimitExceeded);
}

TEST_CASE("frame: another protocol revision is reported", "[wire][frame]") {
    frame_header h;
    h.revision = Rhp::wire::kProtocolRevision + 1;
    h.code = op::kHello;
    Rhp::utils::byte_buffer out;
    REQUIRE(Rhp::wire::encode_frame(h, {}, out, nullptr, kMax));
    frame_decoder d{kMax};
    d.feed(out.view());
    const auto r = d.next();
    CHECK(r.status == decode_status::kBadRevision);
    CHECK(r.frame.header.revision == Rhp::wire::kProtocolRevision + 1);
}

TEST_CASE("frame: a sealer adds a MAC the decoder hands back", "[wire][frame]") {
    const xor_sealer sealer;
    const auto f = frame(op::kResult, 3, "sealed", &sealer);
    CHECK(f.size() == 28 + 6 + 4 + 32);
    frame_decoder d{kMax};
    d.feed(f.view());
    const auto r = d.next();
    REQUIRE(r.status == decode_status::kFrame);
    CHECK(Rhp::wire::has(r.frame.header.flags, Rhp::wire::frame_flag::kMac));
    REQUIRE(r.frame.mac.size() == Rhp::wire::kMacSize);
    CHECK(r.frame.sealed.size() == 28 + 6);
    CHECK(sealer.verify(r.frame.sealed, r.frame.mac.first<Rhp::wire::kMacSize>()));
}

TEST_CASE("ops: classes and roles", "[wire][ops]") {
    STATIC_REQUIRE(Rhp::wire::is_handshake(op::kHello));
    STATIC_REQUIRE(Rhp::wire::is_request(op::kExec));
    STATIC_REQUIRE(Rhp::wire::is_reply(op::kResult));
    STATIC_REQUIRE(Rhp::wire::is_sequenced(op::kError));
    STATIC_REQUIRE_FALSE(Rhp::wire::is_sequenced(op::kPing));
    STATIC_REQUIRE(Rhp::wire::required_role(op::kExec) == Rhp::role::kObserve);
    STATIC_REQUIRE(Rhp::wire::required_role(op::kLoad) == Rhp::role::kPatch);
    STATIC_REQUIRE(Rhp::wire::required_role(op::kRevertAll) == Rhp::role::kAdmin);
    STATIC_REQUIRE_FALSE(Rhp::wire::required_role(op::kResult).has_value());
    STATIC_REQUIRE(Rhp::wire::is_known(16));
    STATIC_REQUIRE_FALSE(Rhp::wire::is_known(15));
    CHECK(std::format("{}", op::kRevertTo) == "revert_to");
}
