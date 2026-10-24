// The golden frames the Python client is tested against (clients/python/tests/vectors.json), read by
// RHP's own decoder: each decodes to the expected header and value, and encoding that value again
// gives the same bytes (payload, header, CRC and flags). The MACs and the handshake derivations are
// covered end to end by the Python client's live tests against headless_server.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/frame.hpp>
#include <rhp/wire/ops.hpp>

namespace cross_language_fixture {

// hello (client, plaintext)
constexpr std::string_view kHello =
    "5248500004000100000000000000000000000000000000004c00000083a372657604a8706c6174666f726da6707974686f6e"
    "a46175746882a36b6579a3646576a56e6f6e6365c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b"
    "3c3d3e3fc4727038";
// challenge (host)
constexpr std::string_view kChallenge =
    "5248500004000200000000000000000000000000000000006d00000083a372657604a8706c6174666f726da777696e646f77"
    "73a46175746882a56e6f6e6365c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa57072"
    "6f6f66c42041d547f170bf9a1c0f0aede0f9870cf297359b78570ecc21eaff28134ef92f13dfff3e26";
// response (client)
constexpr std::string_view kResponse =
    "5248500004000300000000000000000000000000000000002f00000081a46175746881a570726f6f66c420aa0b6508937fbf"
    "a678998b5196032ff27200ac83859e1583d0c6f7bad5579a4447fbfc7d";
// welcome (host, sealed h2c)
constexpr std::string_view kWelcome =
    "5248500004010400000000000000000000000000000000004300000085a773657373696f6e01a86964656e74697479a36465"
    "76a4726f6c65a561646d696eac6865617274626561745f6d73cd07d0a8706c6174666f726da777696e646f7773079d143310"
    "f7f884a4ae1ca114e81593a6042fa37bac24a364002182f40b0bf437db016b";
// exec request seq 1 ack 0 (client, sealed c2h)
constexpr std::string_view kExecRequest =
    "5248500004011000010000000000000000000000000000009100000083a372657101a46964656dcf0123456789abcdefa462"
    "6f647983a6736f75726365a872657475726e2031a56368756e6ba465786563a97369676e617475726582a67369676e6572a3"
    "646576a3736967c4402dad7e172491c346e8a608b7793a1e8b228932077186ff1371e80dbc4463090b32fc2e26d002e0b94d"
    "469fd4b1f55b6138334a4cffdd4cd9cc43bae204ae350a58097d962b9d41d5639d74e6c3a580799ca47caec5039cf63e384c"
    "a49e5aa2c5d798fcdc";
// result reply seq 1 ack 1 (host, sealed h2c): body [1]
constexpr std::string_view kResultReply =
    "5248500004013200010000000000000001000000000000000d00000082a372657101a4626f6479910181a7a5b3406e116bf4"
    "67264fb993d12b85d4e36b90db3ca313b20fc8d63a0c2c5c3d3e72";
// ack control seq 1 ack 1 (client, sealed c2h)
constexpr std::string_view kAck =
    "52485000040142000100000000000000010000000000000000000000defc7a664dfa28a233dd4877e6a378504a68b5dc82b6"
    "f5106f8fbd430cf8aca5e5fd0a6d";
// same ack on a TLS link (kCrcOmitted, no CRC)
constexpr std::string_view kTlsAck =
    "5248500004094200010000000000000001000000000000000000000008ecc076ab4e0b230eda5c2206cf5e46b3d9850b3a13"
    "a9a50bbd640695584a77";
// kResume (client, control seq 2, ack 1, sealed c2h)
constexpr std::string_view kResume =
    "5248500004010500020000000000000001000000000000003200000082a773657373696f6e01a570726f6f66c420e5015ad3"
    "828c8c448e56b855e4ce1ba772b54ee5307e10513d15fd490758edc7f4d3ebd0fc33b71db2926c19850831737f76bfa528d1"
    "131fe7a2877006a90ad99b9950b6";

std::vector<std::byte> from_hex(std::string_view hex) {
    const auto nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    std::vector<std::byte> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::byte>(nibble(hex[2 * i]) * 16 + nibble(hex[2 * i + 1]));
    }
    return out;
}

// A "sealer" that hands back the MAC a golden frame already carries: re-encoding then has to agree
// on everything the MAC doesn't cover (header, payload, CRC, flags, order of the trailers).
class recorded_mac final : public Rhp::wire::frame_sealer {
public:
    explicit recorded_mac(std::span<const std::byte> mac) { std::copy(mac.begin(), mac.end(), mac_.begin()); }
    [[nodiscard]] Rhp::wire::mac_bytes seal(Rhp::utils::bytes_view) const noexcept override { return mac_; }
    [[nodiscard]] bool verify(Rhp::utils::bytes_view, std::span<const std::byte, Rhp::wire::kMacSize> mac) const noexcept override {
        return std::equal(mac.begin(), mac.end(), mac_.begin());
    }

private:
    Rhp::wire::mac_bytes mac_{};
};

struct expected_frame {
    std::string_view hex;
    Rhp::wire::op code;
    std::uint64_t seq;
    std::uint64_t ack;
    bool sealed;
    bool crc_omitted;
};

} // namespace cross_language_fixture

using namespace cross_language_fixture;

TEST_CASE("golden frames shared with the Python client decode and re-encode byte for byte", "[wire][cross_language]") {
    using Rhp::wire::op;
    const expected_frame frames[] = {
        {kHello, op::kHello, 0, 0, false, false},
        {kChallenge, op::kChallenge, 0, 0, false, false},
        {kResponse, op::kResponse, 0, 0, false, false},
        {kWelcome, op::kWelcome, 0, 0, true, false},
        {kExecRequest, op::kExec, 1, 0, true, false},
        {kResultReply, op::kResult, 1, 1, true, false},
        {kAck, op::kAck, 1, 1, true, false},
        {kTlsAck, op::kAck, 1, 1, true, true},
        {kResume, op::kResume, 2, 1, true, false},
    };
    for (const expected_frame& e : frames) {
        const std::vector<std::byte> raw = from_hex(e.hex);
        Rhp::wire::frame_decoder decoder{1u << 20};
        decoder.feed(raw);
        const auto decoded = decoder.next();
        REQUIRE(decoded.status == Rhp::wire::decode_status::kFrame);
        const Rhp::wire::frame_view& f = decoded.frame;
        CHECK(f.header.code == e.code);
        CHECK(f.header.seq == e.seq);
        CHECK(f.header.ack == e.ack);
        CHECK(f.mac.empty() == !e.sealed);
        CHECK(Rhp::wire::has(f.header.flags, Rhp::wire::frame_flag::kCrcOmitted) == e.crc_omitted);

        // The payload is canonical MessagePack: decoding and encoding again reproduces it.
        Rhp::utils::byte_buffer payload;
        if (!f.payload.empty()) {
            const auto v = Rhp::wire::msgpack::decode(f.payload, {});
            REQUIRE(v);
            REQUIRE(Rhp::wire::msgpack::encode(*v, payload));
            CHECK(std::ranges::equal(payload.view(), f.payload));
        }

        Rhp::wire::frame_header header = f.header;
        const std::vector<std::byte> mac(f.mac.begin(), f.mac.end());
        const recorded_mac sealer{mac.empty() ? std::span<const std::byte>{} : std::span<const std::byte>{mac}};
        Rhp::utils::byte_buffer again;
        REQUIRE(Rhp::wire::encode_frame(header, payload.view(), again, e.sealed ? &sealer : nullptr, 1u << 20));
        CHECK(std::ranges::equal(again.view(), raw));
    }
}

TEST_CASE("the golden exec request carries what the host checks", "[wire][cross_language]") {
    const std::vector<std::byte> raw = from_hex(kExecRequest);
    Rhp::wire::frame_decoder decoder{1u << 20};
    decoder.feed(raw);
    const auto decoded = decoder.next();
    REQUIRE(decoded.status == Rhp::wire::decode_status::kFrame);
    const auto envelope = Rhp::wire::msgpack::decode(decoded.frame.payload, {});
    REQUIRE(envelope);
    CHECK(envelope->find("req")->get_if<std::int64_t>() != nullptr);
    const Rhp::value* body = envelope->find("body");
    REQUIRE(body != nullptr);
    CHECK(*body->find("source") == Rhp::value{"return 1"});
    CHECK(*body->find("chunk") == Rhp::value{"exec"});
    const Rhp::value* signature = body->find("signature");
    REQUIRE(signature != nullptr);
    CHECK(*signature->find("signer") == Rhp::value{"dev"});
    CHECK(signature->find("sig")->get_if<Rhp::value::bytes>()->size() == 64);
}
