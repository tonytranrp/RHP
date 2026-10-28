// The golden frames the Python client is tested against (clients/python/tests/vectors.json), read by
// RHP's own decoder: each decodes to the expected header and value, and encoding that value again
// gives the same bytes (payload, header, CRC and flags). The MACs and the handshake derivations are
// covered end to end by the Python client's live tests against headless_server.
#include <algorithm>
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
    "5248500007000100000000000000000000000000000000004c00000083a372657607a8706c6174666f726da6707974686f6e"
    "a46175746882a36b6579a3646576a56e6f6e6365c420202122232425262728292a2b2c2d2e2f303132333435363738393a3b"
    "3c3d3e3f79847148";
// challenge (host)
constexpr std::string_view kChallenge =
    "5248500007000200000000000000000000000000000000006d00000083a372657607a8706c6174666f726da777696e646f77"
    "73a46175746882a56e6f6e6365c420404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5fa57072"
    "6f6f66c42041d547f170bf9a1c0f0aede0f9870cf297359b78570ecc21eaff28134ef92f13d0f86373";
// response (client)
constexpr std::string_view kResponse =
    "5248500007000300000000000000000000000000000000002f00000081a46175746881a570726f6f66c420aa0b6508937fbf"
    "a678998b5196032ff27200ac83859e1583d0c6f7bad5579a449cd16153";
// welcome (host, sealed h2c)
constexpr std::string_view kWelcome =
    "5248500007010400000000000000000000000000000000004300000085a773657373696f6e01a86964656e74697479a36465"
    "76a4726f6c65a561646d696eac6865617274626561745f6d73cd07d0a8706c6174666f726da777696e646f7773932b23aea5"
    "e6f0867715dae523598c1d6465865602d8e07fc6a5b821c2cae9d97f6c1a61";
// exec request seq 1 ack 0 (client, sealed c2h)
constexpr std::string_view kExecRequest =
    "5248500007011000010000000000000000000000000000009100000083a372657101a46964656dcf0123456789abcdefa462"
    "6f647983a6736f75726365a872657475726e2031a56368756e6ba465786563a97369676e617475726582a67369676e6572a3"
    "646576a3736967c4402dad7e172491c346e8a608b7793a1e8b228932077186ff1371e80dbc4463090b32fc2e26d002e0b94d"
    "469fd4b1f55b6138334a4cffdd4cd9cc43bae204ae350a3a51523708079371fbc3be6ff57f6ba5a5979a642b2d0fad288b7c"
    "8879d9f8f13b84749c";
// result reply seq 1 ack 1 (host, sealed h2c): body [1]
constexpr std::string_view kResultReply =
    "5248500007013200010000000000000001000000000000000d00000082a372657101a4626f647991019643e6b77d9707f994"
    "2c76c70975a6ef45d402b626ccd9e8b22c315aa08132353bcb377d";
// ack control seq 1 ack 1 (client, sealed c2h)
constexpr std::string_view kAck =
    "52485000070142000100000000000000010000000000000000000000bdcd46ad44b855510ea69fcefb2ae62593847c401c2e"
    "8ef4901318b42ec4cb0b9507e663";
// same ack on a TLS link (kCrcOmitted, no CRC)
constexpr std::string_view kTlsAck =
    "52485000070942000100000000000000010000000000000000000000506d69bc18b98fdecc4dd92ae464175faa90c72a2dc6"
    "d1abffae29bd73a3e1c1";
// kResume (client, control seq 2, ack 1, sealed c2h)
constexpr std::string_view kResume =
    "5248500007010500020000000000000001000000000000003200000082a773657373696f6e01a570726f6f66c420e5015ad3"
    "828c8c448e56b855e4ce1ba772b54ee5307e10513d15fd490758edc7ec072ed64d1d3a221bf104e7780df53ad77f34e8f26a"
    "7da513b3231456e8dd22e65637ed";

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
