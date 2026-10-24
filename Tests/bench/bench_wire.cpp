// G/H: values and the wire. MessagePack encode / decode of a typical reply, frame encode / decode,
// CRC32C, and value conversion, next to a plain memcpy of the same bytes.
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <rhp/core/convert.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/crc32c.hpp>
#include <rhp/wire/codec/msgpack.hpp>
#include <rhp/wire/frame.hpp>

namespace bench_wire_fixture {

// A reply a script might return: a few scalars and a small table.
Rhp::value sample_reply() {
    Rhp::value::map position;
    position.emplace_back("x", 1.25);
    position.emplace_back("y", -7.5);
    position.emplace_back("alive", true);
    Rhp::value::array list;
    list.emplace_back(42);
    list.emplace_back("player_one");
    list.emplace_back(3.5);
    list.emplace_back(std::move(position));
    return Rhp::value{std::move(list)};
}

std::vector<std::byte> bytes(std::size_t n) {
    std::vector<std::byte> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::byte>(i * 31u + 7u);
    }
    return out;
}

} // namespace bench_wire_fixture

using namespace bench_wire_fixture;

TEST_CASE("bench wire: values codec frames and checksums", "[bench][wire]") {
    const Rhp::value reply = sample_reply();
    Rhp::utils::byte_buffer encoded;
    REQUIRE(Rhp::wire::msgpack::encode(reply, encoded));

    BENCHMARK("wire rhp: msgpack encode of a small reply") {
        Rhp::utils::byte_buffer out;
        (void)Rhp::wire::msgpack::encode(reply, out);
        return out.size();
    };
    BENCHMARK("wire rhp: msgpack decode of a small reply") {
        return Rhp::wire::msgpack::decode(encoded.view(), {})->is_array();
    };
    BENCHMARK("wire rhp: copy of a small reply value") {
        Rhp::value copy = reply;
        return copy.is_array();
    };

    for (const std::size_t size : {std::size_t{64}, std::size_t{4096}, std::size_t{65536}}) {
        const auto payload = bytes(size);
        BENCHMARK("wire raw: memcpy of " + std::to_string(size) + " bytes") {
            std::vector<std::byte> out(payload.size());
            std::memcpy(out.data(), payload.data(), payload.size());
            return out.size();
        };
        BENCHMARK("wire rhp: crc32c of " + std::to_string(size) + " bytes") {
            return Rhp::utils::crc32c(payload);
        };
        BENCHMARK("wire rhp: encode a frame of " + std::to_string(size) + " bytes") {
            Rhp::utils::byte_buffer out;
            (void)Rhp::wire::encode_frame(Rhp::wire::frame_header{}, payload, out, nullptr, 1u << 20);
            return out.size();
        };
        Rhp::utils::byte_buffer frame;
        REQUIRE(Rhp::wire::encode_frame(Rhp::wire::frame_header{}, payload, frame, nullptr, 1u << 20));
        Rhp::wire::frame_decoder decoder{1u << 20};
        BENCHMARK("wire rhp: decode a frame of " + std::to_string(size) + " bytes") {
            decoder.feed(frame.view());
            return decoder.next().frame.payload.size();
        };
    }
}
