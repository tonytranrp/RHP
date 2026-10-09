#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/error.hpp>
#include <rhp/core/value.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/wire/codec.hpp>
#include <rhp/wire/codec/msgpack.hpp>

using Rhp::errc;
using Rhp::value;
using Rhp::wire::msgpack;

namespace {

std::vector<std::byte> encode(const value& v) {
    Rhp::utils::byte_buffer out;
    REQUIRE(msgpack::encode(v, out));
    return {out.view().begin(), out.view().end()};
}

std::vector<std::byte> bytes(std::initializer_list<int> list) {
    std::vector<std::byte> out;
    for (const int b : list) {
        out.push_back(static_cast<std::byte>(b));
    }
    return out;
}

value roundtrip(const value& v) {
    const auto b = encode(v);
    auto back = msgpack::decode(b);
    REQUIRE(back);
    return *back;
}

} // namespace

TEST_CASE("msgpack: the codec concept", "[wire][msgpack]") {
    STATIC_REQUIRE(Rhp::wire::codec<msgpack>);
    STATIC_REQUIRE(Rhp::wire::codec_ops_for<msgpack>.name == "msgpack");
}

TEST_CASE("msgpack: scalars use the smallest form", "[wire][msgpack]") {
    CHECK(encode(value{}) == bytes({0xc0}));
    CHECK(encode(value{false}) == bytes({0xc2}));
    CHECK(encode(value{true}) == bytes({0xc3}));
    CHECK(encode(value{0}) == bytes({0x00}));
    CHECK(encode(value{127}) == bytes({0x7f}));
    CHECK(encode(value{128}) == bytes({0xcc, 0x80}));
    CHECK(encode(value{255}) == bytes({0xcc, 0xff}));
    CHECK(encode(value{256}) == bytes({0xcd, 0x01, 0x00}));
    CHECK(encode(value{65536}) == bytes({0xce, 0x00, 0x01, 0x00, 0x00}));
    CHECK(encode(value{std::int64_t{1} << 32}) == bytes({0xcf, 0, 0, 0, 1, 0, 0, 0, 0}));
    CHECK(encode(value{-1}) == bytes({0xff}));
    CHECK(encode(value{-32}) == bytes({0xe0}));
    CHECK(encode(value{-33}) == bytes({0xd0, 0xdf}));
    CHECK(encode(value{-129}) == bytes({0xd1, 0xff, 0x7f}));
    CHECK(encode(value{-32769}) == bytes({0xd2, 0xff, 0xff, 0x7f, 0xff}));
    CHECK(encode(value{std::numeric_limits<std::int64_t>::min()}) == bytes({0xd3, 0x80, 0, 0, 0, 0, 0, 0, 0}));
    CHECK(encode(value{1.5}) == bytes({0xcb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0}));
}

TEST_CASE("msgpack: every value kind round-trips", "[wire][msgpack]") {
    const std::vector<value> cases = {
        value{},
        value{true},
        value{std::numeric_limits<std::int64_t>::max()},
        value{std::numeric_limits<std::int64_t>::min()},
        value{-0.0},
        value{3.25},
        value{std::numeric_limits<double>::infinity()},
        value{""},
        value{std::string(31, 'a')},
        value{std::string(32, 'b')},
        value{std::string(256, 'c')},
        value{std::string(70'000, 'd')},
        value{value::bytes{}},
        value{value::bytes(300, std::byte{7})},
        value{value::array{}},
        value{value::array(15, value{1})},
        value{value::array(16, value{2})},
        value{value::array(70'000, value{})},
        value{value::map{}},
        value{value::map{{value{"k"}, value{1}}, {value{2}, value{"two"}}, {value{true}, value{value::array{value{1.5}}}}}},
    };
    for (const value& v : cases) {
        CHECK(roundtrip(v) == v);
    }
}

TEST_CASE("msgpack: strings keep embedded zeros and arbitrary bytes", "[wire][msgpack]") {
    const std::string s{"a\0b\xff", 4};
    CHECK(roundtrip(value{s}) == value{s});
}

TEST_CASE("msgpack: decoding widens other forms", "[wire][msgpack]") {
    // float32 1.5
    auto f = msgpack::decode(bytes({0xca, 0x3f, 0xc0, 0x00, 0x00}));
    REQUIRE(f);
    CHECK(*f == value{1.5});
    // uint64 above INT64_MAX becomes a number
    auto big = msgpack::decode(bytes({0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
    REQUIRE(big);
    CHECK(big->is_number());
    // str8 / bin8 / array16 / map16 forms another encoder might pick
    auto s = msgpack::decode(bytes({0xd9, 0x01, 'x'}));
    REQUIRE(s);
    CHECK(*s == value{"x"});
    auto a = msgpack::decode(bytes({0xdc, 0x00, 0x01, 0xc3}));
    REQUIRE(a);
    CHECK(*a == value{value::array{value{true}}});
    auto m = msgpack::decode(bytes({0xde, 0x00, 0x01, 0x01, 0x02}));
    REQUIRE(m);
    CHECK(*m == value{value::map{{value{1}, value{2}}}});
}

TEST_CASE("msgpack: hostile input is rejected without allocating", "[wire][msgpack]") {
    // An array32 claiming 4 billion elements in 5 bytes.
    auto huge = msgpack::decode(bytes({0xdd, 0xff, 0xff, 0xff, 0xff}));
    REQUIRE_FALSE(huge);
    CHECK(huge.error().code == errc::kProtocol);
    // A str32 longer than the data.
    CHECK_FALSE(msgpack::decode(bytes({0xdb, 0x00, 0x00, 0x10, 0x00, 'a'})));
    // A map whose count needs more than the bytes left.
    CHECK_FALSE(msgpack::decode(bytes({0x83, 0x01, 0x02})));
    // Truncated scalars.
    CHECK_FALSE(msgpack::decode(bytes({0xcd, 0x01})));
    CHECK_FALSE(msgpack::decode(bytes({0xcb, 0x00})));
    CHECK_FALSE(msgpack::decode(bytes({})));
    // Ext types and the never-used byte.
    auto ext = msgpack::decode(bytes({0xd4, 0x01, 0x00}));
    REQUIRE_FALSE(ext);
    CHECK(ext.error().message.find("ext") != std::string::npos);
    CHECK_FALSE(msgpack::decode(bytes({0xc1})));
    // Trailing bytes after one value.
    auto trailing = msgpack::decode(bytes({0x01, 0x02}));
    REQUIRE_FALSE(trailing);
    CHECK(trailing.error().code == errc::kProtocol);
}

TEST_CASE("msgpack: nesting is bounded both ways", "[wire][msgpack]") {
    // 200 nested one-element arrays.
    std::vector<std::byte> deep(200, std::byte{0x91});
    deep.push_back(std::byte{0xc0});
    auto r = msgpack::decode(deep);
    REQUIRE_FALSE(r);
    CHECK(r.error().code == errc::kLimitExceeded);
    // A custom bound.
    std::vector<std::byte> three = bytes({0x91, 0x91, 0x91, 0xc0});
    CHECK(msgpack::decode(three));
    CHECK_FALSE(msgpack::decode(three, Rhp::wire::decode_limits{.max_depth = 2}));

    value v{};
    for (int i = 0; i < 150; ++i) {
        v = value{value::array{std::move(v)}};
    }
    Rhp::utils::byte_buffer out;
    out.append(std::string_view{"keep"});
    auto encoded = msgpack::encode(v, out);
    REQUIRE_FALSE(encoded);
    CHECK(encoded.error().code == errc::kLimitExceeded);
    CHECK(out.size() == 4); // left as it was
}

TEST_CASE("msgpack: claimed counts can't multiply memory", "[wire][msgpack]") {
    // 99 nested array32 headers, each claiming every byte that is left, over 64 KiB of nils: before
    // the fix each level reserved its claim (hundreds of MB); now it is a plain truncation error.
    std::vector<std::byte> payload;
    constexpr std::size_t kFill = 64 * 1024;
    for (int level = 0; level < 99; ++level) {
        const std::uint32_t left = static_cast<std::uint32_t>(kFill + (98 - level) * 5);
        payload.push_back(std::byte{0xdd});
        for (int shift = 24; shift >= 0; shift -= 8) {
            payload.push_back(static_cast<std::byte>(left >> shift));
        }
    }
    payload.insert(payload.end(), kFill, std::byte{0xc0});
    auto r = msgpack::decode(payload);
    REQUIRE_FALSE(r);
    CHECK(r.error().code == errc::kProtocol);
}

TEST_CASE("msgpack: the element budget", "[wire][msgpack]") {
    const value many{value::array(5'000, value{})};
    Rhp::utils::byte_buffer out;
    REQUIRE(msgpack::encode(many, out));
    CHECK(msgpack::decode(out.view()));
    auto limited = msgpack::decode(out.view(), Rhp::wire::decode_limits{.max_depth = 100, .max_elements = 1'000});
    REQUIRE_FALSE(limited);
    CHECK(limited.error().code == errc::kLimitExceeded);
}
