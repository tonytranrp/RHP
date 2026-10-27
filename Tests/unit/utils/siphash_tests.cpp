#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/siphash.hpp>

using Rhp::utils::siphash24;

namespace {

// 00 01 02 ...: the key and the messages of the paper's vectors.
template <std::size_t N>
constexpr std::array<std::byte, N> counting() {
    std::array<std::byte, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<std::byte>(i);
    }
    return out;
}

constexpr auto kKey = counting<16>();
constexpr auto kMessage = counting<64>();

} // namespace

TEST_CASE("SipHash-2-4 matches the reference vectors", "[utils][siphash]") {
    // The paper's example (15 bytes) and entries 0, 1, 8 and 63 of its vectors.h (message 00..n-1).
    STATIC_REQUIRE(siphash24(kKey, std::span{kMessage}.first(15)) == 0xa129'ca61'49be'45e5u);
    STATIC_REQUIRE(siphash24(kKey, {}) == 0x726f'db47'dd0e'0e31u);
    STATIC_REQUIRE(siphash24(kKey, std::span{kMessage}.first(1)) == 0x74f8'39c5'93dc'67fdu);
    STATIC_REQUIRE(siphash24(kKey, std::span{kMessage}.first(8)) == 0x93f5'f579'9a93'2462u);
    STATIC_REQUIRE(siphash24(kKey, std::span{kMessage}.first(63)) == 0x958a'324c'eb06'4572u);

    // The same at run time, from memory the compiler can't see through.
    const std::vector<std::byte> key(kKey.begin(), kKey.end());
    const std::vector<std::byte> message(kMessage.begin(), kMessage.begin() + 15);
    CHECK(siphash24(std::span<const std::byte, 16>{key.data(), 16}, message) == 0xa129'ca61'49be'45e5u);
}
