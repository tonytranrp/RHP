#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/utils/crc32c.hpp>

using Rhp::utils::as_bytes;
using Rhp::utils::crc32c;

namespace {

template <std::size_t N>
std::array<std::byte, N> filled(std::byte b) {
    std::array<std::byte, N> out{};
    out.fill(b);
    return out;
}

} // namespace

TEST_CASE("crc32c check value", "[utils][crc32c]") {
    REQUIRE(crc32c(as_bytes("123456789")) == 0xE3069283u);
    REQUIRE(crc32c({}) == 0u);
}

// RFC 3720 (iSCSI) appendix B.4 test vectors.
TEST_CASE("crc32c RFC 3720 vectors", "[utils][crc32c]") {
    REQUIRE(crc32c(filled<32>(std::byte{0x00})) == 0x8A9136AAu);
    REQUIRE(crc32c(filled<32>(std::byte{0xFF})) == 0x62A8AB43u);

    std::array<std::byte, 32> ascending{};
    std::array<std::byte, 32> descending{};
    for (std::size_t i = 0; i < 32; ++i) {
        ascending[i] = static_cast<std::byte>(i);
        descending[i] = static_cast<std::byte>(31 - i);
    }
    REQUIRE(crc32c(ascending) == 0x46DD794Eu);
    REQUIRE(crc32c(descending) == 0x113FDB5Cu);
}

TEST_CASE("crc32c incremental equals one-shot for every split", "[utils][crc32c]") {
    constexpr std::string_view text = "The quick brown fox jumps over the lazy dog, twice over.";
    const auto bytes = as_bytes(text);
    const std::uint32_t whole = crc32c(bytes);
    for (std::size_t split = 0; split <= bytes.size(); ++split) {
        Rhp::utils::crc32c_hasher hasher;
        hasher.update(bytes.first(split));
        hasher.update(bytes.subspan(split));
        REQUIRE(hasher.value() == whole);
    }
}
