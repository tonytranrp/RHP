#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

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

TEST_CASE("crc32c matches the portable tables for every length and alignment", "[utils][crc32c]") {
    // Whichever implementation crc32c picked (CPU instruction or tables), the tails and odd
    // alignments must agree with the table version byte for byte.
    std::array<std::byte, 300> data{};
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::byte>((i * 131u + 17u) & 0xFFu);
    }
    for (std::size_t offset = 0; offset < 8; ++offset) {
        for (std::size_t length = 0; length + offset <= data.size(); length += 7) {
            const std::span<const std::byte> view{data.data() + offset, length};
            REQUIRE(crc32c(view) == Rhp::utils::crc32c_portable(view));
            REQUIRE(crc32c(view, 0x12345678u) == Rhp::utils::crc32c_portable(view, 0x12345678u));
        }
    }
}

TEST_CASE("crc32c matches the portable tables across the three-block paths", "[utils][crc32c]") {
    // Lengths around 3 x 256 and 3 x 8192 (where the instruction runs three streams and combines
    // them), odd offsets, initial values, and incremental splits inside and across those blocks.
    std::vector<std::byte> data(3 * 8192 * 2 + 64);
    std::uint32_t x = 0x9E3779B9u;
    for (std::byte& b : data) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b = static_cast<std::byte>(x & 0xFFu);
    }
    for (const std::size_t length : {std::size_t{767}, std::size_t{768}, std::size_t{769}, std::size_t{1543}, std::size_t{24575}, std::size_t{24576},
                                     std::size_t{24577}, std::size_t{49152}, std::size_t{49159}}) {
        for (const std::size_t offset : {std::size_t{0}, std::size_t{1}, std::size_t{3}, std::size_t{7}}) {
            CAPTURE(length, offset);
            const std::span<const std::byte> view{data.data() + offset, length};
            REQUIRE(crc32c(view) == Rhp::utils::crc32c_portable(view));
            REQUIRE(crc32c(view, 0xDEADBEEFu) == Rhp::utils::crc32c_portable(view, 0xDEADBEEFu));
            for (const std::size_t split : {std::size_t{1}, std::size_t{255}, length / 2, length - 9}) {
                Rhp::utils::crc32c_hasher hasher;
                hasher.update(view.first(split));
                hasher.update(view.subspan(split));
                REQUIRE(hasher.value() == Rhp::utils::crc32c_portable(view));
            }
        }
    }
}
