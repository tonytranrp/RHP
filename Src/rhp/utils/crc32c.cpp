#include <array>
#include <cstddef>
#include <cstdint>

#include <rhp/utils/crc32c.hpp>

namespace Rhp::utils {

namespace {

constexpr std::uint32_t kPolynomial = 0x82F63B78u;

using table_t = std::array<std::array<std::uint32_t, 256>, 8>;

consteval table_t make_tables() {
    table_t tables{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t crc = i;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1u) ? (crc >> 1) ^ kPolynomial : crc >> 1;
        }
        tables[0][i] = crc;
    }
    for (std::size_t t = 1; t < 8; ++t) {
        for (std::size_t i = 0; i < 256; ++i) {
            const std::uint32_t prev = tables[t - 1][i];
            tables[t][i] = (prev >> 8) ^ tables[0][prev & 0xFFu];
        }
    }
    return tables;
}

constexpr table_t kTables = make_tables();

} // namespace

std::uint32_t crc32c(bytes_view data, std::uint32_t crc) noexcept {
    crc = ~crc;
    const std::byte* p = data.data();
    std::size_t n = data.size();

    while (n >= 8) {
        const std::uint32_t lo = crc ^ load_le<std::uint32_t>(std::span<const std::byte, 4>{p, 4});
        const std::uint32_t hi = load_le<std::uint32_t>(std::span<const std::byte, 4>{p + 4, 4});
        crc = kTables[7][lo & 0xFFu] ^ kTables[6][(lo >> 8) & 0xFFu] ^
              kTables[5][(lo >> 16) & 0xFFu] ^ kTables[4][lo >> 24] ^
              kTables[3][hi & 0xFFu] ^ kTables[2][(hi >> 8) & 0xFFu] ^
              kTables[1][(hi >> 16) & 0xFFu] ^ kTables[0][hi >> 24];
        p += 8;
        n -= 8;
    }
    while (n-- > 0) {
        crc = (crc >> 8) ^ kTables[0][(crc ^ static_cast<std::uint32_t>(*p++)) & 0xFFu];
    }
    return ~crc;
}

} // namespace Rhp::utils
