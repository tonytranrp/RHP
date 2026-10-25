#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <rhp/utils/crc32c.hpp>

// The CPU's CRC32C instruction where there is one: SSE4.2 on x86-64 (checked at run time), the
// ARMv8 CRC extension on ARM64 when the compiler targets it. Everywhere else, the slicing-by-8 table.
#if defined(_M_X64) || defined(__x86_64__)
#define RHP_CRC32C_X86 1
#include <nmmintrin.h>
#if defined(_MSC_VER)
#include <intrin.h> // __cpuid (clang-cl too)
#else
#include <cpuid.h>
#endif
// cl.exe compiles the intrinsic for any target; Clang (clang-cl included) wants the feature on the
// function that uses it.
#if defined(_MSC_VER) && !defined(__clang__)
#define RHP_TARGET_SSE42
#else
#define RHP_TARGET_SSE42 __attribute__((target("sse4.2")))
#endif
#elif defined(__aarch64__) && defined(__ARM_FEATURE_CRC32)
#define RHP_CRC32C_ARM 1
#include <arm_acle.h>
#endif

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

// `crc` is the running (inverted) register in all three.
std::uint32_t crc32c_table(const std::byte* p, std::size_t n, std::uint32_t crc) noexcept {
    while (n >= 8) {
        const std::uint32_t lo = crc ^ load_le<std::uint32_t>(std::span<const std::byte, 4>{p, 4});
        const std::uint32_t hi = load_le<std::uint32_t>(std::span<const std::byte, 4>{p + 4, 4});
        crc = kTables[7][lo & 0xFFu] ^ kTables[6][(lo >> 8) & 0xFFu] ^ kTables[5][(lo >> 16) & 0xFFu] ^ kTables[4][lo >> 24] ^
              kTables[3][hi & 0xFFu] ^ kTables[2][(hi >> 8) & 0xFFu] ^ kTables[1][(hi >> 16) & 0xFFu] ^ kTables[0][hi >> 24];
        p += 8;
        n -= 8;
    }
    while (n-- > 0) {
        crc = (crc >> 8) ^ kTables[0][(crc ^ static_cast<std::uint32_t>(*p++)) & 0xFFu];
    }
    return crc;
}

#if defined(RHP_CRC32C_X86)

RHP_TARGET_SSE42 std::uint32_t crc32c_hw(const std::byte* p, std::size_t n, std::uint32_t crc) noexcept {
    std::uint64_t c = crc;
    while (n >= 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, p, 8); // little-endian: the instruction takes the bytes in memory order
        c = _mm_crc32_u64(c, v);
        p += 8;
        n -= 8;
    }
    auto c32 = static_cast<std::uint32_t>(c);
    while (n-- > 0) {
        c32 = _mm_crc32_u8(c32, static_cast<unsigned char>(*p++));
    }
    return c32;
}

bool cpu_has_sse42() noexcept {
#if defined(_MSC_VER)
    int info[4] = {};
    __cpuid(info, 1);
    return (info[2] & (1 << 20)) != 0;
#else
    unsigned a = 0;
    unsigned b = 0;
    unsigned c = 0;
    unsigned d = 0;
    return __get_cpuid(1, &a, &b, &c, &d) != 0 && (c & bit_SSE4_2) != 0;
#endif
}

#elif defined(RHP_CRC32C_ARM)

std::uint32_t crc32c_hw(const std::byte* p, std::size_t n, std::uint32_t crc) noexcept {
    while (n >= 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, p, 8);
        crc = __crc32cd(crc, v);
        p += 8;
        n -= 8;
    }
    while (n-- > 0) {
        crc = __crc32cb(crc, static_cast<std::uint8_t>(*p++));
    }
    return crc;
}

#endif

} // namespace

std::uint32_t crc32c(bytes_view data, std::uint32_t crc) noexcept {
#if defined(RHP_CRC32C_X86)
    static const bool hardware = cpu_has_sse42();
    if (hardware) {
        return ~crc32c_hw(data.data(), data.size(), ~crc);
    }
#elif defined(RHP_CRC32C_ARM)
    return ~crc32c_hw(data.data(), data.size(), ~crc);
#endif
    return ~crc32c_table(data.data(), data.size(), ~crc);
}

std::uint32_t crc32c_portable(bytes_view data, std::uint32_t crc) noexcept {
    return ~crc32c_table(data.data(), data.size(), ~crc);
}

} // namespace Rhp::utils
