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
#define RHP_TARGET_SSE42
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

// ---- the CRC instruction, three streams at a time ------------------------------------------------------
//
// The instruction has a latency of about three cycles but can start one per cycle: three independent
// streams over three blocks keep it busy, and the blocks' CRCs are then combined. Combining shifts a CRC
// over a block of zeros (by linearity, crc(A || B) = shift(crc(A), |B|) ^ crc(B) for the raw register),
// which the tables below do for the two block sizes. Mark Adler's method (zlib's crc32_combine, his
// crc32c.c).

#if defined(RHP_CRC32C_X86) || defined(RHP_CRC32C_ARM)

constexpr std::size_t kLongBlock = 8192;
constexpr std::size_t kShortBlock = 256;

using shift_t = std::array<std::array<std::uint32_t, 256>, 4>;

consteval std::uint32_t gf2_times(const std::array<std::uint32_t, 32>& mat, std::uint32_t vec) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; vec != 0; ++i, vec >>= 1) {
        if ((vec & 1u) != 0) {
            sum ^= mat[i];
        }
    }
    return sum;
}

consteval std::array<std::uint32_t, 32> gf2_square(const std::array<std::uint32_t, 32>& mat) {
    std::array<std::uint32_t, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) {
        out[i] = gf2_times(mat, mat[i]);
    }
    return out;
}

// The operator that appends `bytes` zero bytes (a power of two) to a raw CRC register.
consteval std::array<std::uint32_t, 32> zeros_operator(std::size_t bytes) {
    std::array<std::uint32_t, 32> one_bit{};
    one_bit[0] = kPolynomial;
    for (std::size_t i = 1; i < 32; ++i) {
        one_bit[i] = std::uint32_t{1} << (i - 1);
    }
    std::array<std::uint32_t, 32> op = gf2_square(gf2_square(gf2_square(one_bit))); // one byte
    for (; bytes > 1; bytes >>= 1) {
        op = gf2_square(op);
    }
    return op;
}

consteval shift_t make_shift(std::size_t bytes) {
    const std::array<std::uint32_t, 32> op = zeros_operator(bytes);
    shift_t table{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        table[0][i] = gf2_times(op, i);
        table[1][i] = gf2_times(op, i << 8);
        table[2][i] = gf2_times(op, i << 16);
        table[3][i] = gf2_times(op, i << 24);
    }
    return table;
}

constexpr shift_t kShiftLong = make_shift(kLongBlock);
constexpr shift_t kShiftShort = make_shift(kShortBlock);

constexpr std::uint32_t shift(const shift_t& table, std::uint32_t crc) noexcept {
    return table[0][crc & 0xFFu] ^ table[1][(crc >> 8) & 0xFFu] ^ table[2][(crc >> 16) & 0xFFu] ^ table[3][crc >> 24];
}

#endif

#if defined(RHP_CRC32C_X86)

RHP_TARGET_SSE42 inline std::uint32_t step64(std::uint32_t crc, const std::byte* p) noexcept {
    std::uint64_t v = 0;
    std::memcpy(&v, p, 8); // little-endian: the instruction takes the bytes in memory order
    return static_cast<std::uint32_t>(_mm_crc32_u64(crc, v));
}

RHP_TARGET_SSE42 inline std::uint32_t step8(std::uint32_t crc, std::byte b) noexcept {
    return _mm_crc32_u8(crc, static_cast<unsigned char>(b));
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

inline std::uint32_t step64(std::uint32_t crc, const std::byte* p) noexcept {
    std::uint64_t v = 0;
    std::memcpy(&v, p, 8);
    return __crc32cd(crc, v);
}

inline std::uint32_t step8(std::uint32_t crc, std::byte b) noexcept {
    return __crc32cb(crc, static_cast<std::uint8_t>(b));
}

#endif

#if defined(RHP_CRC32C_X86) || defined(RHP_CRC32C_ARM)

// `Block` bytes from each of three consecutive blocks per step, then the three combined.
template <std::size_t Block>
RHP_TARGET_SSE42 std::uint32_t three_blocks(const std::byte*& p, std::size_t& n, std::uint32_t crc, const shift_t& table) noexcept {
    while (n >= 3 * Block) {
        std::uint32_t crc1 = 0;
        std::uint32_t crc2 = 0;
        for (const std::byte* end = p + Block; p < end; p += 8) {
            crc = step64(crc, p);
            crc1 = step64(crc1, p + Block);
            crc2 = step64(crc2, p + 2 * Block);
        }
        crc = shift(table, crc) ^ crc1;
        crc = shift(table, crc) ^ crc2;
        p += 2 * Block;
        n -= 3 * Block;
    }
    return crc;
}

// One stream: what a small frame needs, and the tail of a large one.
RHP_TARGET_SSE42 std::uint32_t single_stream(const std::byte* p, std::size_t n, std::uint32_t crc) noexcept {
#if defined(RHP_CRC32C_X86)
    std::uint64_t c = crc; // the 64-bit instruction keeps its register 64 bits wide between steps
    for (; n >= 8; p += 8, n -= 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, p, 8);
        c = _mm_crc32_u64(c, v);
    }
    crc = static_cast<std::uint32_t>(c);
#else
    for (; n >= 8; p += 8, n -= 8) {
        crc = step64(crc, p);
    }
#endif
    while (n-- > 0) {
        crc = step8(crc, *p++);
    }
    return crc;
}

RHP_TARGET_SSE42 std::uint32_t crc32c_hw(const std::byte* p, std::size_t n, std::uint32_t crc) noexcept {
    if (n >= 3 * kShortBlock) { // a small frame goes straight to the single stream
        crc = three_blocks<kLongBlock>(p, n, crc, kShiftLong);
        crc = three_blocks<kShortBlock>(p, n, crc, kShiftShort);
    }
    return single_stream(p, n, crc);
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
