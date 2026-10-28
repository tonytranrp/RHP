#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <rhp/utils/byte_buffer.hpp>

namespace Rhp::utils {

// SipHash-2-4 (Aumasson and Bernstein, 2012) of `data` under a 128-bit `key`: a keyed 64-bit PRF
// built for short inputs. RHP uses it where a short keyed hash does and a layer has no keyed BLAKE2b:
// the reliable UDP transport's cookies, and what a sandbox shows for an object's address (tostring,
// %p; cmake/lua/lua_cxx.cpp).
[[nodiscard]] constexpr std::uint64_t siphash24(std::span<const std::byte, 16> key, std::span<const std::byte> data) noexcept {
    const auto word = [](std::span<const std::byte> at) { return load_le<std::uint64_t>(at.first<8>()); };
    const auto rotl = [](std::uint64_t x, int bits) { return (x << bits) | (x >> (64 - bits)); };
    const std::uint64_t k0 = word(key.first<8>());
    const std::uint64_t k1 = word(key.last<8>());
    std::uint64_t s0 = 0x736f'6d65'7073'6575u ^ k0;
    std::uint64_t s1 = 0x646f'7261'6e64'6f6du ^ k1;
    std::uint64_t s2 = 0x6c79'6765'6e65'7261u ^ k0;
    std::uint64_t s3 = 0x7465'6462'7974'6573u ^ k1;
    const auto rounds = [&](int n) {
        for (int i = 0; i < n; ++i) {
            s0 += s1;
            s1 = rotl(s1, 13) ^ s0;
            s0 = rotl(s0, 32);
            s2 += s3;
            s3 = rotl(s3, 16) ^ s2;
            s0 += s3;
            s3 = rotl(s3, 21) ^ s0;
            s2 += s1;
            s1 = rotl(s1, 17) ^ s2;
            s2 = rotl(s2, 32);
        }
    };
    const auto compress = [&](std::uint64_t m) {
        s3 ^= m;
        rounds(2);
        s0 ^= m;
    };
    const std::size_t whole = data.size() - data.size() % 8;
    for (std::size_t at = 0; at < whole; at += 8) {
        compress(word(data.subspan(at)));
    }
    // The last block: the bytes left over, and the message length in the top byte.
    std::uint64_t last = static_cast<std::uint64_t>(data.size()) << 56;
    for (std::size_t i = whole; i < data.size(); ++i) {
        last |= std::to_integer<std::uint64_t>(data[i]) << (8 * (i - whole));
    }
    compress(last);
    s2 ^= 0xff;
    rounds(4);
    return s0 ^ s1 ^ s2 ^ s3;
}

} // namespace Rhp::utils
