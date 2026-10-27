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
    std::uint64_t v0 = 0x736f'6d65'7073'6575u ^ k0;
    std::uint64_t v1 = 0x646f'7261'6e64'6f6du ^ k1;
    std::uint64_t v2 = 0x6c79'6765'6e65'7261u ^ k0;
    std::uint64_t v3 = 0x7465'6462'7974'6573u ^ k1;
    const auto rounds = [&](int n) {
        for (int i = 0; i < n; ++i) {
            v0 += v1;
            v1 = rotl(v1, 13) ^ v0;
            v0 = rotl(v0, 32);
            v2 += v3;
            v3 = rotl(v3, 16) ^ v2;
            v0 += v3;
            v3 = rotl(v3, 21) ^ v0;
            v2 += v1;
            v1 = rotl(v1, 17) ^ v2;
            v2 = rotl(v2, 32);
        }
    };
    const auto compress = [&](std::uint64_t m) {
        v3 ^= m;
        rounds(2);
        v0 ^= m;
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
    v2 ^= 0xff;
    rounds(4);
    return v0 ^ v1 ^ v2 ^ v3;
}

} // namespace Rhp::utils
