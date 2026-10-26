#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include <monocypher.h>

#include <rhp/security/hash.hpp>

namespace Rhp::security {

digest256 blake2b_256(std::span<const std::byte> data) noexcept {
    digest256 out{};
    crypto_blake2b(reinterpret_cast<std::uint8_t*>(out.data()), out.size(), reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    return out;
}

digest256 blake2b_256(std::string_view text) noexcept {
    return blake2b_256(std::as_bytes(std::span{text.data(), text.size()}));
}

digest256 keyed_blake2b_256(std::span<const std::byte> key, std::string_view domain, std::span<const std::byte> data) noexcept {
    constexpr std::size_t kMaxKey = 64;
    const std::size_t key_size = key.size() < kMaxKey ? key.size() : kMaxKey;
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, digest256{}.size(), reinterpret_cast<const std::uint8_t*>(key.data()), key_size);
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(domain.data()), domain.size());
    crypto_blake2b_update(&ctx, reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    digest256 out{};
    crypto_blake2b_final(&ctx, reinterpret_cast<std::uint8_t*>(out.data()));
    crypto_wipe(&ctx, sizeof ctx);
    return out;
}

bool digests_equal(const digest256& a, const digest256& b) noexcept {
    return crypto_verify32(reinterpret_cast<const std::uint8_t*>(a.data()), reinterpret_cast<const std::uint8_t*>(b.data())) == 0;
}

std::string to_hex(std::span<const std::byte> bytes) {
    constexpr std::string_view kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const std::byte b : bytes) {
        const auto n = std::to_integer<unsigned>(b);
        out += kDigits[n >> 4];
        out += kDigits[n & 15u];
    }
    return out;
}

} // namespace Rhp::security
