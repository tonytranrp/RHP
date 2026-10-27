#include <cstddef>
#include <span>
#include <string_view>

#include <monocypher.h>

#include <rhp/security/detail/bytes.hpp>
#include <rhp/security/hash.hpp>

namespace Rhp::security {

using detail::u8;

digest256 blake2b_256(std::span<const std::byte> data) noexcept {
    digest256 out{};
    crypto_blake2b(u8(out.data()), out.size(), u8(data.data()), data.size());
    return out;
}

digest256 blake2b_256(std::string_view text) noexcept {
    return blake2b_256(std::as_bytes(std::span{text.data(), text.size()}));
}

digest256 keyed_blake2b_256(std::span<const std::byte> key, std::string_view domain, std::span<const std::byte> data) noexcept {
    constexpr std::size_t kMaxKey = 64;
    const std::size_t key_size = key.size() < kMaxKey ? key.size() : kMaxKey;
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, digest256{}.size(), u8(key.data()), key_size);
    crypto_blake2b_update(&ctx, u8(domain.data()), domain.size());
    crypto_blake2b_update(&ctx, u8(data.data()), data.size());
    digest256 out{};
    crypto_blake2b_final(&ctx, u8(out.data()));
    crypto_wipe(&ctx, sizeof ctx);
    return out;
}

bool digests_equal(std::span<const std::byte, 32> a, std::span<const std::byte, 32> b) noexcept {
    return crypto_verify32(u8(a.data()), u8(b.data())) == 0;
}

} // namespace Rhp::security
