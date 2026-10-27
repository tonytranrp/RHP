#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

#include <rhp/net/udp_reliable/detail/cookie.hpp>
#include <rhp/platform/random.hpp>

namespace Rhp::net::detail::rudp {

namespace {

[[nodiscard]] constexpr std::uint64_t rotl(std::uint64_t x, int bits) noexcept {
    return (x << bits) | (x >> (64 - bits));
}

[[nodiscard]] std::uint64_t load64(const std::byte* at) noexcept {
    return utils::load_le<std::uint64_t>(std::span<const std::byte, 8>{at, 8});
}

} // namespace

std::uint64_t siphash24(const cookie_key& key, utils::bytes_view data) noexcept {
    const std::uint64_t k0 = load64(key.data());
    const std::uint64_t k1 = load64(key.data() + 8);
    std::uint64_t v0 = 0x736f'6d65'7073'6575u ^ k0;
    std::uint64_t v1 = 0x646f'7261'6e64'6f6du ^ k1;
    std::uint64_t v2 = 0x6c79'6765'6e65'7261u ^ k0;
    std::uint64_t v3 = 0x7465'6462'7974'6573u ^ k1;
    const auto round = [&]() noexcept {
        v0 += v1;
        v1 = rotl(v1, 13);
        v1 ^= v0;
        v0 = rotl(v0, 32);
        v2 += v3;
        v3 = rotl(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = rotl(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = rotl(v1, 17);
        v1 ^= v2;
        v2 = rotl(v2, 32);
    };
    const std::size_t whole = data.size() - data.size() % 8;
    for (std::size_t at = 0; at < whole; at += 8) {
        const std::uint64_t m = load64(data.data() + at);
        v3 ^= m;
        round();
        round();
        v0 ^= m;
    }
    std::uint64_t last = static_cast<std::uint64_t>(data.size()) << 56;
    for (std::size_t i = whole; i < data.size(); ++i) {
        last |= std::to_integer<std::uint64_t>(data[i]) << (8 * (i - whole));
    }
    v3 ^= last;
    round();
    round();
    v0 ^= last;
    v2 ^= 0xff;
    round();
    round();
    round();
    round();
    return v0 ^ v1 ^ v2 ^ v3;
}

result<cookie_jar> cookie_jar::make(time_point now) {
    cookie_jar jar;
    auto current = platform::random_array<16>();
    auto previous = platform::random_array<16>();
    if (!current || !previous) {
        return std::unexpected{!current ? std::move(current).error() : std::move(previous).error()};
    }
    jar.origin_ = now;
    jar.current_ = *current;
    jar.previous_ = *previous;
    return jar;
}

std::uint64_t cookie_jar::issue(time_point now, const hello_source& from) {
    rotate(now);
    return mac(current_, bucket_, from);
}

bool cookie_jar::valid(time_point now, const hello_source& from, std::uint64_t cookie) {
    rotate(now);
    return cookie == mac(current_, bucket_, from) || (bucket_ != 0 && cookie == mac(previous_, bucket_ - 1, from));
}

void cookie_jar::rotate(time_point now) {
    const auto elapsed = now > origin_ ? now - origin_ : time_point::duration{};
    const auto bucket = static_cast<std::uint64_t>(elapsed / kCookiePeriod);
    if (bucket <= bucket_) {
        return;
    }
    // The secret of the period that just ended stays valid for one more; anything older goes. (A
    // failing OS random source keeps the old secret: its cookies then live a little longer.)
    const cookie_key ended = current_;
    if (auto fresh = platform::random_array<16>()) {
        current_ = *fresh;
    }
    if (bucket == bucket_ + 1) {
        previous_ = ended;
    } else if (auto fresh = platform::random_array<16>()) {
        previous_ = *fresh;
    }
    bucket_ = bucket;
}

std::uint64_t cookie_jar::mac(const cookie_key& key, std::uint64_t bucket, const hello_source& from) noexcept {
    std::array<std::byte, 16 + 2 + 8 + 8> input{};
    for (std::size_t i = 0; i < from.address.size(); ++i) {
        input[i] = static_cast<std::byte>(from.address[i]);
    }
    utils::store_le<std::uint16_t>(std::span<std::byte, 2>{input.data() + 16, 2}, from.port);
    utils::store_le<std::uint64_t>(std::span<std::byte, 8>{input.data() + 18, 8}, from.token);
    utils::store_le<std::uint64_t>(std::span<std::byte, 8>{input.data() + 26, 8}, bucket);
    return siphash24(key, input);
}

} // namespace Rhp::net::detail::rudp
