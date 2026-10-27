#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

#include <rhp/net/udp_reliable/detail/cookie.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/utils/byte_buffer.hpp>
#include <rhp/utils/siphash.hpp>

namespace Rhp::net::detail::rudp {

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
    return utils::siphash24(key, input);
}

} // namespace Rhp::net::detail::rudp
