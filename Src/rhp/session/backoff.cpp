#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>

#include <rhp/core/limits.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/session/backoff.hpp>

namespace Rhp::session {

std::chrono::milliseconds backoff_delay(const Rhp::limits& limits, std::uint32_t attempts, std::mt19937_64& rng, bool quick_first) {
    const std::uint32_t lo = limits.backoff_min_ms == 0 ? 1 : limits.backoff_min_ms;
    const std::uint32_t hi = limits.backoff_max_ms < lo ? lo : limits.backoff_max_ms;
    const std::uint64_t ceiling = quick_first && attempts == 0 ? 50 : std::min<std::uint64_t>(hi, static_cast<std::uint64_t>(lo) << std::min<std::uint32_t>(attempts, 20));
    std::uniform_int_distribution<std::uint64_t> pick{1, ceiling};
    return std::chrono::milliseconds{pick(rng)};
}

std::optional<std::uint64_t> random_seed() {
    auto bytes = platform::random_array<8>();
    if (!bytes) {
        return std::nullopt;
    }
    std::uint64_t k = 0;
    for (const std::byte b : *bytes) {
        k = (k << 8) | std::to_integer<std::uint64_t>(b);
    }
    return k;
}

} // namespace Rhp::session
