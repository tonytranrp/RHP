#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <random>

#include <rhp/core/limits.hpp>

namespace Rhp::session {

// When to dial again after `attempts` failed dials (or a lost link): capped exponential backoff with
// full jitter, a random delay in [1, min(backoff_max_ms, backoff_min_ms * 2^attempts)] ms (a
// backoff_min_ms of 0 counts as 1). With `quick_first` the first try (attempts 0) comes within 50 ms.
// One draw from `rng`.
[[nodiscard]] std::chrono::milliseconds backoff_delay(const Rhp::limits& limits, std::uint32_t attempts, std::mt19937_64& rng, bool quick_first);

// 64 bits from the OS random source (platform::random_bytes), or nothing if it failed: a seed for a
// backoff generator, or a fresh key.
[[nodiscard]] std::optional<std::uint64_t> random_seed();

} // namespace Rhp::session
