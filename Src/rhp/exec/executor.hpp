#pragma once

#include <chrono>
#include <concepts>

namespace Rhp::exec {

// Executor policy for Rhp::config<>::executor<...>: where scripts run. Stage 3 has one: scripts
// run on the thread that calls host.pump() (an RHP-owned script thread may follow later).
template <class X>
concept executor = requires {
    { X::kRunsInPump } -> std::convertible_to<bool>;
};

struct pumped {
    static constexpr bool kRunsInPump = true;
};

static_assert(executor<pumped>);

// Clock policy for Rhp::config<>::clock<...>: script time (rhp.sleep, rhp.timer) and the HTTP
// listener's idle expiry (through an offset host.pump() samples, so now() is only called on the
// pump thread). Inject game time or a manual clock for deterministic tests; limits, heartbeats and
// HTTP proof freshness always use the steady / system clocks.
template <class K>
concept clock_source = std::default_initializable<K> && requires(const K& k) {
    { k.now() } -> std::same_as<std::chrono::steady_clock::time_point>;
};

struct steady_clock {
    [[nodiscard]] static std::chrono::steady_clock::time_point now() noexcept { return std::chrono::steady_clock::now(); }
};

static_assert(clock_source<steady_clock>);

} // namespace Rhp::exec
