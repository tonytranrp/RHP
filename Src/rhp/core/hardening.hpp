#pragma once

#include <cstdint>
#include <format>
#include <string_view>

#include <rhp/build_config.hpp>
#include <rhp/core/limits.hpp>

namespace Rhp {

// How much a build, a config or a host allows (decisions AL1 and AL2,
// Docs/decisions/stage13-security.md). Ordered: each level allows less than the one before.
//   kDev         everything: admin's full Lua standard library (io, os, package, debug), dev
//                sessions, insecure_lan, signer<unsigned_scripts>
//   kLan         admin gets patch's libraries; dev sessions, insecure_lan and unsigned_scripts are
//                refused; observe limits are capped (kObserveCaps)
//   kProduction  also: observe code must be signed, no remote debugger, every role's limits are
//                capped (kProductionCaps), no advertising, the HTTP gateway only with channel binding
//
// The build's level (RHP_HARDENING, kBuildHardening) is a ceiling: config<>::hardening<H> may only
// raise it (a weaker H fails to compile) and host_options::hardening only raise that; a host runs at
// the strictest of the three. What the build's level doesn't allow is compiled out (if constexpr on
// kBuildHardening), so no config, option or memory patch turns it back on.
enum class hardening : std::uint8_t {
    kDev,
    kLan,
    kProduction,
};

// The level this RHP was built with (CMake RHP_HARDENING=dev|lan|production).
inline constexpr hardening kBuildHardening = static_cast<hardening>(RHP_HARDENING);

static_assert(kBuildHardening <= hardening::kProduction, "RHP_HARDENING is 0 (dev), 1 (lan) or 2 (production)");

[[nodiscard]] constexpr hardening strictest(hardening a, hardening b) noexcept {
    return a < b ? b : a;
}

[[nodiscard]] constexpr std::string_view to_string(hardening h) noexcept {
    switch (h) {
    case hardening::kDev: return "dev";
    case hardening::kLan: return "lan";
    case hardening::kProduction: return "production";
    }
    return "unknown";
}

// The script limits a role may have at most (decision AL4). capped() reads these fields of a caps
// value: instructions, memory, wall_ms, event_queue, async_ms, request_rate, pump_requests, handlers and
// cancel_check_instructions (0 = no cap; limits{}'s 1'000 caps that one at its default), and
// cancel_checks (the least scope); the others (network and wire limits, host-wide rather than per
// role) mean nothing in it.
//
// Observe identities from kLan up: they run unsigned code there (and read-only code in production),
// so a run is short and bounded, every run checks for cancels, and one identity can't take the pump
// thread: at most pump_requests runs of at most wall_ms each per pump() (40 ms a frame), and at most
// request_rate runs a second (200 ms of every second).
inline constexpr limits kObserveCaps{
    .instructions = 2'000'000,           // a few ms of plain Lua: plenty for reading state
    .memory = 64ull * 1024 * 1024,       // 64 MiB per lua_State
    .wall_ms = 20,                       // a run longer than a frame is not a read
    .cancel_check_instructions = 10'000, // the wall cap and cancel() are seen within a fraction of a millisecond
    .cancel_checks = cancel_scope::kEverything,
    .event_queue = 1024, // events waiting for one identity's next pump()
    .async_ms = 0,
    .request_rate = 10, // a dashboard polling a few values a few times a second, with a burst of 10
    .pump_requests = 2, // runs one pump() starts for it
    .handlers = 0,      // no cap: observe can't register lasting handlers at all
};

// Every role in kProduction: a script can't take the process's memory or hold the pump thread for
// long, and cancel() stops anything. No instruction cap: the wall-time cap bounds a run already, and
// long loops that yield (rhp.wait, slices) stay possible.
inline constexpr limits kProductionCaps{
    .instructions = 0,
    .memory = 512ull * 1024 * 1024,      // 512 MiB per lua_State
    .wall_ms = 1'000,                    // per run or handler call, suspended time not counted
    .cancel_check_instructions = 10'000, // checked often enough for the wall cap and cancel() to bite
    .cancel_checks = cancel_scope::kEverything,
    .event_queue = 65'536, // the default: production can't make it unlimited
    .async_ms = 0,
    .request_rate = 0, // no cap: operators' signed scripts and rollouts; a host sets its own
    .pump_requests = 0,
    .handlers = 0,
};

// `value` with every capped field at most its cap: where the cap is nonzero, 0 (unlimited) or a
// larger value becomes the cap (for cancel_check_instructions, whose 0 means the default 1'000, a value
// that comes to more); cancel_checks becomes the stricter scope of the two.
[[nodiscard]] constexpr limits capped(limits value, const limits& caps) noexcept {
    const auto cap = [](auto& field, auto most) {
        if (most != 0 && (field == 0 || field > most)) {
            field = most;
        }
    };
    cap(value.instructions, caps.instructions);
    cap(value.memory, caps.memory);
    cap(value.wall_ms, caps.wall_ms);
    cap(value.event_queue, caps.event_queue);
    cap(value.async_ms, caps.async_ms);
    cap(value.request_rate, caps.request_rate);
    cap(value.pump_requests, caps.pump_requests);
    cap(value.handlers, caps.handlers);
    // Checks too far apart would let a run outlive its wall cap and ignore cancel() for billions of
    // instructions.
    const std::uint32_t every = value.cancel_check_instructions != 0 ? value.cancel_check_instructions : kDefaultLimits.cancel_check_instructions;
    if (caps.cancel_check_instructions != 0 && every > caps.cancel_check_instructions) {
        value.cancel_check_instructions = caps.cancel_check_instructions;
    }
    if (caps.cancel_checks > value.cancel_checks) {
        value.cancel_checks = caps.cancel_checks;
    }
    return value;
}

} // namespace Rhp

template <>
struct std::formatter<Rhp::hardening> : std::formatter<std::string_view> {
    auto format(Rhp::hardening h, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::to_string(h), ctx);
    }
};
