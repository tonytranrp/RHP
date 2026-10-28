#include <format>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/hardening.hpp>
#include <rhp/core/limits.hpp>

using Rhp::cancel_scope;
using Rhp::hardening;
using Rhp::limits;

TEST_CASE("hardening: the build's level is what CMake wrote and the levels are ordered", "[core][hardening]") {
    STATIC_REQUIRE(static_cast<int>(Rhp::kBuildHardening) == RHP_HARDENING);
    STATIC_REQUIRE(hardening::kDev < hardening::kLan);
    STATIC_REQUIRE(hardening::kLan < hardening::kProduction);
    STATIC_REQUIRE(Rhp::strictest(hardening::kDev, hardening::kLan) == hardening::kLan);
    STATIC_REQUIRE(Rhp::strictest(hardening::kProduction, hardening::kLan) == hardening::kProduction);
    STATIC_REQUIRE(Rhp::strictest(hardening::kDev, hardening::kDev) == hardening::kDev);
    CHECK(std::format("{} {} {}", hardening::kDev, hardening::kLan, hardening::kProduction) == "dev lan production");
}

TEST_CASE("hardening: capped turns unlimited and larger limits into the cap", "[core][hardening]") {
    constexpr limits caps{.instructions = 1'000, .memory = 4'096, .wall_ms = 50, .cancel_checks = cancel_scope::kEverything, .event_queue = 8, .async_ms = 0};

    constexpr limits unlimited{.instructions = 0, .memory = 0, .wall_ms = 0, .cancel_checks = cancel_scope::kNone, .event_queue = 0, .async_ms = 30};
    constexpr limits a = Rhp::capped(unlimited, caps);
    STATIC_REQUIRE(a.instructions == 1'000);
    STATIC_REQUIRE(a.memory == 4'096);
    STATIC_REQUIRE(a.wall_ms == 50);
    STATIC_REQUIRE(a.cancel_checks == cancel_scope::kEverything);
    STATIC_REQUIRE(a.event_queue == 8);
    STATIC_REQUIRE(a.async_ms == 30); // a cap of 0 is no cap

    constexpr limits rates{.request_rate = 5, .pump_requests = 2, .handlers = 3};
    constexpr limits r = Rhp::capped(limits{.request_rate = 0, .pump_requests = 9, .handlers = 1}, rates);
    STATIC_REQUIRE(r.request_rate == 5);
    STATIC_REQUIRE(r.pump_requests == 2);
    STATIC_REQUIRE(r.handlers == 1);

    constexpr limits tighter{.instructions = 10, .memory = 100, .wall_ms = 5, .event_queue = 2};
    constexpr limits b = Rhp::capped(tighter, caps);
    STATIC_REQUIRE(b.instructions == 10);
    STATIC_REQUIRE(b.memory == 100);
    STATIC_REQUIRE(b.wall_ms == 5);
    STATIC_REQUIRE(b.event_queue == 2);

    constexpr limits larger{.instructions = 1'000'000, .memory = 1u << 30, .wall_ms = 60'000};
    constexpr limits c = Rhp::capped(larger, caps);
    STATIC_REQUIRE(c.instructions == 1'000);
    STATIC_REQUIRE(c.memory == 4'096);
    STATIC_REQUIRE(c.wall_ms == 50);

    // cancel_check_instructions: 0 is the default (1'000), not unlimited.
    constexpr limits checks{.cancel_check_instructions = 5'000};
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 0xFFFF'FFFF}, checks).cancel_check_instructions == 5'000);
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 200}, checks).cancel_check_instructions == 200);
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 0}, checks).cancel_check_instructions == 0);
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 0}, limits{.cancel_check_instructions = 500}).cancel_check_instructions == 500);
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 0xFFFF'FFFF}, limits{.cancel_check_instructions = 0}).cancel_check_instructions == 0xFFFF'FFFF);

    // Network and wire limits are host-wide, not per role: caps never touch them.
    constexpr limits wire{.max_frame = 123, .pending_handshakes = 0, .resume_ms = 0};
    constexpr limits d = Rhp::capped(wire, caps);
    STATIC_REQUIRE(d.max_frame == 123);
    STATIC_REQUIRE(d.pending_handshakes == 0);
    STATIC_REQUIRE(d.resume_ms == 0);
    STATIC_REQUIRE(d.slice_us == 0);
}

TEST_CASE("hardening: the observe and production caps bound every run", "[core][hardening]") {
    constexpr limits observe = Rhp::capped(limits{}, Rhp::kObserveCaps);
    STATIC_REQUIRE(observe.instructions != 0);
    STATIC_REQUIRE(observe.memory == 64ull * 1024 * 1024);
    STATIC_REQUIRE(observe.wall_ms != 0);
    STATIC_REQUIRE(observe.cancel_checks == cancel_scope::kEverything);
    STATIC_REQUIRE(observe.event_queue == 1024);
    STATIC_REQUIRE(observe.request_rate != 0);
    STATIC_REQUIRE(observe.pump_requests != 0);
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 0xFFFF'FFFF}, Rhp::kObserveCaps).cancel_check_instructions == 10'000);

    constexpr limits production = Rhp::capped(limits{}, Rhp::kProductionCaps);
    STATIC_REQUIRE(production.memory == 512ull * 1024 * 1024);
    STATIC_REQUIRE(production.wall_ms == 1'000);
    STATIC_REQUIRE(production.cancel_checks == cancel_scope::kEverything);
    STATIC_REQUIRE(production.event_queue == limits{}.event_queue);
    STATIC_REQUIRE(production.cancel_check_instructions == limits{}.cancel_check_instructions);
    STATIC_REQUIRE(Rhp::capped(limits{.cancel_check_instructions = 0xFFFF'FFFF}, Rhp::kProductionCaps).cancel_check_instructions == 10'000);
    // Observe in production: both caps, the tighter of each.
    constexpr limits both = Rhp::capped(production, Rhp::kObserveCaps);
    STATIC_REQUIRE(both.memory == observe.memory);
    STATIC_REQUIRE(both.wall_ms == observe.wall_ms);
}
