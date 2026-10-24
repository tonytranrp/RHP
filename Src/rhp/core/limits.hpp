#pragma once

#include <cstdint>

namespace Rhp {

// Structural, so it can be a template argument: Rhp::config<>::limits<Rhp::limits{ .memory = 64_MiB }>.
// 0 usually means unlimited / off (some fields differ: see each). Defaults follow the decided policy:
// unlimited, run to completion.
struct limits {
    std::uint64_t instructions = 0; // total per run; once hit, sticky for the rest of that run
    std::uint64_t memory = 0;       // bytes per lua_State; once hit, sticky for the rest of that run
    std::uint32_t wall_ms = 0;      // time spent running (not suspended) per run or handler call
    std::uint32_t slice_us = 0;     // opt-in time slicing per pump(); 0 = run to completion
    std::uint32_t max_frame = 4u * 1024u * 1024u;
    std::uint64_t max_blob = 256ull * 1024ull * 1024ull; // bytes per blob (host.on_blob); 0 = only empty blobs
    std::uint32_t revisions = 8;           // revisions kept per module
    std::uint32_t pending_handshakes = 64; // unauthenticated connections allowed at once
    std::uint32_t handshake_timeout_ms = 5'000;
    std::uint32_t heartbeat_ms = 2'000;
    std::uint32_t heartbeat_misses = 3;
    std::uint32_t resume_ms = 6'000; // a lost link may come back (resume) within this; 0 = a lost link ends the session
    std::uint32_t backoff_min_ms = 250;
    std::uint32_t backoff_max_ms = 30'000;
    std::uint32_t gateway_idle_ms = 5u * 60u * 1000u;
    std::uint32_t cancel_check_instructions = 1'000;
    std::uint32_t event_queue = 65'536; // events queued per sandbox for its next pump() (other threads' fires, rhp.publish); 0 = unlimited

    [[nodiscard]] constexpr bool operator==(const limits&) const = default;
};

inline constexpr limits kDefaultLimits{};

} // namespace Rhp
