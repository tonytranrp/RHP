#pragma once

#include <cstdint>

namespace Rhp {

// Which script runs check, every limits::cancel_check_instructions Lua instructions, for cancel().
// The check is a count hook that runs at safe points (loop back-edges and Lua calls), so armed code
// runs within a few percent of raw Lua; by default only requests pay even that. The instruction,
// wall-time and time-slice limits arm it for every run whatever this says.
enum class cancel_scope : std::uint8_t {
    // Nothing checks: cancel() and a client's cancel stop a request only before it starts or
    // resumes (a suspended one), never while its code runs. The fastest; for trusted scripts.
    kNone,
    // exec / load / call / reload / rollback and rhp.spawn tasks, the coroutines they create and
    // the C++ they call: what a client's cancel and sandbox::cancel(request) stop. Handler calls
    // (timers, frame callbacks, events, patch handlers hit from game code) run unchecked.
    kRequests,
    // Every run, handlers included: sandbox::cancel() also stops a handler stuck in a loop.
    kEverything,
};

// Structural, so it can be a template argument: Rhp::config<>::limits<Rhp::limits{ .memory = 64_MiB }>.
// 0 usually means unlimited / off; each field's comment says what 0 does. Defaults follow the decided
// policy: unlimited, run to completion.
struct limits {
    std::uint64_t instructions = 0;                       // total per run, counted at safe points (each loop iteration its body's length, each Lua call 1: an arithmetic loop counts up to ~1.7x the instructions it runs); once hit, sticky for the rest of that run; 0 = no limit
    std::uint64_t memory = 0;                             // bytes per lua_State; once hit, sticky for the rest of that run; 0 = no limit
    std::uint32_t wall_ms = 0;                            // time spent running (not suspended) per run or handler call; 0 = no limit
    std::uint32_t slice_us = 0;                           // opt-in time slicing per pump(); 0 = run to completion
    std::uint32_t max_frame = 4u * 1024u * 1024u;         // payload bytes per wire frame, both ways (larger ones are refused); 0 = only empty payloads
    std::uint64_t max_blob = 256ull * 1024ull * 1024ull;  // bytes per blob (host.on_blob); 0 = only empty blobs
    std::uint32_t revisions = 8;                          // revisions kept per module; 0 keeps 1 (the live one)
    std::uint32_t pending_handshakes = 64;                // unauthenticated connections allowed at once (a new one takes the place of the oldest that has sent nothing, else of the oldest still waiting after handshake_timeout_ms / 4); 0 = every connection is refused
    std::uint32_t handshakes_per_source = 8;              // unauthenticated connections at once from one IPv4 address or IPv6 /64 (links without an IP address don't count); 0 = no per-source cap
    std::uint32_t handshake_timeout_ms = 5'000;           // a connection that hasn't authenticated by then is dropped (also an HTTP gateway request's head); 0 = no deadline
    std::uint32_t first_byte_ms = 2'000;                  // an unauthenticated connection that has sent nothing by then is dropped; 0 = no deadline
    std::uint32_t heartbeat_ms = 2'000;                   // a ping per interval on a quiet session; 0 = no heartbeats (a dead link is noticed only by the transport)
    std::uint32_t heartbeat_misses = 3;                   // quiet intervals in a row before the link counts as dead; 0 = never
    std::uint32_t resume_ms = 6'000;                      // a lost link may come back (resume) within this; 0 = a lost link ends the session
    std::uint32_t backoff_min_ms = 250;                   // the first redial's delay ceiling (doubling up to backoff_max_ms, full jitter); 0 acts as 1
    std::uint32_t backoff_max_ms = 30'000;                // the largest redial delay; below backoff_min_ms acts as backoff_min_ms
    std::uint32_t gateway_idle_ms = 5u * 60u * 1000u;     // an HTTP gateway identity with no request in flight ends after this; 0 = never
    std::uint32_t cancel_check_instructions = 1'000;      // instructions between cancel checks (see cancel_scope); 0 = the default, 1'000
    cancel_scope cancel_checks = cancel_scope::kRequests; // which runs check for cancel() (see cancel_scope)
    std::uint32_t event_queue = 65'536;                   // events queued per sandbox for its next pump() (other threads' fires, rhp.publish); 0 = unlimited
    std::uint32_t async_ms = 0;                           // script time an asynchronous binding (Rhp::async<T>) may take before the script gets kTimeout; 0 = no limit
    std::uint32_t request_rate = 0;                       // requests per second per identity, in bursts of up to as many (a token bucket on the host's clock; a blob counts once); one over it is answered kLimitExceeded without running; 0 = no limit
    std::uint32_t pump_requests = 0;                      // requests started per identity per pump(), identities taking turns; the rest wait in order for the next pump(); 0 = every one that arrived
    std::uint32_t handlers = 0;                           // timers, frame callbacks, subscriptions and tasks alive at once per sandbox; registering one more raises kLimitExceeded; 0 = no limit

    [[nodiscard]] constexpr bool operator==(const limits&) const = default;
};

inline constexpr limits kDefaultLimits{};

} // namespace Rhp
