#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::event {

// What a host reports (host.on<E>(fn), host.on_any(fn)). Every event carries the wall-clock time it
// happened; `peer` is the transport's address of the client ("127.0.0.1:51234").
using time_point = std::chrono::system_clock::time_point;

// A client authenticated.
struct session_opened {
    static constexpr std::string_view name = "session_opened";
    time_point time;
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::string peer;
    std::string platform;
    bool tls = false; // the connection is TLS
};

// A session continued on a new connection after its link was lost (resume): nothing was reverted
// and no request ran twice.
struct session_resumed {
    static constexpr std::string_view name = "session_resumed";
    time_point time;
    session_id session;
    std::string identity;
    std::string peer; // the new connection's address
    bool tls = false;
};

// An authenticated session ended (`reason`: the peer closed, the heartbeat lapsed, ...).
struct session_closed {
    static constexpr std::string_view name = "session_closed";
    time_point time;
    session_id session;
    std::string identity;
    std::string peer;
    error reason;
};

// A connection never authenticated (wrong key, unknown key name, timeout, garbage).
struct auth_failed {
    static constexpr std::string_view name = "auth_failed";
    time_point time;
    std::string peer;
    error reason;
};

// A request that runs code or changes state: exec, load, reload, rollback, call, revert, unload,
// checkpoint, revert_to, revert_all, pin, unpin - including refused ones (`outcome` is kOk when it
// ran; a suspended request is reported when it finishes, with its final outcome, or kCancelled if
// its identity is torn down first). `hash` is the BLAKE2b-256 of the source
// (hex) for exec / load / reload, `signer` who signed it (empty: unsigned).
struct script_executed {
    static constexpr std::string_view name = "script_executed";
    time_point time;
    session_id session;
    std::string identity;
    role granted = role::kObserve;
    std::string peer; // who sent this request (over HTTP each request has its own)
    std::string op;
    std::string module;
    std::string hash;
    std::string signer;
    error outcome;
};

// A blob transfer finished (or was refused); `outcome` is the sink's verdict.
struct blob_received {
    static constexpr std::string_view name = "blob_received";
    time_point time;
    session_id session;
    std::string identity;
    std::string sink;
    std::string file;
    std::uint64_t size = 0;
    std::string hash; // BLAKE2b-256 of the bytes (hex), when they all arrived
    error outcome;
};

// An identity's last session ended and the host reverted what it did (pinned modules are kept).
struct identity_reverted {
    static constexpr std::string_view name = "identity_reverted";
    time_point time;
    std::string identity;
    std::uint64_t undone = 0;
    std::uint64_t irreversible = 0;
    std::uint64_t failures = 0;
    std::uint64_t pinned = 0; // modules kept
};

// A timer, frame callback, event handler or task of a script failed (script::handler_error_policy
// decides what was done: `action` is "report", "remove" or "fault").
struct handler_failed {
    static constexpr std::string_view name = "handler_failed";
    time_point time;
    std::string identity;
    std::string module;
    std::string kind;   // "timer", "frame", "event" or "task"
    std::string source; // the event name, or "timer" / "frame" / "task"
    std::uint64_t handler = 0; // the id the script holds (0: none)
    std::string action;
    error outcome;
};

// A served release manager (host.serve) changed what a channel runs, or refused a release.
// `kind`: "applied", "confirmed", "rolled_back", "refused" or "revocations"; ids are hex.
struct release_changed {
    static constexpr std::string_view name = "release_changed";
    time_point time;
    std::string kind;
    std::string channel;
    std::string release;  // what it is about (empty: none)
    std::string fallback; // rolled_back: what runs instead (empty: nothing)
    std::uint64_t seq = 0;
    std::string reason;   // rolled_back: why ("unhealthy: ...", "deactivated", "revoked", "expired")
    error outcome;        // refused: why
};

// Every host event, for handlers that take them all (the audit sinks). New kinds go at the end.
using any = std::variant<session_opened, session_closed, auth_failed, script_executed, blob_received, identity_reverted, session_resumed, handler_failed,
                         release_changed>;

// An rhp.publish of some identity's script (host.on_script_event). Not part of `any`: script events
// are application traffic, not an audit record.
struct script_event {
    static constexpr std::string_view name = "script_event";
    time_point time;
    std::string identity;
    std::string module; // the publishing module (empty: the sandbox itself, e.g. rhp.handler_failed)
    std::string event;
    std::vector<value> args;
};

namespace detail {

template <class E, class V>
struct index_of;

template <class E, class... Ts>
struct index_of<E, std::variant<Ts...>> {
    static constexpr std::size_t find() {
        std::size_t i = 0;
        const bool found = ((std::is_same_v<E, Ts> ? true : (++i, false)) || ...);
        return found ? i : sizeof...(Ts);
    }
    static constexpr std::size_t value = find();
};

} // namespace detail

// One of the event types above.
template <class E>
concept host_event = detail::index_of<E, any>::value < std::variant_size_v<any>;

template <host_event E>
inline constexpr std::size_t kind_of = detail::index_of<E, any>::value;

// One line of JSON (no trailing newline): {"event":"script_executed","time":"2026-10-08T22:13:00.123Z",...}.
[[nodiscard]] std::string to_json(const any& e);

} // namespace Rhp::event
