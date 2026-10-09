#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/role.hpp>

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
// checkpoint, revert_to, revert_all, pin, unpin — including refused ones (`outcome` is kOk when it
// ran; a suspended request reports when it was started). `hash` is the BLAKE2b-256 of the source
// (hex) for exec / load / reload, `signer` who signed it (empty: unsigned).
struct script_executed {
    static constexpr std::string_view name = "script_executed";
    time_point time;
    session_id session;
    std::string identity;
    role granted = role::kObserve;
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

// Every host event, for handlers that take them all (the audit sinks).
using any = std::variant<session_opened, session_closed, auth_failed, script_executed, blob_received, identity_reverted>;

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
