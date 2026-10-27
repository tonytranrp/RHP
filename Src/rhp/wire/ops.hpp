#pragma once

#include <cstdint>
#include <format>
#include <optional>
#include <string_view>

#include <rhp/core/role.hpp>

namespace Rhp::wire {

// The protocol revision both ends must agree on in hello. A plain integer, bumped on any change to
// the frame layout, the handshake or a message schema.
// 2: signatures, pin / unpin, blobs (Stage 4); 3: resume, CRC-less TLS frames (Stage 5);
// 4: subscribe / unsubscribe / event (Stage 7); 5: releases and revocation lists (Stage 10);
// 6: tunables, the profiler and the debugger (Stage 11).
inline constexpr std::uint8_t kProtocolRevision = 6;

// What a frame carries (the header's `op`, 16 bits on the wire).
//
//   handshake  1..15   unsequenced; hello / challenge / response unsealed, welcome and resume sealed
//   requests  16..47   client -> host, sequenced
//   replies   48..63   host -> client, sequenced
//   control   64..     unsequenced (seq = a per-direction control counter), MAC'd once the handshake is done
enum class op : std::uint16_t {
    kHello = 1, // client: protocol revision, platform, authenticator hello
    kChallenge, // host: protocol revision, platform, authenticator challenge
    kResponse,  // client: authenticator response
    kWelcome,   // host: session id, identity, role, heartbeat, platform; also the answer to a kResume
    kResume,    // the dialing side, on a new connection: continue session N (sealed, control counter)

    kExec = 16,
    kLoad,
    kCall,
    kReload,
    kRollback,
    kUnload,
    kRevert,
    kRevertTo,
    kCheckpoint,
    kRevertAll,
    kCancel,
    kList,
    kStatus,
    kDescribe,
    kPin,   // keep a module when its identity's last session ends
    kUnpin, // stop keeping it
    kBlob,        // one chunk of a blob for a host-registered sink
    kSubscribe,   // deliver an event to this session (kEvent) until kUnsubscribe or the session ends
    kUnsubscribe, // stop delivering it
    kReleaseApply,      // run a signed release envelope in its channel (the host's release manager)
    kReleaseConfirm,    // a channel's candidate becomes active
    kReleaseDeactivate, // a channel stops what runs (falls back, or holds)
    kReleaseStatus,     // the channels and what they run
    kRevoke,            // apply a signed revocation list
    kTunables,          // the variables the identity's libs expose, with values and tags
    kTune,              // write one of them (journaled like an exec)
    kProfile,           // start / read / stop the sampling profiler of the identity's sandbox
    kDebug,             // the debugger of the identity's sandbox (breakpoints, steps, inspection)

    kOutput = 48, // print() line
    kEmit,        // rhp.emit(value)
    kResult,      // a request's final result
    kError,       // a request failed, or the session is being closed
    kEvent,       // one delivery of a subscribed event (envelope req 0)

    kPing = 64,
    kPong,
    kAck,  // header.ack only
    kNack, // header.ack = last good seq: resend everything after it
};

[[nodiscard]] constexpr std::string_view to_string(op code) noexcept {
    switch (code) {
    case op::kHello: return "hello";
    case op::kChallenge: return "challenge";
    case op::kResponse: return "response";
    case op::kWelcome: return "welcome";
    case op::kResume: return "resume";
    case op::kExec: return "exec";
    case op::kLoad: return "load";
    case op::kCall: return "call";
    case op::kReload: return "reload";
    case op::kRollback: return "rollback";
    case op::kUnload: return "unload";
    case op::kRevert: return "revert";
    case op::kRevertTo: return "revert_to";
    case op::kCheckpoint: return "checkpoint";
    case op::kRevertAll: return "revert_all";
    case op::kCancel: return "cancel";
    case op::kList: return "list";
    case op::kStatus: return "status";
    case op::kDescribe: return "describe";
    case op::kPin: return "pin";
    case op::kUnpin: return "unpin";
    case op::kBlob: return "blob";
    case op::kSubscribe: return "subscribe";
    case op::kUnsubscribe: return "unsubscribe";
    case op::kReleaseApply: return "release_apply";
    case op::kReleaseConfirm: return "release_confirm";
    case op::kReleaseDeactivate: return "release_deactivate";
    case op::kReleaseStatus: return "release_status";
    case op::kRevoke: return "revoke";
    case op::kTunables: return "tunables";
    case op::kTune: return "tune";
    case op::kProfile: return "profile";
    case op::kDebug: return "debug";
    case op::kOutput: return "output";
    case op::kEmit: return "emit";
    case op::kResult: return "result";
    case op::kError: return "error";
    case op::kEvent: return "event";
    case op::kPing: return "ping";
    case op::kPong: return "pong";
    case op::kAck: return "ack";
    case op::kNack: return "nack";
    }
    return "unknown";
}

[[nodiscard]] constexpr bool is_known(std::uint16_t raw) noexcept {
    return to_string(static_cast<op>(raw)) != "unknown";
}

[[nodiscard]] constexpr bool is_handshake(op code) noexcept {
    return static_cast<std::uint16_t>(code) < 16;
}

[[nodiscard]] constexpr bool is_request(op code) noexcept {
    const auto raw = static_cast<std::uint16_t>(code);
    return raw >= 16 && raw < 48;
}

[[nodiscard]] constexpr bool is_reply(op code) noexcept {
    const auto raw = static_cast<std::uint16_t>(code);
    return raw >= 48 && raw < 64;
}

// Sequenced frames are numbered, acknowledged, resent on nack and delivered exactly once in order.
[[nodiscard]] constexpr bool is_sequenced(op code) noexcept {
    return is_request(code) || is_reply(code);
}

// The least role a request needs (nullopt: not a request). Bindings check their own roles too.
[[nodiscard]] constexpr std::optional<role> required_role(op code) noexcept {
    switch (code) {
    case op::kExec:
    case op::kCall:
    case op::kCancel:
    case op::kList:
    case op::kStatus:
    case op::kDescribe:
    case op::kSubscribe:
    case op::kUnsubscribe:
    case op::kReleaseStatus:
    case op::kTunables:
    case op::kProfile: // the identity's own sandbox
    case op::kRevoke: return role::kObserve; // a revocation list carries its own signatures
    case op::kLoad:
    case op::kReload:
    case op::kRollback:
    case op::kUnload:
    case op::kRevert:
    case op::kRevertTo:
    case op::kCheckpoint:
    case op::kTune:   // each variable's setter checks kPatch too
    case op::kDebug: return role::kPatch; // pausing a script changes what it does
    case op::kBlob: return role::kObserve; // each sink checks its own role (admin by default)
    case op::kRevertAll:
    case op::kPin:
    case op::kUnpin:
    case op::kReleaseApply: // releases outlive the session and survive restarts
    case op::kReleaseConfirm:
    case op::kReleaseDeactivate: return role::kAdmin;
    default: return std::nullopt;
    }
}

// Frame header flags.
enum class frame_flag : std::uint8_t {
    kMac = 1u << 0,          // a 32-byte MAC follows the CRC
    kAckRequested = 1u << 1, // reply with an ack right away
    kMore = 1u << 2,         // reserved: blobs are chunked per message (op kBlob), not per frame
    kCrcOmitted = 1u << 3,   // no CRC trailer: only on encrypted links (TLS checks integrity)
};

[[nodiscard]] constexpr std::uint8_t operator|(frame_flag a, frame_flag b) noexcept {
    return static_cast<std::uint8_t>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}

// `flags` with `f` set.
[[nodiscard]] constexpr std::uint8_t operator|(std::uint8_t flags, frame_flag f) noexcept {
    return static_cast<std::uint8_t>(flags | static_cast<std::uint8_t>(f));
}

[[nodiscard]] constexpr bool has(std::uint8_t flags, frame_flag f) noexcept {
    return (flags & static_cast<std::uint8_t>(f)) != 0;
}

} // namespace Rhp::wire

template <>
struct std::formatter<Rhp::wire::op> : std::formatter<std::string_view> {
    auto format(Rhp::wire::op code, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::wire::to_string(code), ctx);
    }
};
