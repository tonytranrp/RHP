#pragma once

#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace Rhp {

enum class errc : std::uint16_t {
    kOk,
    kTransport,
    kProtocol,
    kProtocolRevisionMismatch,
    kAuth,
    kForbidden,
    kBadSignature,
    kIntegrity,
    kTimeout,
    kCompile,
    kRuntime,
    kBudgetExceeded,
    kMemoryExceeded,
    kStaleHandle,
    kNotFound,
    kAlreadyLoaded,
    kHasDependents,
    kRevertPartial,
    kIrreversible,
    kCancelled,
    kLimitExceeded,
    kDisabled,
    kInvalidArgument,
    kTypeMismatch,
    kOutOfRange,
};

[[nodiscard]] constexpr std::string_view to_string(errc code) noexcept {
    switch (code) {
    case errc::kOk: return "ok";
    case errc::kTransport: return "transport";
    case errc::kProtocol: return "protocol";
    case errc::kProtocolRevisionMismatch: return "protocol_revision_mismatch";
    case errc::kAuth: return "auth";
    case errc::kForbidden: return "forbidden";
    case errc::kBadSignature: return "bad_signature";
    case errc::kIntegrity: return "integrity";
    case errc::kTimeout: return "timeout";
    case errc::kCompile: return "compile";
    case errc::kRuntime: return "runtime";
    case errc::kBudgetExceeded: return "budget_exceeded";
    case errc::kMemoryExceeded: return "memory_exceeded";
    case errc::kStaleHandle: return "stale_handle";
    case errc::kNotFound: return "not_found";
    case errc::kAlreadyLoaded: return "already_loaded";
    case errc::kHasDependents: return "has_dependents";
    case errc::kRevertPartial: return "revert_partial";
    case errc::kIrreversible: return "irreversible";
    case errc::kCancelled: return "cancelled";
    case errc::kLimitExceeded: return "limit_exceeded";
    case errc::kDisabled: return "disabled";
    case errc::kInvalidArgument: return "invalid_argument";
    case errc::kTypeMismatch: return "type_mismatch";
    case errc::kOutOfRange: return "out_of_range";
    }
    return "unknown";
}

// The one error type every RHP API reports. Plain data: copyable, comparable, wire-friendly.
struct error {
    errc code = errc::kOk;
    std::string message;   // human readable
    std::string where;     // "game.spawn", "@combat.low_grav:12", "session 7"
    std::string traceback; // Lua traceback when there is one

    [[nodiscard]] bool operator==(const error&) const = default;
};

[[nodiscard]] inline error make_error(errc code, std::string message = {}, std::string where = {}) {
    return error{code, std::move(message), std::move(where), {}};
}

} // namespace Rhp

template <>
struct std::formatter<Rhp::errc> : std::formatter<std::string_view> {
    auto format(Rhp::errc code, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::to_string(code), ctx);
    }
};

// "[forbidden] game.spawn: needs role patch"
template <>
struct std::formatter<Rhp::error> : std::formatter<std::string_view> {
    auto format(const Rhp::error& err, std::format_context& ctx) const {
        auto out = std::format_to(ctx.out(), "[{}]", err.code);
        if (!err.where.empty()) {
            out = std::format_to(out, " {}", err.where);
        }
        if (!err.message.empty()) {
            out = std::format_to(out, "{} {}", err.where.empty() ? "" : ":", err.message);
        }
        return out;
    }
};
