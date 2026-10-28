#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>

namespace Rhp {

// What a capability scope pattern names (decision AL13).
//   kLib   - a lib (or sub-lib, "game.debug") installed into the identity's sandbox
//   kCap   - a binding tagged Rhp::cap<"economy.write">
//   kPatch - a patch point id rhp.patch may override
//   kEvent - an event name rhp.on / rhp.once / rhp.wait_event or a remote kSubscribe may listen to
//   kOp    - a request op, by its wire name ("exec", "release_apply")
enum class scope_kind : std::uint8_t {
    kLib,
    kCap,
    kPatch,
    kEvent,
    kOp
};

inline constexpr std::size_t kScopeKinds = 5;

[[nodiscard]] constexpr std::string_view to_string(scope_kind k) noexcept {
    switch (k) {
    case scope_kind::kLib: return "lib";
    case scope_kind::kCap: return "cap";
    case scope_kind::kPatch: return "patch";
    case scope_kind::kEvent: return "event";
    case scope_kind::kOp: return "op";
    }
    return "unknown";
}

// "lib" / "cap" / "patch" / "event" / "op"; nullopt for anything else.
[[nodiscard]] constexpr std::optional<scope_kind> parse_scope_kind(std::string_view text) noexcept {
    for (std::size_t i = 0; i < kScopeKinds; ++i) {
        if (to_string(static_cast<scope_kind>(i)) == text) {
            return static_cast<scope_kind>(i);
        }
    }
    return std::nullopt;
}

// True if `name` matches `pattern`: "*", the exact name, or "prefix.*" (any name below prefix, not
// prefix itself: "game.*" matches "game.balance", not "game" or "gameplay"). Release channel
// patterns (release::channel_matches) and scope patterns match the same way.
[[nodiscard]] constexpr bool name_matches(std::string_view pattern, std::string_view name) noexcept {
    if (pattern == "*" || pattern == name) {
        return true;
    }
    if (pattern.ends_with(".*")) {
        pattern.remove_suffix(1); // keep the dot
        return name.starts_with(pattern) && name.size() > pattern.size();
    }
    return false;
}

// A pattern name_matches understands: "*", a dotted name of [A-Za-z0-9_] segments, or such a name
// followed by ".*".
[[nodiscard]] constexpr bool valid_name_pattern(std::string_view pattern) noexcept {
    if (pattern == "*") {
        return true;
    }
    if (pattern.ends_with(".*")) {
        pattern.remove_suffix(2);
    }
    if (pattern.empty()) {
        return false;
    }
    bool segment_start = true;
    for (const char c : pattern) {
        if (c == '.') {
            if (segment_start) {
                return false;
            }
            segment_start = true;
            continue;
        }
        const bool word = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        if (!word) {
            return false;
        }
        segment_start = false;
    }
    return !segment_start;
}

// What an identity (a keyring column, an operator certificate) may reach, as patterns
// `kind:name` with `kind` one of lib, cap, patch, event, op and `name` "*", a dotted name or
// "prefix.*"; a leading `!` denies. A bare `*` allows everything, `!*` denies everything.
//
//   lib:game,lib:ui.*,!cap:economy.*,op:exec,op:call
//
// Deny wins. Per kind, a set without allow patterns of that kind allows every name of it (so
// "lib:game" restricts libs only); one with allow patterns allows only what they match. No patterns
// at all (the default) allows everything.
class scope_set {
public:
    scope_set() = default; // everything

    // Comma-separated patterns (spaces around them are ignored); empty text is everything.
    // kInvalidArgument names the first pattern that isn't one.
    [[nodiscard]] static result<scope_set> parse(std::string_view text);

    // What both allow: intersect(a, b).allows(k, n) == (a.allows(k, n) && b.allows(k, n)) for every
    // kind and name. Identity scopes meet certificate scopes here.
    [[nodiscard]] static scope_set intersect(const scope_set& a, const scope_set& b);

    [[nodiscard]] bool allows(scope_kind kind, std::string_view name) const noexcept;
    // A deny pattern matches `name`. A sandbox leaves out a sub-lib its identity's scopes deny
    // ("!lib:game.debug") under a lib they allow. intersect(a, b).denies == a.denies || b.denies.
    [[nodiscard]] bool denies(scope_kind kind, std::string_view name) const noexcept;
    // Allows every name of every kind (the default), or of one kind: callers skip the check.
    [[nodiscard]] bool unrestricted() const noexcept;
    [[nodiscard]] bool unrestricted(scope_kind kind) const noexcept;

    // The patterns as text parse() reads back to a set that allows the same names; "*" for
    // everything. Sorted, without duplicates.
    [[nodiscard]] std::string to_string() const;

    [[nodiscard]] bool operator==(const scope_set&) const = default;

private:
    struct kind_rules {
        bool restricted = false;        // allow patterns apply (else every name is allowed)
        std::vector<std::string> allow; // restricted: names any of these match are allowed
        std::vector<std::string> deny;  // names any of these match are refused, whatever allows them

        [[nodiscard]] bool operator==(const kind_rules&) const = default;
    };

    void normalize();

    std::array<kind_rules, kScopeKinds> kinds_{};
};

} // namespace Rhp

template <>
struct std::formatter<Rhp::scope_kind> : std::formatter<std::string_view> {
    auto format(Rhp::scope_kind k, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::to_string(k), ctx);
    }
};

template <>
struct std::formatter<Rhp::scope_set> : std::formatter<std::string_view> {
    auto format(const Rhp::scope_set& s, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(s.to_string(), ctx);
    }
};
