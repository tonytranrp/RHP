#pragma once

#include <cstdint>
#include <format>
#include <initializer_list>
#include <optional>
#include <string_view>

namespace Rhp {

// What a caller may do. Ordered: every role includes everything the roles below it can do.
//   kObserve - run code, read state, call pure bindings
//   kPatch   - mutate: var writes, reversible/irreversible bindings, patch points, load/revert
//   kAdmin   - revert_all, blobs, admin-tagged bindings, the full Lua standard library
enum class role : std::uint8_t {
    kObserve,
    kPatch,
    kAdmin
};

[[nodiscard]] constexpr bool allows(role have, role need) noexcept {
    return static_cast<std::uint8_t>(have) >= static_cast<std::uint8_t>(need);
}

[[nodiscard]] constexpr std::string_view to_string(role r) noexcept {
    switch (r) {
    case role::kObserve: return "observe";
    case role::kPatch: return "patch";
    case role::kAdmin: return "admin";
    }
    return "unknown";
}

// "observe" / "patch" / "admin" (what to_string writes); nullopt for anything else.
[[nodiscard]] constexpr std::optional<role> parse_role(std::string_view text) noexcept {
    for (const role r : {role::kObserve, role::kPatch, role::kAdmin}) {
        if (to_string(r) == text) {
            return r;
        }
    }
    return std::nullopt;
}

} // namespace Rhp

template <>
struct std::formatter<Rhp::role> : std::formatter<std::string_view> {
    auto format(Rhp::role r, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::to_string(r), ctx);
    }
};
