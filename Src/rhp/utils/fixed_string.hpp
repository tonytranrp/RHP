#pragma once

#include <algorithm>
#include <cstddef>
#include <string_view>

namespace Rhp::utils {

// A string usable as a non-type template parameter: Rhp::lib<"game">, patch_point<"combat.damage", ...>.
// Structural type, so every member is public.
template <std::size_t N>
struct fixed_string {
    char chars[N + 1]{};

    constexpr fixed_string() noexcept = default;

    constexpr fixed_string(const char (&str)[N + 1]) noexcept {
        std::copy_n(str, N + 1, chars);
    }

    [[nodiscard]] static constexpr std::size_t size() noexcept { return N; }
    [[nodiscard]] static constexpr bool empty() noexcept { return N == 0; }
    [[nodiscard]] constexpr std::string_view view() const noexcept { return {chars, N}; }
    [[nodiscard]] constexpr const char* c_str() const noexcept { return chars; }
    constexpr operator std::string_view() const noexcept { return view(); }

    template <std::size_t M>
    [[nodiscard]] constexpr bool operator==(const fixed_string<M>& other) const noexcept {
        return view() == other.view();
    }
};

template <std::size_t N>
fixed_string(const char (&)[N]) -> fixed_string<N - 1>;

// Names for modules, patch points and events: dotted lowercase segments, e.g. "combat.damage".
// Each segment starts with a letter; segments hold [a-z0-9_]; no empty segments.
[[nodiscard]] constexpr bool is_dotted_name(std::string_view name) noexcept {
    if (name.empty()) {
        return false;
    }
    bool segment_start = true;
    for (const char c : name) {
        const bool lower = c >= 'a' && c <= 'z';
        const bool digit = c >= '0' && c <= '9';
        if (c == '.') {
            if (segment_start) {
                return false;
            }
            segment_start = true;
            continue;
        }
        if (segment_start && !lower) {
            return false;
        }
        if (!lower && !digit && c != '_') {
            return false;
        }
        segment_start = false;
    }
    return !segment_start;
}

// is_dotted_name as a constraint on a fixed_string template argument (a compiler names it when it fails).
template <fixed_string Name>
concept dotted_name = is_dotted_name(Name.view());

// Names for Lua-visible identifiers inside a lib: "spawn", "gravity", "dump_state".
[[nodiscard]] constexpr bool is_identifier(std::string_view name) noexcept {
    if (name.empty()) {
        return false;
    }
    const auto is_alpha = [](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; };
    const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    if (!is_alpha(name.front())) {
        return false;
    }
    return std::ranges::all_of(name, [&](char c) { return is_alpha(c) || is_digit(c); });
}

// is_identifier as a constraint on a fixed_string template argument.
template <fixed_string Name>
concept identifier_name = is_identifier(Name.view());

} // namespace Rhp::utils
