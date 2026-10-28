#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include <rhp/script/detail/lib_traits.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/utils/type_list.hpp>

// Capabilities (Rhp::cap<"economy.write">, decision AL13) as bits: every capability name gets one
// bit of a 64-bit mask, process-wide, when a lib whose bindings carry it is first installed; each
// sandbox keeps the mask of the bits its scopes deny (context::denied_caps). A tagged binding's
// trampoline tests its bit against that mask: one load and one AND next to the role check. Names
// after the 63rd share the last bit, whose test falls back to matching the name.

namespace Rhp::script::detail {

inline constexpr std::uint64_t kCapOverflowBit = std::uint64_t{1} << 63;

// The bit of capability tag Cap (one variable per name: equal names are one type). 0 until a lib
// using it is installed; written once, under assign_cap_bit's lock, then only read.
template <class Cap>
inline std::atomic<std::uint64_t> cap_bit_v{0};

// One capability a lib tree's bindings carry: its name and its bit's variable.
struct cap_ref {
    std::string_view name;
    std::atomic<std::uint64_t>* bit = nullptr;
};

// Gives `ref` its bit (the next free one; kCapOverflowBit after 63 names) unless it has one, and
// returns it. Thread-safe (caps.cpp).
std::uint64_t assign_cap_bit(const cap_ref& ref) noexcept;

template <class Entry>
consteval bool capped() {
    if constexpr (requires { Entry::has_cap; }) {
        return Entry::has_cap;
    } else {
        return false;
    }
}

template <class Entry>
struct is_capped_entry : std::bool_constant<capped<Entry>()> {};

template <class List>
struct cap_refs;

template <class... Es>
struct cap_refs<utils::type_list<Es...>> {
    static constexpr std::array<cap_ref, sizeof...(Es)> value{cap_ref{Es::cap_tag::name.view(), &cap_bit_v<typename Es::cap_tag>}...};
};

// Every capability the bindings of lib tree Lib carry (a name may repeat).
template <class Lib>
inline constexpr const auto& cap_refs_v = cap_refs<utils::filter_t<flat_entries_t<Lib>, is_capped_entry>>::value;

} // namespace Rhp::script::detail
