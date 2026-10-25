#pragma once

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/value.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/type_list.hpp>

namespace Rhp::script {

// A variable a lib exposes (::var or ::ro), as tools see it: sandbox::tunables, rhp.tunables(),
// rhp-cli tune. Its tags (Rhp::range, Rhp::step, Rhp::unit, Rhp::doc) fill in the rest.
struct tunable_info {
    std::string path;      // "game.speed"
    std::string type;      // its LuaLS type: "number", "integer", "boolean", "string", a handle's or a Rhp::convert's lua_type, "any"
    bool writable = false; // a ::var, and the caller may write it (kPatch)
    value current{};       // its value now (nil when it has no wire form)
    std::optional<double> min{};
    std::optional<double> max{};
    std::optional<double> step{};
    std::string unit{};
    std::string doc{};

    [[nodiscard]] bool operator==(const tunable_info&) const = default;
};

// True for "game.speed" against "", "game" and "game.speed" (not "gam").
[[nodiscard]] inline bool path_matches(std::string_view path, std::string_view prefix) noexcept {
    return prefix.empty() || path == prefix || (path.starts_with(prefix) && path.size() > prefix.size() && path[prefix.size()] == '.');
}

namespace detail {

template <utils::type_list_like Handles, class Lib>
struct tunable_walker;

template <utils::type_list_like Handles, utils::fixed_string Name, class... Entries>
struct tunable_walker<Handles, lib<Name, Entries...>> {
    static void append(std::vector<tunable_info>& out, std::string_view path) { (entry<Entries>(out, path), ...); }

private:
    template <class Entry>
    static void entry([[maybe_unused]] std::vector<tunable_info>& out, [[maybe_unused]] std::string_view path) {
        if constexpr (Entry::kind == entry_kind::kVar || Entry::kind == entry_kind::kRo) {
            using meta = typename Entry::meta;
            tunable_info t;
            t.path = std::format("{}.{}", path, Entry::name);
            t.type = stubs::detail::type_name<Handles, typename Entry::value_type>();
            t.writable = Entry::kind == entry_kind::kVar;
            t.min = meta::lower();
            t.max = meta::upper();
            t.step = meta::step();
            t.unit = std::string{meta::unit()};
            t.doc = std::string{meta::doc()};
            out.push_back(std::move(t));
        } else if constexpr (Entry::kind == entry_kind::kSub) {
            tunable_walker<Handles, typename Entry::lib>::append(out, std::format("{}.{}", path, Entry::name));
        }
    }
};

// Every variable of a lib tree, without values (sandbox::install hands it over).
template <lib_type L>
void collect_tunables(std::vector<tunable_info>& out) {
    tunable_walker<handles_of_t<L>, L>::append(out, L::name);
}

using tunables_fn = void (*)(std::vector<tunable_info>&);

} // namespace detail

} // namespace Rhp::script
