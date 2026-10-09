#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <string_view>
#include <type_traits>

#include <rhp/core/role.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/function_traits.hpp>
#include <rhp/utils/type_list.hpp>

namespace Rhp::script {

// ---- binding tags ------------------------------------------------------------------------------

// The binding changes host state and G takes it back. G is invocable with the binding's result
// (or, for void bindings, with its arguments). Needs role::kPatch.
template <auto G>
struct undo {
    static constexpr auto function = G;
};

// The binding changes host state and can't be taken back. Allowed (needs role::kPatch); every call
// is counted in revert reports as an irreversible effect.
struct irreversible {};

// Overrides the role a binding needs.
template <role R>
struct requires_role {
    static constexpr role value = R;
};

namespace detail {

template <class T>
inline constexpr bool is_undo_v = false;

template <auto G>
inline constexpr bool is_undo_v<undo<G>> = true;

template <class T>
inline constexpr bool is_requires_role_v = false;

template <role R>
inline constexpr bool is_requires_role_v<requires_role<R>> = true;

template <class T>
concept fn_tag = is_undo_v<T> || std::same_as<T, irreversible> || is_requires_role_v<T>;

enum class entry_kind : std::uint8_t {
    kFn,
    kVar,
    kRo,
    kHandle,
    kSub
};

// ---- function bindings -------------------------------------------------------------------------

template <auto F>
concept bindable_function = utils::has_function_traits<decltype(F)> && !utils::function_traits<decltype(F)>::is_member;

template <class Tag, class... Tags>
inline constexpr std::size_t count_tag_v = (std::size_t{0} + ... + (std::same_as<Tag, Tags> ? 1u : 0u));

template <class... Tags>
inline constexpr std::size_t undo_count_v = (std::size_t{0} + ... + (is_undo_v<Tags> ? 1u : 0u));

template <class... Tags>
inline constexpr std::size_t role_count_v = (std::size_t{0} + ... + (is_requires_role_v<Tags> ? 1u : 0u));

template <class... Tags>
struct undo_of {
    using type = void;
};

template <class Tag, class... Tags>
struct undo_of<Tag, Tags...> {
    using type = std::conditional_t<is_undo_v<Tag>, Tag, typename undo_of<Tags...>::type>;
};

template <class R>
struct unwrap_result {
    using type = R;
};

template <class T, class E>
struct unwrap_result<std::expected<T, E>> {
    using type = T;
};

// The value an undo receives: the binding's result with any Rhp::result<> peeled off.
template <auto F>
using undo_input_t = typename unwrap_result<std::remove_cvref_t<utils::return_type_t<decltype(F)>>>::type;

template <class G, class List>
inline constexpr bool invocable_with_args_v = false;

template <class G, class... Args>
inline constexpr bool invocable_with_args_v<G, utils::type_list<Args...>> = std::invocable<G, std::remove_cvref_t<Args>&...>;

// How undo<G> is fed: kResult → G(result), kArgs → G(args...), kInvalid → compile error.
enum class undo_feed : std::uint8_t {
    kNone,
    kResult,
    kArgs,
    kInvalid
};

template <auto F, class Undo>
consteval undo_feed undo_feed_of() {
    if constexpr (std::is_void_v<Undo>) {
        return undo_feed::kNone;
    } else {
        using R = undo_input_t<F>;
        if constexpr (!std::is_void_v<R>) {
            if constexpr (std::invocable<decltype(Undo::function), R&>) {
                return undo_feed::kResult;
            }
        }
        if constexpr (invocable_with_args_v<decltype(Undo::function), utils::args_t<decltype(F)>>) {
            return undo_feed::kArgs;
        } else {
            return undo_feed::kInvalid;
        }
    }
}

template <auto F, class... Tags>
concept valid_fn_tags = (undo_count_v<Tags...> + count_tag_v<irreversible, Tags...> <= 1) && (role_count_v<Tags...> <= 1) &&
                        (undo_feed_of<F, typename undo_of<Tags...>::type>() != undo_feed::kInvalid);

template <class Tag>
struct role_value {
    static constexpr role value = role::kObserve;
};

template <role R>
struct role_value<requires_role<R>> {
    static constexpr role value = R;
};

template <utils::fixed_string Name, auto F, class... Tags>
struct fn_entry {
    static constexpr entry_kind kind = entry_kind::kFn;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto function = F;
    using traits = utils::function_traits<decltype(F)>;
    using undo_tag = typename undo_of<Tags...>::type;
    static constexpr undo_feed feed = undo_feed_of<F, undo_tag>();
    static constexpr bool is_irreversible = count_tag_v<irreversible, Tags...> > 0;
    static constexpr role required = [] {
        role r = (undo_count_v<Tags...> + count_tag_v<irreversible, Tags...>) > 0 ? role::kPatch : role::kObserve;
        ((is_requires_role_v<Tags> ? void(r = role_value<Tags>::value) : void()), ...);
        return r;
    }();
};

// ---- variables -------------------------------------------------------------------------------------

template <auto Ptr>
concept object_pointer = std::is_pointer_v<decltype(Ptr)> && std::is_object_v<std::remove_pointer_t<decltype(Ptr)>>;

template <auto Ptr>
concept writable_variable = object_pointer<Ptr> && !std::is_const_v<std::remove_pointer_t<decltype(Ptr)>> &&
                            std::copyable<std::remove_pointer_t<decltype(Ptr)>>;

template <utils::fixed_string Name, auto Ptr>
struct var_entry {
    static constexpr entry_kind kind = entry_kind::kVar;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto pointer = Ptr;
    using value_type = std::remove_pointer_t<decltype(Ptr)>;
};

template <utils::fixed_string Name, auto Ptr>
struct ro_entry {
    static constexpr entry_kind kind = entry_kind::kRo;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto pointer = Ptr;
    using value_type = std::remove_cv_t<std::remove_pointer_t<decltype(Ptr)>>;
};

// ---- opaque handles ------------------------------------------------------------------------------

// A handle type is a distinct, trivially copyable value type (typically a strong id); builtin
// arithmetic types are refused because every int in the lib would turn into a handle.
template <class H>
concept handle_value = std::is_trivially_copyable_v<H> && std::equality_comparable<H> && !std::is_arithmetic_v<H> &&
                       !std::is_pointer_v<H> && std::same_as<H, std::remove_cvref_t<H>>;

template <utils::fixed_string Name, class H, auto IsAlive>
struct handle_entry {
    static constexpr entry_kind kind = entry_kind::kHandle;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto is_alive = IsAlive;
    using type = H;
};

template <class Lib>
struct sub_entry {
    static constexpr entry_kind kind = entry_kind::kSub;
    static constexpr std::string_view name = Lib::name;
    using lib = Lib;
};

template <class... Entries>
consteval bool name_free(std::string_view name) {
    return ((Entries::name != name) && ...);
}

} // namespace detail

// ---- the lib DSL -------------------------------------------------------------------------------------

// A Lua-visible library, declared as a type:
//
//   using game_lib = Rhp::lib<"game">
//       ::fn <"spawn",   &game::spawn,   Rhp::undo<&game::despawn>>   // reversible, needs kPatch
//       ::fn <"find",    &game::find>                                  // pure, kObserve
//       ::fn <"explode", &game::explode, Rhp::irreversible>            // allowed, reported by revert
//       ::fn <"wipe",    &game::wipe,    Rhp::requires_role<Rhp::role::kAdmin>>
//       ::var<"gravity", &game::g_gravity>                             // read kObserve, write kPatch (journaled)
//       ::ro <"tick",    &game::g_tick>
//       ::handle<"entity", game::entity_id, &game::is_alive>           // opaque userdata + validity check
//       ::sub<Rhp::lib<"debug">::fn<"dump", &game::dump_state>>;
//
// Names are Lua identifiers and unique within a lib — both checked where you write them.
// Whether every parameter/return type crosses the Lua boundary is checked at
// sandbox::install<L>() (handles may be declared after the functions that use them).
template <utils::fixed_string Name, class... Entries>
    requires(utils::is_identifier(Name.view()))
struct lib {
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    using entries = utils::type_list<Entries...>;

    template <utils::fixed_string N, auto F, detail::fn_tag... Tags>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::bindable_function<F> &&
                    detail::valid_fn_tags<F, Tags...>
    using fn = lib<Name, Entries..., detail::fn_entry<N, F, Tags...>>;

    template <utils::fixed_string N, auto Ptr>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::writable_variable<Ptr>
    using var = lib<Name, Entries..., detail::var_entry<N, Ptr>>;

    template <utils::fixed_string N, auto Ptr>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::object_pointer<Ptr>
    using ro = lib<Name, Entries..., detail::ro_entry<N, Ptr>>;

    template <utils::fixed_string N, class H, auto IsAlive>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::handle_value<H> &&
                    std::predicate<decltype(IsAlive), const H&>
    using handle = lib<Name, Entries..., detail::handle_entry<N, H, IsAlive>>;

    template <class Sub>
        requires(detail::name_free<Entries...>(Sub::name))
    using sub = lib<Name, Entries..., detail::sub_entry<Sub>>;
};

namespace detail {

template <class T>
inline constexpr bool is_lib_v = false;

template <utils::fixed_string Name, class... Entries>
inline constexpr bool is_lib_v<lib<Name, Entries...>> = true;

} // namespace detail

template <class T>
concept lib_type = detail::is_lib_v<T>;

} // namespace Rhp::script

namespace Rhp {

using script::irreversible;
using script::lib;
using script::requires_role;
using script::undo;

} // namespace Rhp
