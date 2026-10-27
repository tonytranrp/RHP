#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/views.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/type_list.hpp>

// What a lib's types mean, computed at compile time: the handle and view types of a lib tree, how
// each parameter and result crosses the Lua boundary, which bindings take the plain or the view
// trampoline, and whether a lib can be installed (`installable`). No trampolines: stubs.hpp,
// api.hpp and tunables.hpp need only this, the lib builder (lib_builder.hpp) builds on it.

namespace Rhp::script::detail {

// ---- compile-time helpers --------------------------------------------------------------------------

template <utils::fixed_string A, utils::fixed_string B>
consteval auto concat_fixed() {
    utils::fixed_string<A.size() + B.size()> out{};
    std::copy_n(A.chars, A.size(), out.chars);
    std::copy_n(B.chars, B.size(), out.chars + A.size());
    return out;
}

// Registry key of a handle's metatable: "rhp.handle.<name>".
template <class Entry>
inline constexpr auto handle_key_v = concat_fixed<utils::fixed_string{"rhp.handle."}, Entry::fixed_name>();

// Registry key of a struct view type's metatable: "rhp.view.<name>".
template <class Entry>
inline constexpr auto view_key_v = concat_fixed<utils::fixed_string{"rhp.view."}, Entry::fixed_name>();

// ---- collecting handles (and view types) across a lib tree ---------------------------------------
//
// `Handles` below is every ::handle and ::view entry of the tree: the types a binding's parameters
// and results may name. find_handle_t / find_view_t pick one kind.

template <class Entry>
struct handles_of_entry {
    using type = utils::type_list<>;
};

template <class Lib>
struct handles_of;

template <utils::fixed_string N, class H, auto IsAlive>
struct handles_of_entry<handle_entry<N, H, IsAlive>> {
    using type = utils::type_list<handle_entry<N, H, IsAlive>>;
};

template <utils::fixed_string N, class T>
struct handles_of_entry<view_entry<N, T>> {
    using type = utils::type_list<view_entry<N, T>>;
};

template <class Lib>
struct handles_of_entry<sub_entry<Lib>> {
    using type = typename handles_of<Lib>::type;
};

template <utils::fixed_string Name, class... Entries>
struct handles_of<lib<Name, Entries...>> {
    using type = utils::concat_t<utils::type_list<>, typename handles_of_entry<Entries>::type...>;
};

template <class Lib>
using handles_of_t = typename handles_of<Lib>::type;

// The entry of kind K for C++ type T in Handles, or void.
template <class Handles, class T, entry_kind K>
struct find_typed {
    using type = void;
};

template <class T, entry_kind K, class Entry, class... Rest>
struct find_typed<utils::type_list<Entry, Rest...>, T, K> {
    using type = std::conditional_t<Entry::kind == K && std::is_same_v<typename Entry::type, T>, Entry,
                                    typename find_typed<utils::type_list<Rest...>, T, K>::type>;
};

// The handle entry for C++ type T in Handles, or void.
template <class Handles, class T>
using find_handle_t = typename find_typed<Handles, std::remove_cvref_t<T>, entry_kind::kHandle>::type;

template <class Handles, class T>
inline constexpr bool is_handle_v = !std::is_void_v<find_handle_t<Handles, T>>;

// The view entry for C++ type T in Handles, or void.
template <class Handles, class T>
using find_view_t = typename find_typed<Handles, std::remove_cvref_t<T>, entry_kind::kView>::type;

template <class Handles, class T>
inline constexpr bool is_view_v = !std::is_void_v<find_view_t<Handles, T>>;

// A parameter a struct view stands in for: the view's type by value, by const reference or as a
// const pointer (nil: nullptr). 0 none, 1 by value, 2 const reference, 3 const pointer.
template <class Handles, class T>
consteval int view_param_kind() {
    if constexpr (std::is_lvalue_reference_v<T>) {
        using U = std::remove_reference_t<T>;
        return std::is_const_v<U> && is_view_v<Handles, U> ? 2 : 0;
    } else if constexpr (std::is_pointer_v<std::remove_cv_t<T>>) {
        using U = std::remove_pointer_t<std::remove_cv_t<T>>;
        return std::is_const_v<U> && is_view_v<Handles, U> ? 3 : 0;
    } else {
        return !std::is_reference_v<T> && is_view_v<Handles, T> && std::is_copy_constructible_v<std::remove_cv_t<T>> ? 1 : 0;
    }
}

// ---- parameters and results ------------------------------------------------------------------------

template <class Handles, class T>
struct arg_traits {
    using U = std::remove_cvref_t<T>;
    static constexpr bool handle = is_handle_v<Handles, U>;
    static constexpr bool optional_handle = is_optional_v<U> && [] {
        if constexpr (is_optional_v<U>) {
            return is_handle_v<Handles, typename U::value_type>;
        } else {
            return false;
        }
    }();
    // std::span<E> / std::span<const E>: a typed view, a buffer or (read-only) a table (span_type_ok).
    static constexpr bool span = is_span_v<U>;
    static constexpr int view = view_param_kind<Handles, T>();
    static constexpr bool by_value_or_const_ref = !std::is_reference_v<T> || std::is_const_v<std::remove_reference_t<T>>;
    static constexpr bool pull_ok = by_value_or_const_ref && (handle || optional_handle || span || view != 0 || pullable<U>);
    static constexpr bool push_ok = handle || optional_handle || pushable<U>;
};

template <class T>
inline constexpr bool is_tuple_v = false;

template <class... Ts>
inline constexpr bool is_tuple_v<std::tuple<Ts...>> = true;

template <class Handles, class R>
struct return_traits {
    static constexpr bool ok = arg_traits<Handles, R>::push_ok;
};

template <class Handles>
struct return_traits<Handles, void> {
    static constexpr bool ok = true;
};

template <class Handles, class... Ts>
struct return_traits<Handles, std::tuple<Ts...>> {
    static constexpr bool ok = (arg_traits<Handles, Ts>::push_ok && ...);
};

template <class Handles, class T, class E>
struct return_traits<Handles, std::expected<T, E>> {
    static constexpr bool ok = std::is_same_v<E, error> && return_traits<Handles, T>::ok;
};

template <class Handles, class T>
struct return_traits<Handles, Rhp::async<T>> {
    static constexpr bool ok = return_traits<Handles, T>::ok;
};

template <class T>
using storage_t = std::remove_cvref_t<T>;

// ---- plain bindings -------------------------------------------------------------------------------

// A parameter type the plain trampoline reads straight off the stack: `kind` tells
// stack::read_args how to read it, take() converts the slot (false when the value doesn't fit the
// type: the general path then says why). Every other type keeps the general path (invoke_fn). A new
// kind of argument is a specialization here and a case in stack::read_args.
template <class T>
struct plain_arg {};

template <>
struct plain_arg<bool> {
    static constexpr arg_kind kind = arg_kind::kBool;
    static bool take(const arg_slot& slot, bool& out) noexcept {
        out = slot.boolean;
        return true;
    }
};

template <lua_integer T>
struct plain_arg<T> {
    static constexpr arg_kind kind = arg_kind::kInteger;
    static bool take(const arg_slot& slot, T& out) noexcept {
        if (!std::in_range<T>(slot.integer)) {
            return false;
        }
        out = static_cast<T>(slot.integer);
        return true;
    }
};

template <std::floating_point T>
struct plain_arg<T> {
    static constexpr arg_kind kind = arg_kind::kNumber;
    static bool take(const arg_slot& slot, T& out) noexcept {
        out = static_cast<T>(slot.number);
        return true;
    }
};

template <>
struct plain_arg<std::string_view> {
    static constexpr arg_kind kind = arg_kind::kString;
    static bool take(const arg_slot& slot, std::string_view& out) noexcept {
        out = std::string_view{slot.string.data, slot.string.size};
        return true;
    }
};

template <>
struct plain_arg<std::string> {
    static constexpr arg_kind kind = arg_kind::kString;
    static bool take(const arg_slot& slot, std::string& out) {
        out.assign(slot.string.data, slot.string.size);
        return true;
    }
};

// A read-only span: a typed view of the same element type, or for a one-byte element a byte buffer,
// a byte view or a Lua string. Tables, mutable spans and every mismatch take the general path.
template <span_element E>
struct plain_arg<std::span<const E>> {
    static constexpr arg_kind kind = arg_kind::kSpan;
    static bool take(const arg_slot& slot, std::span<const E>& out) noexcept {
        const auto k = static_cast<elem_kind>(slot.view.elem);
        const bool fits = slot.view.string ? byte_element<E> : (k == elem_kind_of<E>() || (byte_element<E> && is_byte_kind(k)));
        if (!fits || reinterpret_cast<std::uintptr_t>(slot.view.data) % alignof(E) != 0) {
            return false; // the general path raises the error (a misaligned buffer view)
        }
        out = std::span<const E>{static_cast<const E*>(slot.view.data), slot.view.size / sizeof(E)};
        return true;
    }
};

// Taken by value or const reference.
template <class T>
inline constexpr bool by_value_or_const_ref_v = !std::is_reference_v<T> || std::is_const_v<std::remove_reference_t<T>>;

// A parameter the plain trampoline takes: a type with a plain_arg reader, or a handle (checked with
// pull_handle, as on the general path).
template <class Handles, class T>
concept plain_param = by_value_or_const_ref_v<T> && (requires { plain_arg<std::remove_cvref_t<T>>::kind; } || is_handle_v<Handles, T>);

template <class Handles, class List>
inline constexpr bool plain_params_v = false;

template <class Handles, class... Args>
inline constexpr bool plain_params_v<Handles, utils::type_list<Args...>> = (plain_param<Handles, Args> && ...);

// A binding (function, method or property) the plain trampoline calls: synchronous, nothing
// journaled (no undo<G>, not irreversible), every parameter plain. Its result is anything
// push_return takes; a role it needs is still checked (call_fn).
template <class Handles, class Entry>
inline constexpr bool plain_binding_v = !Entry::is_async && Entry::feed == undo_feed::kNone && !Entry::is_irreversible &&
                                        plain_params_v<Handles, typename Entry::traits::args>;

// ---- bindings returning views ------------------------------------------------------------------------

// What a binding's result is as a view (Rhp::result<> peeled): a span (a typed view of its
// elements), a pointer or reference to a declared view type (a struct view), or neither.
template <class Handles, class R>
struct view_result {
    static constexpr view_shape shape = view_shape::kSpan;
    static constexpr bool is_view = false;
};

template <class Handles, class T>
struct view_result<Handles, std::expected<T, error>> : view_result<Handles, T> {};

template <class Handles, class E>
struct view_result<Handles, std::span<E>> {
    static constexpr view_shape shape = view_shape::kSpan;
    static constexpr bool is_view = span_element<std::remove_const_t<E>>;
    static constexpr bool writable = !std::is_const_v<E>;
    static constexpr elem_kind elem = elem_kind_of<std::remove_const_t<E>>();
};

template <class Handles, class T>
struct view_result<Handles, T*> {
    using object = std::remove_cv_t<T>;
    static constexpr view_shape shape = view_shape::kObject;
    static constexpr bool is_view = is_view_v<Handles, object>;
    static constexpr bool writable = !std::is_const_v<T>;
    static constexpr elem_kind elem = elem_kind::kU8;
};

template <class Handles, class T>
struct view_result<Handles, T* const> : view_result<Handles, T*> {};

template <class Handles, class T>
struct view_result<Handles, T&> : view_result<Handles, T*> {};

template <class Handles, class E>
struct view_result<Handles, const std::span<E>> : view_result<Handles, std::span<E>> {};

template <class Handles, class Entry>
inline constexpr bool returns_view_v = view_result<Handles, typename Entry::traits::return_type>::is_view;

// ---- methods, properties and fields across a lib tree ------------------------------------------------

// Every method and property across a lib tree.
template <class Entry>
struct members_of_entry {
    using type = utils::type_list<>;
};

template <class Lib>
struct members_of;

template <utils::fixed_string N, auto F, class... Tags>
struct members_of_entry<method_entry<N, F, Tags...>> {
    using type = utils::type_list<method_entry<N, F, Tags...>>;
};

template <utils::fixed_string N, auto F, class... Tags>
struct members_of_entry<property_entry<N, F, Tags...>> {
    using type = utils::type_list<property_entry<N, F, Tags...>>;
};

template <class Lib>
struct members_of_entry<sub_entry<Lib>> {
    using type = typename members_of<Lib>::type;
};

template <utils::fixed_string Name, class... Entries>
struct members_of<lib<Name, Entries...>> {
    using type = utils::concat_t<utils::type_list<>, typename members_of_entry<Entries>::type...>;
};

template <class Lib>
using members_of_t = typename members_of<Lib>::type;

template <class Entry>
struct fields_in_entry {
    using type = utils::type_list<>;
};

template <utils::fixed_string N, auto Member, bool ReadOnly, class... Tags>
struct fields_in_entry<field_entry<N, Member, ReadOnly, Tags...>> {
    using type = utils::type_list<field_entry<N, Member, ReadOnly, Tags...>>;
};

template <class Lib>
struct fields_in;

template <class Lib>
struct fields_in_entry<sub_entry<Lib>> {
    using type = typename fields_in<Lib>::type;
};

template <utils::fixed_string Name, class... Entries>
struct fields_in<lib<Name, Entries...>> {
    using type = utils::concat_t<utils::type_list<>, typename fields_in_entry<Entries>::type...>;
};

// Every ::field across a lib tree.
template <class Lib>
using fields_in_t = typename fields_in<Lib>::type;

// An array field's element type and count.
template <class T>
struct array_traits {};

template <class E, std::size_t N>
struct array_traits<E[N]> {
    using element = std::remove_cv_t<E>;
    static constexpr std::size_t count = N;
};

template <class E, std::size_t N>
struct array_traits<std::array<E, N>> {
    using element = std::remove_cv_t<E>;
    static constexpr std::size_t count = N;
};

// ---- install-time checks ---------------------------------------------------------------------------------------

template <class Entry, class Handles>
struct entry_installable : std::true_type {};

template <class List, class Handles>
struct params_ok;

template <class... Args, class Handles>
struct params_ok<utils::type_list<Args...>, Handles> : std::bool_constant<(arg_traits<Handles, Args>::pull_ok && ...)> {};

// A view binding is called again on every access with copies of its arguments: they own their data
// (no span, no struct view parameter), and the binding has nothing to undo and never waits.
template <class List, class Handles>
inline constexpr bool owning_view_params_v = false;

template <class... Args, class Handles>
inline constexpr bool owning_view_params_v<utils::type_list<Args...>, Handles> =
    ((!is_span_v<std::remove_cvref_t<Args>> && view_param_kind<Handles, Args>() == 0) && ...);

template <class Entry, class Handles>
consteval bool view_binding_ok() {
    if constexpr (!returns_view_v<Handles, Entry>) {
        return true;
    } else {
        return !Entry::is_async && Entry::feed == undo_feed::kNone && !Entry::is_irreversible &&
               owning_view_params_v<typename Entry::traits::args, Handles>;
    }
}

template <utils::fixed_string N, auto F, class... Tags, class Handles>
struct entry_installable<fn_entry<N, F, Tags...>, Handles>
    : std::bool_constant<params_ok<utils::args_t<decltype(F)>, Handles>::value &&
                         (returns_view_v<Handles, fn_entry<N, F, Tags...>>
                              ? view_binding_ok<fn_entry<N, F, Tags...>, Handles>()
                              : return_traits<Handles, std::remove_cvref_t<utils::return_type_t<decltype(F)>>>::ok &&
                                    !std::is_reference_v<utils::return_type_t<decltype(F)>>)> {};

// A field belongs to a view type declared in the tree; a struct field's type is declared too.
template <utils::fixed_string N, auto Member, bool ReadOnly, class... Tags, class Handles>
struct entry_installable<field_entry<N, Member, ReadOnly, Tags...>, Handles>
    : std::bool_constant<is_view_v<Handles, member_owner_t<Member>> &&
                         (field_entry<N, Member, ReadOnly, Tags...>::shape != 3 ||
                          is_view_v<Handles, typename field_entry<N, Member, ReadOnly, Tags...>::value_type>)> {};

template <utils::fixed_string N, auto F, class... Tags, class Handles>
struct entry_installable<method_entry<N, F, Tags...>, Handles>
    : std::bool_constant<entry_installable<fn_entry<N, F, Tags...>, Handles>::value && is_handle_v<Handles, self_t<F>>> {};

template <utils::fixed_string N, auto F, class... Tags, class Handles>
struct entry_installable<property_entry<N, F, Tags...>, Handles>
    : std::bool_constant<entry_installable<fn_entry<N, F, Tags...>, Handles>::value && is_handle_v<Handles, self_t<F>>> {};

template <utils::fixed_string N, auto Ptr, class... Tags, class Handles>
struct entry_installable<var_entry<N, Ptr, Tags...>, Handles>
    : std::bool_constant<arg_traits<Handles, typename var_entry<N, Ptr, Tags...>::value_type>::pull_ok &&
                         arg_traits<Handles, typename var_entry<N, Ptr, Tags...>::value_type>::push_ok> {};

template <utils::fixed_string N, auto Ptr, class... Tags, class Handles>
struct entry_installable<ro_entry<N, Ptr, Tags...>, Handles>
    : std::bool_constant<arg_traits<Handles, typename ro_entry<N, Ptr, Tags...>::value_type>::push_ok> {};

template <class Lib, class Handles>
struct lib_installable;

template <class Lib, class Handles>
struct entry_installable<sub_entry<Lib>, Handles> : lib_installable<Lib, Handles> {};

template <utils::fixed_string Name, class... Entries, class Handles>
struct lib_installable<lib<Name, Entries...>, Handles> : std::bool_constant<(entry_installable<Entries, Handles>::value && ...)> {};

template <class Handles>
struct handles_distinct;

template <class... Hs>
struct handles_distinct<utils::type_list<Hs...>> {
    static consteval bool check() {
        constexpr std::string_view names[] = {Hs::name..., ""};
        for (std::size_t i = 0; i < sizeof...(Hs); ++i) {
            for (std::size_t j = i + 1; j < sizeof...(Hs); ++j) {
                if (names[i] == names[j]) {
                    return false;
                }
            }
        }
        return utils::is_unique_v<utils::type_list<typename Hs::type...>>;
    }
    static constexpr bool value = check();
};

// A method or property name is used once per handle across the whole tree.
template <class Members>
struct members_distinct;

template <class... Ms>
struct members_distinct<utils::type_list<Ms...>> {
    template <class M>
    static consteval std::size_t uses() {
        return (std::size_t{0} + ... + ((std::is_same_v<typename M::self_type, typename Ms::self_type> && M::name == Ms::name) ? 1u : 0u));
    }
    static constexpr bool value = ((uses<Ms>() == 1) && ...);
};

// A field name is used once per view type across the whole tree.
template <class Fields>
struct fields_distinct;

template <class... Fs>
struct fields_distinct<utils::type_list<Fs...>> {
    template <class F>
    static consteval std::size_t uses() {
        return (std::size_t{0} + ... + ((std::is_same_v<typename F::owner_type, typename Fs::owner_type> && F::name == Fs::name) ? 1u : 0u));
    }
    static constexpr bool value = ((uses<Fs>() == 1) && ...);
};

} // namespace Rhp::script::detail

namespace Rhp::script {

// Every binding's parameter and result type crosses the Lua boundary (as a handle, a span, a struct
// view or through Rhp::convert), handle and view type names/types are unique across the whole lib
// tree, every method or property belongs to a handle of the tree under a name of its own, and every
// field to a view type of the tree.
template <class L>
concept installable = lib_type<L> && detail::lib_installable<L, detail::handles_of_t<L>>::value &&
                      detail::handles_distinct<detail::handles_of_t<L>>::value && detail::members_distinct<detail::members_of_t<L>>::value &&
                      detail::fields_distinct<detail::fields_in_t<L>>::value;

} // namespace Rhp::script
