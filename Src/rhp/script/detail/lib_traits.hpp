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

// ---- walking a lib tree --------------------------------------------------------------------------

template <class Lib>
struct flat_entries;

template <class Entry>
struct flat_entry {
    using type = utils::type_list<Entry>;
};

template <class Lib>
struct flat_entry<sub_entry<Lib>> {
    using type = typename flat_entries<Lib>::type;
};

template <utils::fixed_string Name, class... Entries>
struct flat_entries<lib<Name, Entries...>> {
    using type = utils::concat_t<utils::type_list<>, typename flat_entry<Entries>::type...>;
};

// Every entry of a lib tree in declaration order, each ::sub replaced by the entries of its lib.
template <class Lib>
using flat_entries_t = typename flat_entries<Lib>::type;

template <class Entry>
struct is_type_entry : std::bool_constant<Entry::kind == entry_kind::kHandle || Entry::kind == entry_kind::kView> {};

template <class Entry>
struct is_member_entry : std::bool_constant<Entry::kind == entry_kind::kMethod || Entry::kind == entry_kind::kProperty> {};

template <class Entry>
struct is_field_entry : std::bool_constant<Entry::kind == entry_kind::kField> {};

// Every ::handle and ::view entry of a lib tree: the types a binding's parameters and results may
// name (`Handles` below). find_handle_t / find_view_t pick one kind.
template <class Lib>
using handles_of_t = utils::filter_t<flat_entries_t<Lib>, is_type_entry>;

// Every method and property of a lib tree.
template <class Lib>
using members_of_t = utils::filter_t<flat_entries_t<Lib>, is_member_entry>;

// Every ::field of a lib tree.
template <class Lib>
using fields_in_t = utils::filter_t<flat_entries_t<Lib>, is_field_entry>;

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

// How a parameter takes a struct view's object: by value (a copy), by const reference, as a const
// pointer (nil: nullptr), or not at all (the parameter isn't a declared view type).
enum class view_param : std::uint8_t {
    kNone,
    kValue,
    kConstRef,
    kConstPointer
};

template <class Handles, class T>
consteval view_param view_param_kind() {
    if constexpr (std::is_lvalue_reference_v<T>) {
        using U = std::remove_reference_t<T>;
        return std::is_const_v<U> && is_view_v<Handles, U> ? view_param::kConstRef : view_param::kNone;
    } else if constexpr (std::is_pointer_v<std::remove_cv_t<T>>) {
        using U = std::remove_pointer_t<std::remove_cv_t<T>>;
        return std::is_const_v<U> && is_view_v<Handles, U> ? view_param::kConstPointer : view_param::kNone;
    } else {
        return !std::is_reference_v<T> && is_view_v<Handles, T> && std::is_copy_constructible_v<std::remove_cv_t<T>> ? view_param::kValue
                                                                                                                     : view_param::kNone;
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
    static constexpr view_param view = view_param_kind<Handles, T>();
    static constexpr bool by_value_or_const_ref = !std::is_reference_v<T> || std::is_const_v<std::remove_reference_t<T>>;
    static constexpr bool pull_ok = by_value_or_const_ref && (handle || optional_handle || span || view != view_param::kNone || pullable<U>);
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

template <class List, class Handles>
inline constexpr bool params_pull_ok_v = false;

template <class... Args, class Handles>
inline constexpr bool params_pull_ok_v<utils::type_list<Args...>, Handles> = (arg_traits<Handles, Args>::pull_ok && ...);

// A view binding is called again on every access with copies of its arguments: they own their data
// (no span, no struct view parameter), and the binding has nothing to undo and never waits.
template <class List, class Handles>
inline constexpr bool owning_view_params_v = false;

template <class... Args, class Handles>
inline constexpr bool owning_view_params_v<utils::type_list<Args...>, Handles> =
    ((!is_span_v<std::remove_cvref_t<Args>> && view_param_kind<Handles, Args>() == view_param::kNone) && ...);

template <class Entry, class Handles>
consteval bool view_binding_ok() {
    if constexpr (!returns_view_v<Handles, Entry>) {
        return true;
    } else {
        return !Entry::is_async && Entry::feed == undo_feed::kNone && !Entry::is_irreversible &&
               owning_view_params_v<typename Entry::traits::args, Handles>;
    }
}

// One entry of a flat lib tree, installed with the tree's Handles: a binding's parameters and result
// cross the Lua boundary (a method's or property's handle is one of the tree's), a variable's type
// crosses both ways (a ::ro's only out), a field belongs to a view type of the tree and a struct
// field's type is one too.
template <class Entry, class Handles>
consteval bool entry_ok() {
    constexpr entry_kind kind = Entry::kind;
    if constexpr (kind == entry_kind::kFn || kind == entry_kind::kMethod || kind == entry_kind::kProperty) {
        using R = typename Entry::traits::return_type;
        bool ok = params_pull_ok_v<typename Entry::traits::args, Handles>;
        if constexpr (kind != entry_kind::kFn) {
            ok = ok && is_handle_v<Handles, typename Entry::self_type>;
        }
        if constexpr (returns_view_v<Handles, Entry>) {
            return ok && view_binding_ok<Entry, Handles>();
        } else {
            return ok && return_traits<Handles, std::remove_cvref_t<R>>::ok && !std::is_reference_v<R>;
        }
    } else if constexpr (kind == entry_kind::kVar) {
        return arg_traits<Handles, typename Entry::value_type>::pull_ok && arg_traits<Handles, typename Entry::value_type>::push_ok;
    } else if constexpr (kind == entry_kind::kRo) {
        return arg_traits<Handles, typename Entry::value_type>::push_ok;
    } else if constexpr (kind == entry_kind::kField) {
        return is_view_v<Handles, typename Entry::owner_type> && (Entry::shape != field_shape::kObject || is_view_v<Handles, typename Entry::value_type>);
    } else {
        return true; // a handle or a view type
    }
}

template <class Entries, class Handles>
inline constexpr bool entries_ok_v = false;

template <class... Entries, class Handles>
inline constexpr bool entries_ok_v<utils::type_list<Entries...>, Handles> = (entry_ok<Entries, Handles>() && ...);

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
concept installable = lib_type<L> && detail::entries_ok_v<detail::flat_entries_t<L>, detail::handles_of_t<L>> &&
                      detail::handles_distinct<detail::handles_of_t<L>>::value && detail::members_distinct<detail::members_of_t<L>>::value &&
                      detail::fields_distinct<detail::fields_in_t<L>>::value;

} // namespace Rhp::script
