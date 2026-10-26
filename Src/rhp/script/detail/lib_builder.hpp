#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/var_layers.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/views.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/type_list.hpp>

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

// A unique address per C++ handle type, so two libs can't reuse a handle name for different types.
template <class H>
inline constexpr char handle_type_tag_v = 0;

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

// ---- handles on the Lua stack ----------------------------------------------------------------------

template <class Entry>
int handle_eq(lua_State* L) {
    stack s{L};
    using H = typename Entry::type;
    const auto* a = static_cast<const H*>(s.to_userdata(1, handle_key_v<Entry>.view()));
    const auto* b = static_cast<const H*>(s.to_userdata(2, handle_key_v<Entry>.view()));
    s.push_bool(a != nullptr && b != nullptr && *a == *b);
    return 1;
}

template <class Entry>
int handle_tostring(lua_State* L) {
    stack s{L};
    using H = typename Entry::type;
    const auto* h = static_cast<const H*>(s.to_userdata(1, handle_key_v<Entry>.view()));
    if constexpr (std::formattable<H, char>) {
        s.push_string(h != nullptr ? std::format("{}({})", Entry::name, *h) : std::string{Entry::name});
    } else {
        s.push_string(std::format("{}: {}", Entry::name, static_cast<const void*>(h)));
    }
    return 1;
}

template <class Entry>
void push_handle(stack& s, const typename Entry::type& h) {
    using H = typename Entry::type;
    void* memory = s.push_userdata(sizeof(H), handle_key_v<Entry>.view());
    std::construct_at(static_cast<H*>(memory), h);
}

template <class Entry>
result<typename Entry::type> pull_handle(stack& s, int index) {
    using H = typename Entry::type;
    const auto* h = static_cast<const H*>(s.to_userdata(index, handle_key_v<Entry>.view()));
    if (h == nullptr) {
        return fail(errc::kTypeMismatch, std::format("expected {}, got {}", Entry::name, s.type_name(index)));
    }
    if (!std::invoke(Entry::is_alive, *h)) {
        return fail(errc::kStaleHandle, std::format("{} is no longer valid", Entry::name));
    }
    return *h;
}

// ---- marshaling with handles -------------------------------------------------------------------------

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

// How a pulled argument is held for the call: a struct view's object by const reference stays a
// reference (no copy); everything else is held by value.
template <class Handles, class T>
using pulled_t = std::conditional_t<view_param_kind<Handles, T>() == 2, std::reference_wrapper<const std::remove_cvref_t<T>>, std::remove_cvref_t<T>>;

template <class Handles, class T>
result<pulled_t<Handles, T>> pull_arg(stack& s, int index) {
    using U = std::remove_cvref_t<T>;
    if constexpr (is_span_v<U>) {
        using E = typename U::element_type;
        using V = std::remove_const_t<E>;
        constexpr bool writable = !std::is_const_v<E>;
        const span_request request{elem_kind_of<V>(), writable, byte_element<V>, !writable};
        auto got = s.to_span(index, request);
        if (!got) {
            return std::unexpected{std::move(got).error()};
        }
        return U{static_cast<E*>(got->data), got->count};
    } else if constexpr (constexpr int view = view_param_kind<Handles, T>(); view != 0) {
        using V = std::conditional_t<view == 3, std::remove_const_t<std::remove_pointer_t<U>>, std::remove_const_t<U>>;
        using Entry = find_view_t<Handles, V>;
        auto object = s.to_object(index, view_key_v<Entry>.view(), Entry::name, view == 3);
        if (!object) {
            return std::unexpected{std::move(object).error()};
        }
        const V* p = static_cast<const V*>(*object);
        if constexpr (view == 1) {
            return V{*p};
        } else if constexpr (view == 2) {
            return std::cref(*p);
        } else {
            return p;
        }
    } else if constexpr (is_handle_v<Handles, U>) {
        return pull_handle<find_handle_t<Handles, U>>(s, index);
    } else if constexpr (arg_traits<Handles, U>::optional_handle) {
        if (s.is_none_or_nil(index)) {
            return U{};
        }
        auto h = pull_handle<find_handle_t<Handles, typename U::value_type>>(s, index);
        if (!h) {
            return std::unexpected{std::move(h).error()};
        }
        return U{*h};
    } else {
        return pull<U>(s, index);
    }
}

template <class Handles, class T>
void push_arg(stack& s, const T& v) {
    using U = std::remove_cvref_t<T>;
    if constexpr (is_handle_v<Handles, U>) {
        push_handle<find_handle_t<Handles, U>>(s, v);
    } else if constexpr (arg_traits<Handles, U>::optional_handle) {
        if (v) {
            push_handle<find_handle_t<Handles, typename U::value_type>>(s, *v);
        } else {
            s.push_nil();
        }
    } else {
        push(s, v);
    }
}

// ---- return values ------------------------------------------------------------------------------------

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

// Pushes a binding's result; returns the number of Lua results. Rhp::result errors are raised.
// `label` is a string or a binding_label (read only when an error needs it).
template <class Handles, class R, class Label>
int push_return(stack& s, const Label& label, R& r) {
    if constexpr (is_tuple_v<R>) {
        std::apply([&](const auto&... items) { (push_arg<Handles>(s, items), ...); }, r);
        return static_cast<int>(std::tuple_size_v<R>);
    } else if constexpr (is_result_v<R>) {
        if (!r) {
            error err = r.error();
            if (err.where.empty()) {
                err.where = std::string{std::string_view{label}};
            }
            s.raise(err);
        }
        if constexpr (std::is_void_v<typename R::value_type>) {
            return 0;
        } else {
            return push_return<Handles>(s, label, *r);
        }
    } else {
        push_arg<Handles>(s, r);
        return 1;
    }
}

// ---- trampolines --------------------------------------------------------------------------------------

[[nodiscard]] inline error forbidden(std::string_view label, role need) {
    return make_error(errc::kForbidden, std::format("needs role {}", need), std::string{label});
}

[[nodiscard]] inline error out_of_range(std::string_view label, double min, double max) {
    return make_error(errc::kOutOfRange, std::format("must lie in [{}, {}]", min, max), std::string{label});
}

// `position` counts from 1; a method's first parameter is its handle ("(self)"), and the
// arguments after it count from 1 as the script wrote them.
[[nodiscard]] inline error arg_error(error err, std::string_view label, std::size_t position, bool method = false) {
    if (!method) {
        err.where = std::format("{} (argument {})", label, position);
    } else if (position == 1) {
        err.where = std::format("{} (self)", label);
    } else {
        err.where = std::format("{} (argument {})", label, position - 1);
    }
    return err;
}

template <class Entry>
inline constexpr bool is_member_v = Entry::kind == entry_kind::kMethod || Entry::kind == entry_kind::kProperty;

template <class T>
inline constexpr bool is_vector_v = false;

template <class E, class A>
inline constexpr bool is_vector_v<std::vector<E, A>> = true;

// Direct-initializes a capture (a std::string from a std::string_view argument is explicit; a span's
// elements are copied into a vector).
template <class Captured, class A>
Captured capture_value(A&& a) {
    if constexpr (is_vector_v<Captured> && is_span_v<std::remove_cvref_t<A>>) {
        return Captured(a.begin(), a.end());
    } else {
        return Captured(std::forward<A>(a));
    }
}

// Effect recorded by a binding tagged Rhp::undo<G>: calls G with the captured values.
template <auto G, class... Captured>
class undo_call_effect final : public effect {
public:
    template <class... A>
        requires(sizeof...(A) == sizeof...(Captured))
    explicit undo_call_effect(A&&... captured) : captured_(capture_value<Captured>(std::forward<A>(captured))...) {}

    void undo() override { std::apply(G, captured_); }

private:
    std::tuple<Captured...> captured_;
};

class irreversible_effect final : public effect {
public:
    void undo() override {}
    [[nodiscard]] bool irreversible() const noexcept override { return true; }
};

template <class T>
using storage_t = std::remove_cvref_t<T>;

template <class T>
struct capture_of {
    using type = std::conditional_t<std::is_same_v<storage_t<T>, std::string_view>, std::string, storage_t<T>>;
};

template <class E, std::size_t N>
struct capture_of<std::span<E, N>> {
    using type = std::vector<std::remove_const_t<E>>;
};

// What an undo keeps of an argument: views into Lua strings are copied, they die with the call (and
// so are a span's elements); a struct view's object by const reference is copied.
template <class T>
using capture_t = typename capture_of<std::remove_cvref_t<T>>::type;

// A binding's label (upvalue 1 of its closure), read from Lua only when something needs it: an
// error, or an undo record. The common successful call never touches it.
struct binding_label {
    const stack& s;
    operator std::string_view() const noexcept { return s.upvalue_string(1); } // NOLINT(google-explicit-constructor)
};

// A label known at compile time: a property's, whose getter runs in its handle's __index frame
// (no upvalues of its own).
template <utils::fixed_string Text>
struct static_label {
    operator std::string_view() const noexcept { return Text.view(); } // NOLINT(google-explicit-constructor)
};

// `label` converts to std::string_view (binding_label, static_label).
template <class Handles, class Entry, class Label, std::size_t... Is>
int invoke_fn(stack& s, Label label, std::index_sequence<Is...>) {
    using args = typename Entry::traits::args;
    using R = typename Entry::traits::return_type;
    constexpr bool keep_args = Entry::feed == undo_feed::kArgs;

    std::tuple<result<pulled_t<Handles, utils::at_t<args, Is>>>...> pulled{
        pull_arg<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1)...};
    std::optional<error> bad;
    ((bad || std::get<Is>(pulled) ? void() : void(bad = arg_error(std::get<Is>(pulled).error(), label, Is + 1, is_member_v<Entry>))), ...);
    if (bad) {
        s.raise(*bad);
    }

    const auto arg = [&]<std::size_t I>() -> decltype(auto) {
        if constexpr (keep_args) {
            return static_cast<pulled_t<Handles, utils::at_t<args, I>>&>(*std::get<I>(pulled));
        } else {
            return static_cast<pulled_t<Handles, utils::at_t<args, I>>&&>(*std::get<I>(pulled));
        }
    };

    // Exceptions from user code become Lua errors. Lua's own error object is not a std::exception,
    // so it passes through untouched; raising happens only after the try block.
    std::optional<error> thrown;
    std::conditional_t<std::is_void_v<R>, char, std::optional<R>> out{};
    try {
        if constexpr (std::is_void_v<R>) {
            std::invoke(Entry::function, arg.template operator()<Is>()...);
        } else {
            out.emplace(std::invoke(Entry::function, arg.template operator()<Is>()...));
        }
    } catch (const Rhp::exception& e) {
        thrown = e.err();
    } catch (const std::exception& e) {
        thrown = make_error(errc::kRuntime, e.what(), std::string{std::string_view{label}});
    }
    if (thrown) {
        if (thrown->where.empty()) {
            thrown->where = std::string{std::string_view{label}};
        }
        s.raise(*thrown);
    }

    // The C++ effect happened: journal it before pushing results (pushing may raise).
    bool succeeded = true;
    if constexpr (is_result_v<R>) {
        succeeded = out->has_value();
    }
    if (succeeded) {
        if constexpr (Entry::feed == undo_feed::kResult) {
            using V = undo_input_t<Entry::function>;
            if constexpr (is_result_v<R>) {
                s.context().record_effect(std::string{std::string_view{label}}, std::make_unique<undo_call_effect<Entry::undo_tag::function, V>>(**out));
            } else {
                s.context().record_effect(std::string{std::string_view{label}}, std::make_unique<undo_call_effect<Entry::undo_tag::function, V>>(*out));
            }
        } else if constexpr (Entry::feed == undo_feed::kArgs) {
            s.context().record_effect(std::string{std::string_view{label}},
                                      std::make_unique<undo_call_effect<Entry::undo_tag::function, capture_t<utils::at_t<args, Is>>...>>(
                                          *std::get<Is>(pulled)...));
        } else if constexpr (Entry::is_irreversible) {
            s.context().record_effect(std::string{std::string_view{label}}, std::make_unique<irreversible_effect>());
        }
    }

    if constexpr (std::is_void_v<R>) {
        return 0;
    } else {
        return push_return<Handles>(s, label, *out);
    }
}

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
        if (!fits) {
            return false;
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

// How the plain trampoline holds one argument: as itself, or a handle (which needn't be default
// constructible) in an optional.
template <class Handles, class T>
using plain_storage_t = std::conditional_t<is_handle_v<Handles, T>, std::optional<storage_t<T>>, storage_t<T>>;

template <class Handles, class T>
consteval arg_kind plain_kind() {
    if constexpr (is_handle_v<Handles, T>) {
        return arg_kind::kOther;
    } else {
        return plain_arg<storage_t<T>>::kind;
    }
}

// Converts read slot `slot` (a plain argument) or pulls the handle at `index` into `out`.
template <class Handles, class T>
bool take_plain(stack& s, int index, const arg_slot& slot, plain_storage_t<Handles, T>& out) {
    if constexpr (is_handle_v<Handles, T>) {
        auto h = pull_handle<find_handle_t<Handles, T>>(s, index);
        if (!h) {
            return false;
        }
        out.emplace(*h);
        return true;
    } else {
        return plain_arg<storage_t<T>>::take(slot, out);
    }
}

template <class Handles, class T>
decltype(auto) plain_value(plain_storage_t<Handles, T>& held) {
    if constexpr (is_handle_v<Handles, T>) {
        return static_cast<storage_t<T>&&>(*held);
    } else {
        return static_cast<storage_t<T>&&>(held);
    }
}

// The plain trampoline: one stack::read_args for every plain argument (handles are pulled as on the
// general path), no result<> per argument, then the call and push_return as on the general path. An
// argument that doesn't fit sends the call down the general path, which raises the error it always has.
template <class Handles, class Entry, class Label, std::size_t... Is>
int call_plain(stack& s, Label label, [[maybe_unused]] std::index_sequence<Is...> seq) {
    using args = typename Entry::traits::args;
    using R = typename Entry::traits::return_type;

    [[maybe_unused]] std::tuple<plain_storage_t<Handles, utils::at_t<args, Is>>...> values;
    if constexpr (sizeof...(Is) > 0) {
        static constexpr arg_kind kinds[] = {plain_kind<Handles, utils::at_t<args, Is>>()...};
        constexpr bool any_read = ((kinds[Is] != arg_kind::kOther) || ...);
        arg_slot slots[sizeof...(Is)];
        if ((any_read && !s.read_args(kinds, slots, static_cast<int>(sizeof...(Is)))) ||
            !(take_plain<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1, slots[Is], std::get<Is>(values)) && ...)) [[unlikely]] {
            return invoke_fn<Handles, Entry>(s, label, seq);
        }
    }

    // As in invoke_fn: exceptions become Lua errors, raised after the try block.
    std::optional<error> thrown;
    std::conditional_t<std::is_void_v<R>, char, std::optional<R>> out{};
    try {
        if constexpr (std::is_void_v<R>) {
            std::invoke(Entry::function, plain_value<Handles, utils::at_t<args, Is>>(std::get<Is>(values))...);
        } else {
            out.emplace(std::invoke(Entry::function, plain_value<Handles, utils::at_t<args, Is>>(std::get<Is>(values))...));
        }
    } catch (const Rhp::exception& e) {
        thrown = e.err();
    } catch (const std::exception& e) {
        thrown = make_error(errc::kRuntime, e.what(), std::string{std::string_view{label}});
    }
    if (thrown) {
        if (thrown->where.empty()) {
            thrown->where = std::string{std::string_view{label}};
        }
        s.raise(*thrown);
    }
    if constexpr (std::is_void_v<R>) {
        return 0;
    } else {
        return push_return<Handles>(s, label, *out);
    }
}

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

// The memory a view binding's result points at.
template <class R>
result<region> view_region(R&& r) {
    using U = std::remove_cvref_t<R>;
    if constexpr (is_result_v<U>) {
        if (!r) {
            return std::unexpected{r.error()};
        }
        return view_region(*r);
    } else if constexpr (is_span_v<U>) {
        using E = std::remove_const_t<typename U::element_type>;
        return region{reinterpret_cast<std::byte*>(const_cast<E*>(r.data())), r.size_bytes()};
    } else if constexpr (std::is_pointer_v<U>) {
        if (r == nullptr) {
            return fail(errc::kStaleHandle, "the object is gone (its binding returned null)");
        }
        using T = std::remove_cv_t<std::remove_pointer_t<U>>;
        return region{reinterpret_cast<std::byte*>(const_cast<T*>(r)), sizeof(T)};
    } else {
        static_assert(std::is_lvalue_reference_v<R>, "a struct view comes from a pointer or a reference");
        return region{reinterpret_cast<std::byte*>(const_cast<std::remove_cv_t<U>*>(std::addressof(r))), sizeof(U)};
    }
}

// Sets `out` when a handle argument of a view binding died since the view was made.
template <class Handles, class T>
void check_alive(const T& v, std::optional<error>& out) {
    if (out) {
        return;
    }
    if constexpr (is_handle_v<Handles, T>) {
        using H = find_handle_t<Handles, T>;
        if (!std::invoke(H::is_alive, v)) {
            out = make_error(errc::kStaleHandle, std::format("{} is no longer valid", H::name));
        }
    } else if constexpr (arg_traits<Handles, T>::optional_handle) {
        using H = find_handle_t<Handles, typename T::value_type>;
        if (v && !std::invoke(H::is_alive, *v)) {
            out = make_error(errc::kStaleHandle, std::format("{} is no longer valid", H::name));
        }
    }
}

// One address per binding.
template <class Entry>
inline constexpr char binding_tag_v = 0;

// A host view's source: the binding and copies of the arguments it was called with. Every access
// calls the binding again (handle arguments checked first), so the view never holds a pointer that
// could dangle.
template <class Handles, class Entry, class... Captured>
class binding_source final : public view_source {
public:
    template <class... A>
        requires(sizeof...(A) == sizeof...(Captured))
    explicit binding_source(A&&... captured) : args_(capture_value<Captured>(std::forward<A>(captured))...) {}

    [[nodiscard]] result<region> resolve() const noexcept override {
        try {
            std::optional<error> stale;
            std::apply([&](const Captured&... a) { (check_alive<Handles>(a, stale), ...); }, args_);
            if (stale) {
                return std::unexpected{std::move(*stale)};
            }
            return std::apply(
                [](const Captured&... a) -> result<region> {
                    decltype(auto) r = std::invoke(Entry::function, a...);
                    return view_region<decltype(r)>(static_cast<decltype(r)&&>(r));
                },
                args_);
        } catch (const Rhp::exception& e) {
            return std::unexpected{e.err()};
        } catch (const std::exception& e) {
            return fail(errc::kRuntime, e.what());
        } catch (...) { // C++ only in here (no Lua call): nothing else may escape a noexcept function
            return fail(errc::kRuntime, "the binding threw an unknown exception");
        }
    }

    [[nodiscard]] std::unique_ptr<view_source> clone() const override { return std::unique_ptr<view_source>{new binding_source(*this)}; }

    [[nodiscard]] bool same(const view_source& other) const noexcept override {
        if (other.binding() != binding()) {
            return false;
        }
        if constexpr ((std::equality_comparable<Captured> && ...)) {
            try {
                return static_cast<const binding_source&>(other).args_ == args_;
            } catch (...) { // a throwing operator==: not known to be the same memory
                return false;
            }
        } else {
            return &other == this;
        }
    }

    [[nodiscard]] const void* binding() const noexcept override { return &binding_tag_v<Entry>; }

private:
    binding_source(const binding_source&) = default;

    std::tuple<Captured...> args_;
};

template <class Handles, class Entry>
consteval host_view_init view_init_of() {
    using V = view_result<Handles, typename Entry::traits::return_type>;
    host_view_init init{};
    init.shape = V::shape;
    init.elem = V::elem;
    init.writable = V::writable;
    return init;
}

// A view type as views know it: its name, registry key and size (its fields are in its metatable).
template <class V>
struct view_type_of {
    static constexpr view_type_info info{V::name, view_key_v<V>.view(), &handle_type_tag_v<typename V::type>, sizeof(typename V::type)};
    static const view_type_info* get() noexcept { return &info; }
};

// Calls a binding that returns a view and pushes the view (nil for a null pointer): a userdata
// holding a binding_source with copies of the arguments. Errors raise at the call, as on the
// general path.
template <class Handles, class Entry, class Label, std::size_t... Is>
int call_view(stack& s, Label label, std::index_sequence<Is...>) {
    using args = typename Entry::traits::args;
    using source = binding_source<Handles, Entry, capture_t<utils::at_t<args, Is>>...>;
    static_assert(alignof(source) <= alignof(std::max_align_t));

    std::tuple<result<pulled_t<Handles, utils::at_t<args, Is>>>...> pulled{
        pull_arg<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1)...};
    std::optional<error> bad;
    ((bad || std::get<Is>(pulled) ? void() : void(bad = arg_error(std::get<Is>(pulled).error(), label, Is + 1, is_member_v<Entry>))), ...);
    if (bad) {
        s.raise(*bad);
    }

    host_view_init init = view_init_of<Handles, Entry>();
    init.source_size = sizeof(source);
    init.source_align = alignof(source);
    init.label = std::string_view{label};
    if constexpr (view_result<Handles, typename Entry::traits::return_type>::shape == view_shape::kObject) {
        using V = find_view_t<Handles, typename view_result<Handles, typename Entry::traits::return_type>::object>;
        init.type = view_type_of<V>::get();
    }
    // The userdata first (pushing may raise: nothing to clean up yet), then the source in it; the
    // first resolution reports the binding's errors here and turns a null pointer into nil.
    void* where = s.push_host_view(init);
    auto* made = std::construct_at(static_cast<source*>(where), std::move(*std::get<Is>(pulled))...);
    s.attach_view_source(made);
    return 1;
}

// ---- asynchronous bindings ------------------------------------------------------------------------

// One call of an asynchronous binding: its Rhp::async<T>, plus copies of the arguments when its
// undo<G> takes them.
template <class Handles, class Entry, class... Captured>
class async_call final : public async_wait {
public:
    using async_type = std::remove_cvref_t<typename Entry::traits::return_type>;
    using value_type = typename async_type::value_type;

    template <class... A>
    async_call(std::string label, async_type later, A&&... captured)
        : label_(std::move(label)), later_(std::move(later)), captured_(Captured(std::forward<A>(captured))...) {}

    async_call(const async_call&) = delete;
    async_call& operator=(const async_call&) = delete;
    ~async_call() override {
        if (!settled_) {
            (void)settle();
        }
    }

    [[nodiscard]] bool ready() const override { return later_.ready(); }
    [[nodiscard]] bool arm(std::function<void()> wake) override { return later_.arm(std::move(wake)); }
    void request_stop() noexcept override { later_.request_stop(); }

    int finish(stack& s, context& ctx) override {
        settled_ = true;
        result<value_type> r = later_.take();
        if (!r) {
            error err = std::move(r).error();
            if (err.where.empty()) {
                err.where = label_;
            }
            s.raise(err);
        }
        // The C++ effect happened: journal it before pushing results (pushing may raise).
        if constexpr (Entry::feed == undo_feed::kResult) {
            ctx.record_effect(label_, std::make_unique<undo_call_effect<Entry::undo_tag::function, value_type>>(*r));
        } else if constexpr (Entry::feed == undo_feed::kArgs) {
            ctx.record_effect(label_, std::apply(
                                          [](const Captured&... a) {
                                              return std::make_unique<undo_call_effect<Entry::undo_tag::function, Captured...>>(a...);
                                          },
                                          captured_));
        } else if constexpr (Entry::is_irreversible) {
            ctx.record_effect(label_, std::make_unique<irreversible_effect>());
        }
        if constexpr (std::is_void_v<value_type>) {
            return 0;
        } else {
            return push_return<Handles>(s, label_, *r);
        }
    }

    async_settled settle() noexcept override {
        settled_ = true;
        std::optional<result<value_type>> r;
        try {
            r = later_.abandon();
        } catch (...) { // only a failing mutex lock: nothing arrived that we could see
            return async_settled::kNothing;
        }
        if (!r || !*r) {
            return async_settled::kNothing;
        }
        if constexpr (Entry::feed == undo_feed::kNone) {
            return async_settled::kDropped;
        } else {
            try {
                if constexpr (Entry::feed == undo_feed::kResult) {
                    std::invoke(Entry::undo_tag::function, **r);
                } else {
                    std::apply(Entry::undo_tag::function, captured_);
                }
            } catch (...) { // an undo that throws is dropped, as when a revert runs it
            }
            return async_settled::kUndone;
        }
    }

private:
    std::string label_;
    async_type later_;
    std::tuple<Captured...> captured_;
    bool settled_ = false; // finished or settled: the destructor has nothing to do
};

[[nodiscard]] inline error not_suspendable(std::string_view label) {
    return make_error(errc::kInvalidArgument,
                      "is an asynchronous binding: only a script's own thread can wait for it (not a patch handler, "
                      "on_save / on_restore / on_unload, a coroutine it created, or a callback of a C function such as table.sort)",
                      std::string{label});
}

// Calls an asynchronous binding. Returns its number of results when it finished at once, or -1
// when the request must wait (the sandbox keeps the call).
template <class Handles, class Entry, std::size_t... Is>
int start_async(stack& s, context& ctx, std::string_view label, std::index_sequence<Is...>) {
    using args = typename Entry::traits::args;
    using R = std::remove_cvref_t<typename Entry::traits::return_type>;
    constexpr bool keep_args = Entry::feed == undo_feed::kArgs;
    // Refused before anything starts: nothing could receive the result.
    if (!ctx.can_suspend(s.state())) {
        s.raise(not_suspendable(label));
    }

    std::tuple<result<storage_t<utils::at_t<args, Is>>>...> pulled{
        pull_arg<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1)...};
    std::optional<error> bad;
    ((bad || std::get<Is>(pulled) ? void() : void(bad = arg_error(std::get<Is>(pulled).error(), label, Is + 1, is_member_v<Entry>))), ...);
    if (bad) {
        s.raise(*bad);
    }

    const auto arg = [&]<std::size_t I>() -> decltype(auto) {
        if constexpr (keep_args) {
            return static_cast<storage_t<utils::at_t<args, I>>&>(*std::get<I>(pulled));
        } else {
            return static_cast<storage_t<utils::at_t<args, I>>&&>(*std::get<I>(pulled));
        }
    };

    std::optional<error> thrown;
    std::optional<R> out;
    try {
        out.emplace(std::invoke(Entry::function, arg.template operator()<Is>()...));
    } catch (const Rhp::exception& e) {
        thrown = e.err();
    } catch (const std::exception& e) {
        thrown = make_error(errc::kRuntime, e.what(), std::string{label});
    }
    if (thrown) {
        if (thrown->where.empty()) {
            thrown->where = std::string{label};
        }
        s.raise(*thrown);
    }

    if (out->ready()) {
        // Already over (a cache hit, an error found up front): finished here, without the shared
        // call a suspension needs. Nothing yields below; a raise unwinds `now` like any C++ object.
        if constexpr (keep_args) {
            async_call<Handles, Entry, capture_t<utils::at_t<args, Is>>...> now{std::string{label}, std::move(*out), *std::get<Is>(pulled)...};
            return now.finish(s, ctx);
        } else {
            async_call<Handles, Entry> now{std::string{label}, std::move(*out)};
            return now.finish(s, ctx);
        }
    }
    std::shared_ptr<async_wait> op;
    if constexpr (keep_args) {
        op = std::make_shared<async_call<Handles, Entry, capture_t<utils::at_t<args, Is>>...>>(std::string{label}, std::move(*out),
                                                                                               *std::get<Is>(pulled)...);
    } else {
        op = std::make_shared<async_call<Handles, Entry>>(std::string{label}, std::move(*out));
    }
    if (ctx.await_async(s.state(), op)) {
        return -1;
    }
    return op->finish(s, ctx);
}

// Upvalue 1 of every binding closure is its full label ("game.debug.dump").
template <class Handles, class Entry>
int call_fn(lua_State* L) {
    stack s{L};
    if constexpr (Entry::required != role::kObserve) { // every caller has observe
        if (!allows(s.context().caller_role(), Entry::required)) {
            s.raise(forbidden(s.upvalue_string(1), Entry::required));
        }
    }
    if constexpr (Entry::is_async) {
        context& ctx = s.context();
        const std::string_view label = s.upvalue_string(1);
        const int results = start_async<Handles, Entry>(s, ctx, label, std::make_index_sequence<Entry::traits::arity>{});
        if (results >= 0) {
            return results;
        }
        yield_async(L); // nothing here has a destructor: the yield may jump
    } else if constexpr (returns_view_v<Handles, Entry>) {
        return call_view<Handles, Entry>(s, binding_label{s}, std::make_index_sequence<Entry::traits::arity>{});
    } else if constexpr (plain_binding_v<Handles, Entry>) {
        return call_plain<Handles, Entry>(s, binding_label{s}, std::make_index_sequence<Entry::traits::arity>{});
    } else {
        return invoke_fn<Handles, Entry>(s, binding_label{s}, std::make_index_sequence<Entry::traits::arity>{});
    }
}

// A property's getter: no upvalues, so its handle's __index (handle_index, stack.cpp) runs it in its
// own frame, the handle at index 1. Called from Lua (a test's swapped-out original) it reads the
// handle at index 1 too. Its label ("entity.hp") is known at compile time.
template <class Handles, class M>
int get_property(lua_State* L) {
    static_assert(plain_binding_v<Handles, M>, "a property takes only its handle and never waits or journals");
    using H = find_handle_t<Handles, typename M::self_type>;
    using label = static_label<concat_fixed<concat_fixed<H::fixed_name, utils::fixed_string{"."}>(), M::fixed_name>()>;
    stack s{L};
    if constexpr (M::required != role::kObserve) {
        if (!allows(s.context().caller_role(), M::required)) {
            s.raise(forbidden(label{}, M::required));
        }
    }
    if constexpr (returns_view_v<Handles, M>) {
        return call_view<Handles, M>(s, label{}, std::make_index_sequence<M::traits::arity>{});
    } else {
        return call_plain<Handles, M>(s, label{}, std::make_index_sequence<M::traits::arity>{});
    }
}

// Reads no upvalues and raises nothing that needs a label: the lib proxy calls it in its own frame.
template <class Handles, class Entry>
int get_var(lua_State* L) {
    stack s{L};
    if constexpr (Entry::kind == entry_kind::kVar) {
        push_arg<Handles>(s, var_layers<Entry::pointer>::read()); // serialized with other sandboxes' writes
    } else {
        push_arg<Handles>(s, *Entry::pointer); // ro: RHP never writes it
    }
    return 1;
}

// Called as setter(new_value). Journals the replaced value through the variable's layer stack.
template <class Handles, class Entry>
int set_var(lua_State* L) {
    stack s{L};
    context& ctx = s.context();
    const std::string_view label = s.upvalue_string(1);
    if (!allows(ctx.caller_role(), role::kPatch)) {
        s.raise(forbidden(label, role::kPatch));
    }
    using T = typename Entry::value_type;
    auto incoming = pull_arg<Handles, T>(s, 1);
    if (!incoming) {
        s.raise(arg_error(std::move(incoming).error(), label, 1));
    }
    if constexpr (Entry::meta::has_range) {
        if (!Entry::meta::in_range(*incoming)) {
            s.raise(out_of_range(label, *Entry::meta::lower(), *Entry::meta::upper()));
        }
    }
    auto fx = var_layers<Entry::pointer>::assign(std::move(*incoming));
    ctx.record_effect(std::string{label}, std::move(fx));
    return 0;
}

// ---- building a lib ---------------------------------------------------------------------------------------

// Out of line (puc_lua/lib_proxy.cpp): turns the three tables on top of the stack (members,
// getters, setters) into a locked userdata proxy named `label`; leaves the proxy on top.
void make_lib_proxy(stack& s, std::string_view label);

template <class Lib, class Handles>
struct lib_builder;

template <utils::fixed_string Name, class... Entries, class Handles>
struct lib_builder<lib<Name, Entries...>, Handles> {
    // Pushes the proxy for this lib; `label` is its full dotted path ("game", "game.debug").
    static void push(stack& s, std::string_view label) {
        s.new_table(); // members
        s.new_table(); // getters
        s.new_table(); // setters
        const int setters = s.top();
        const int getters = setters - 1;
        const int members = setters - 2;
        (add<Entries>(s, label, members, getters, setters), ...);
        make_lib_proxy(s, label);
    }

private:
    template <class Entry>
    static void add(stack& s, std::string_view label, [[maybe_unused]] int members, [[maybe_unused]] int getters,
                    [[maybe_unused]] int setters) {
        const std::string path = std::format("{}.{}", label, Entry::name);
        if constexpr (Entry::kind == entry_kind::kFn) {
            s.push_string(path);
            s.push_function(&call_fn<Handles, Entry>, 1);
            s.set_field(members, Entry::name);
        } else if constexpr (Entry::kind == entry_kind::kVar) {
            s.push_function(&get_var<Handles, Entry>, 0); // no upvalues: lib_var_index calls it in place
            s.set_field(getters, Entry::name);
            s.push_string(path);
            s.push_function(&set_var<Handles, Entry>, 1);
            s.set_field(setters, Entry::name);
        } else if constexpr (Entry::kind == entry_kind::kRo) {
            s.push_function(&get_var<Handles, Entry>, 0); // no upvalues: lib_var_index calls it in place
            s.set_field(getters, Entry::name);
        } else if constexpr (Entry::kind == entry_kind::kSub) {
            lib_builder<typename Entry::lib, Handles>::push(s, path);
            s.set_field(members, Entry::name);
        }
        // Handles are defined once for the whole tree before building (see install_lib_tree).
    }
};

// ---- methods and properties ---------------------------------------------------------------------------

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

template <class Handles, class Members>
struct member_installer;

template <class Handles, class... Ms>
struct member_installer<Handles, utils::type_list<Ms...>> {
    // All or nothing: every name is checked free on its handle before any is added.
    static void install([[maybe_unused]] stack& s) {
        result<void> r{};
        ((r = r ? s.handle_member_free(handle_key_v<find_handle_t<Handles, typename Ms::self_type>>.view(), Ms::name) : r), ...);
        if (!r) {
            s.raise(r.error());
        }
        (add<Ms>(s), ...);
    }

private:
    template <class M>
    static void add(stack& s) {
        using H = find_handle_t<Handles, typename M::self_type>;
        constexpr bool property = M::kind == entry_kind::kProperty;
        if constexpr (property) {
            s.push_function(&get_property<Handles, M>, 0); // no upvalues: handle_index calls it in place
        } else {
            s.push_string(std::format("{}:{}", H::name, M::name));
            s.push_function(&call_fn<Handles, M>, 1);
        }
        s.add_handle_member(handle_key_v<H>.view(), M::name, property);
    }
};

template <class Handles>
struct handle_definer;

template <class... Hs>
struct handle_definer<utils::type_list<Hs...>> {
    static result<void> define([[maybe_unused]] stack& s) {
        result<void> r{};
        const auto one = [&]<class H>(std::type_identity<H>) {
            if constexpr (H::kind == entry_kind::kHandle) {
                if (r) {
                    r = s.define_userdata_type(handle_key_v<H>.view(), H::name, &handle_type_tag_v<typename H::type>, &handle_eq<H>,
                                               &handle_tostring<H>);
                }
            }
        };
        (one(std::type_identity<Hs>{}), ...);
        return r;
    }
};

// ---- struct view types and their fields ---------------------------------------------------------------

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

// Where a field is inside an object of its type.
template <auto Member>
void* field_address(void* object) noexcept {
    using C = member_owner_t<Member>;
    return const_cast<void*>(static_cast<const volatile void*>(std::addressof(static_cast<C*>(object)->*Member)));
}

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

template <class Handles, class F>
consteval field_desc make_field() {
    using M = typename F::value_type;
    field_desc d{};
    d.name = F::name;
    d.writable = F::writable;
    d.address = &field_address<F::member>;
    if constexpr (F::shape == 2) {
        d.shape = field_shape::kArray;
        d.elem = elem_kind_of<typename array_traits<M>::element>();
        d.count = array_traits<M>::count;
    } else if constexpr (F::shape == 3) {
        d.shape = field_shape::kObject;
        d.nested = &view_type_of<find_view_t<Handles, M>>::get;
    } else {
        d.shape = field_shape::kValue;
        d.elem = elem_kind_of<M>();
        if constexpr (F::meta::has_range) {
            d.ranged = true;
            d.min = *F::meta::lower();
            d.max = *F::meta::upper();
        }
    }
    return d;
}

// The fields of view type V (a view_entry) among the tree's Fields, in declaration order.
template <class Handles, class Fields, class V>
struct view_fields;

template <class Handles, class... Fs, class V>
struct view_fields<Handles, utils::type_list<Fs...>, V> {
    template <class F>
    static constexpr bool mine = std::is_same_v<typename F::owner_type, typename V::type>;
    static constexpr std::size_t count = (std::size_t{0} + ... + (mine<Fs> ? 1u : 0u));

    static consteval std::array<field_desc, count> make() {
        std::array<field_desc, count> out{};
        std::size_t i = 0;
        const auto one = [&]<class F>(std::type_identity<F>) {
            if constexpr (mine<F>) {
                out[i++] = make_field<Handles, F>();
            }
        };
        (one(std::type_identity<Fs>{}), ...);
        return out;
    }

    static constexpr std::array<field_desc, count> fields = make();
};

template <class Handles, class Fields, class List>
struct view_definer;

template <class Handles, class Fields, class... Hs>
struct view_definer<Handles, Fields, utils::type_list<Hs...>> {
    // Defines every view type of the tree with its fields (a type another lib defined gets the
    // fields it lacks; a field defined differently fails with kAlreadyLoaded).
    static result<void> define([[maybe_unused]] stack& s) {
        result<void> r{};
        const auto one = [&]<class V>(std::type_identity<V>) {
            if constexpr (V::kind == entry_kind::kView) {
                if (r) {
                    using fields = view_fields<Handles, Fields, V>;
                    r = s.define_view_type(view_type_of<V>::info, fields::fields.data(), fields::fields.size());
                }
            }
        };
        (one(std::type_identity<Hs>{}), ...);
        return r;
    }
};

// Runs in protected mode (sandbox::install): defines the handle and view types, then pushes the
// lib proxy.
template <class Lib>
int install_lib_tree(lua_State* L) {
    stack s{L};
    using handles = handles_of_t<Lib>;
    if (auto defined = handle_definer<handles>::define(s); !defined) {
        s.raise(defined.error());
    }
    if (auto defined = view_definer<handles, fields_in_t<Lib>, handles>::define(s); !defined) {
        s.raise(defined.error());
    }
    member_installer<handles, members_of_t<Lib>>::install(s);
    lib_builder<Lib, handles>::push(s, Lib::name);
    return 1;
}

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
