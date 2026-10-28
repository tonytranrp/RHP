#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
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
#include <rhp/core/scopes.hpp>
#include <rhp/script/detail/call_guard.hpp>
#include <rhp/script/detail/caps.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/lib_traits.hpp>
#include <rhp/script/detail/var_layers.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/views.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/type_list.hpp>

namespace Rhp::script::detail {

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
        s.push_string(std::format("{}: {}", Entry::name, s.shown_address(h)));
    }
    return 1;
}

template <class Entry>
void push_handle(stack& s, const typename Entry::type& h) {
    using H = typename Entry::type;
    void* memory = s.push_userdata(sizeof(H), handle_key_v<Entry>.view());
    std::construct_at(static_cast<H*>(memory), h);
}

// A handle (or a handle argument a view was made with) whose is_alive says no.
[[nodiscard]] inline error stale_handle(std::string_view name) {
    return make_error(errc::kStaleHandle, std::format("{} is no longer valid", name));
}

template <class Entry>
result<typename Entry::type> pull_handle(stack& s, int index) {
    using H = typename Entry::type;
    const auto* h = static_cast<const H*>(s.to_userdata(index, handle_key_v<Entry>.view()));
    if (h == nullptr) {
        return fail(errc::kTypeMismatch, std::format("expected {}, got {}", Entry::name, s.type_name(index)));
    }
    if (!std::invoke(Entry::is_alive, *h)) {
        return std::unexpected{stale_handle(Entry::name)};
    }
    return *h;
}

// ---- marshaling with handles -------------------------------------------------------------------------

// How a pulled argument is held for the call: a struct view's object by const reference stays a
// reference (no copy); everything else is held by value.
template <utils::type_list_like Handles, class T>
using pulled_t = std::conditional_t<view_param_kind<Handles, T>() == view_param::kConstRef, std::reference_wrapper<const std::remove_cvref_t<T>>, std::remove_cvref_t<T>>;

template <utils::type_list_like Handles, class T>
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
    } else if constexpr (constexpr view_param view = view_param_kind<Handles, T>(); view != view_param::kNone) {
        using V = std::conditional_t<view == view_param::kConstPointer, std::remove_const_t<std::remove_pointer_t<U>>, std::remove_const_t<U>>;
        using Entry = find_view_t<Handles, V>;
        auto object = s.to_object(index, view_key_v<Entry>.view(), Entry::name, view == view_param::kConstPointer);
        if (!object) {
            return std::unexpected{std::move(object).error()};
        }
        const V* p = static_cast<const V*>(*object);
        if constexpr (view == view_param::kValue) {
            return V{*p};
        } else if constexpr (view == view_param::kConstRef) {
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

template <utils::type_list_like Handles, class T>
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

// Pushes a binding's result; returns the number of Lua results. Rhp::result errors are raised.
// `label` is a string, a binding_label or a static_label (read only when an error needs it).
template <utils::type_list_like Handles, class R, class Label>
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

// Raises kForbidden unless the caller has role R (every caller has kObserve). `label` converts to
// std::string_view (read only when it raises).
template <role R, class Label>
void check_role(stack& s, const Label& label) {
    if constexpr (R != role::kObserve) {
        if (!allows(s.context().caller_role(), R)) {
            s.raise(forbidden(label, R));
        }
    }
}

// A capability bit the sandbox denies was hit: raises kForbidden, unless the bit is the one names
// after the 63rd share and the sandbox's scopes allow this name.
inline void refuse_cap(stack& s, std::uint64_t bit, std::string_view cap, std::string_view label) {
    if (bit == kCapOverflowBit && s.context().scope_allows(scope_kind::kCap, cap)) {
        return;
    }
    s.raise(make_error(errc::kForbidden, std::format("needs capability {}", cap), std::string{label}));
}

// check_role for Entry, plus its Rhp::cap<> when it has one: one bit test against the sandbox's
// denied capabilities (caps.hpp). Untagged bindings compile to check_role alone.
template <class Entry, class Label>
void check_access(stack& s, const Label& label) {
    if constexpr (Entry::has_cap) {
        const context& ctx = s.context();
        if constexpr (Entry::required != role::kObserve) {
            if (!allows(ctx.caller_role(), Entry::required)) {
                s.raise(forbidden(label, Entry::required));
            }
        }
        const std::uint64_t bit = cap_bit_v<typename Entry::cap_tag>.load(std::memory_order_relaxed);
        if ((ctx.denied_caps() & bit) != 0) [[unlikely]] {
            refuse_cap(s, bit, Entry::cap_tag::name.view(), label);
        }
    } else {
        check_role<Entry::required>(s, label);
    }
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

// Copies of what a call was given (or gave back), kept after it: for an undo<G>, by a view (its
// binding is called again on every access) and by an asynchronous call. Each Captured is a
// capture_t, made with capture_value.
template <class... Captured>
struct captured_args {
    template <class... A>
        requires(sizeof...(A) == sizeof...(Captured) && !(sizeof...(A) == 1 && (std::same_as<std::remove_cvref_t<A>, captured_args> && ...)))
    explicit captured_args(A&&... a) : values(capture_value<Captured>(std::forward<A>(a))...) {}

    std::tuple<Captured...> values;
};

// Effect recorded by a binding tagged Rhp::undo<G>: calls G with the captured values.
template <auto G, class... Captured>
class undo_call_effect final : public effect {
public:
    template <class... A>
        requires(sizeof...(A) == sizeof...(Captured))
    explicit undo_call_effect(A&&... captured) : captured_(std::forward<A>(captured)...) {}

    void undo() override { std::apply(G, captured_.values); }

private:
    captured_args<Captured...> captured_;
};

class irreversible_effect final : public effect {
public:
    void undo() override {}
    [[nodiscard]] bool irreversible() const noexcept override { return true; }
};

// Journals one successful call of Entry under `label`: its undo<G> with copies of `captured` (the
// result or the arguments, as Captured...), or an irreversible mark; nothing for a binding with
// neither.
template <class Entry, class... Captured, class... A>
void record_binding_effect(context& ctx, std::string label, A&&... captured) {
    if constexpr (Entry::feed != undo_feed::kNone) {
        ctx.record_effect(std::move(label), std::make_unique<undo_call_effect<Entry::undo_tag::function, Captured...>>(std::forward<A>(captured)...));
    } else if constexpr (Entry::is_irreversible) {
        ctx.record_effect(std::move(label), std::make_unique<irreversible_effect>());
    }
}

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

// Raises the first argument that couldn't be pulled, labelled with its position (arg_error).
template <class Entry, class Label, class Pulled, std::size_t... Is>
void raise_bad_arg(stack& s, const Label& label, const Pulled& pulled, std::index_sequence<Is...>) {
    std::optional<error> bad;
    ((bad || std::get<Is>(pulled) ? void() : void(bad = arg_error(std::get<Is>(pulled).error(), label, Is + 1, is_member_entry<Entry>::value))), ...);
    if (bad) {
        s.raise(*bad);
    }
}

// Pulls Entry's arguments as Pulled (a tuple of one result per argument) and raises the first that
// doesn't fit. Pulling runs user code (a handle's is_alive, a Rhp::convert<T>::pull): what it
// throws raises as the binding's own exceptions do.
template <utils::type_list_like Handles, class Entry, class Pulled, class Label, std::size_t... Is>
Pulled pull_args(stack& s, const Label& label, std::index_sequence<Is...> seq) {
    using args = typename Entry::traits::args;
    Pulled pulled = call_guarded(s, label, [&] { return Pulled{pull_arg<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1)...}; });
    raise_bad_arg<Entry>(s, label, pulled, seq);
    return pulled;
}

// The general trampoline. `label` converts to std::string_view (binding_label, static_label).
template <utils::type_list_like Handles, class Entry, class Label, std::size_t... Is>
int invoke_fn(stack& s, Label label, std::index_sequence<Is...> seq) {
    using args = typename Entry::traits::args;
    using R = typename Entry::traits::return_type;
    constexpr bool keep_args = Entry::feed == undo_feed::kArgs;
    constexpr bool journaled = Entry::feed != undo_feed::kNone || Entry::is_irreversible;

    auto pulled = pull_args<Handles, Entry, std::tuple<result<pulled_t<Handles, utils::at_t<args, Is>>>...>>(s, label, seq);
    const auto arg = [&]<std::size_t I>() -> decltype(auto) {
        if constexpr (keep_args) {
            return static_cast<pulled_t<Handles, utils::at_t<args, I>>&>(*std::get<I>(pulled));
        } else {
            return static_cast<pulled_t<Handles, utils::at_t<args, I>>&&>(*std::get<I>(pulled));
        }
    };
    const auto call = [&]() -> R { return std::invoke(Entry::function, arg.template operator()<Is>()...); };

    // The journal entry's label is made before the call: once the C++ effect happened, only its
    // record may fail.
    [[maybe_unused]] std::string journal_label;
    if constexpr (journaled) {
        journal_label = std::string_view{label};
    }
    // The C++ effect happened: journal it before pushing results (pushing may raise). An undo<G> fed
    // with the result gets a copy of `result`.
    [[maybe_unused]] const auto journal = [&]([[maybe_unused]] auto&... result) {
        if constexpr (Entry::feed == undo_feed::kResult) {
            record_binding_effect<Entry, undo_input_t<Entry::function>>(s.context(), std::move(journal_label), result...);
        } else if constexpr (keep_args) {
            record_binding_effect<Entry, capture_t<utils::at_t<args, Is>>...>(s.context(), std::move(journal_label), *std::get<Is>(pulled)...);
        } else { // irreversible
            record_binding_effect<Entry>(s.context(), std::move(journal_label));
        }
    };

    if constexpr (std::is_void_v<R>) {
        call_guarded(s, label, call);
        if constexpr (journaled) {
            journal();
        }
        return 0;
    } else {
        R out = call_guarded(s, label, call);
        if constexpr (journaled && is_result_v<R>) {
            if constexpr (std::is_void_v<typename R::value_type>) {
                if (out) {
                    journal();
                }
            } else if (out) {
                journal(*out);
            }
        } else if constexpr (journaled) {
            journal(out);
        }
        return push_return<Handles>(s, label, out);
    }
}

// ---- plain bindings (plain_binding_v, plain_arg: lib_traits.hpp) -----------------------------------

// How the plain trampoline holds one argument: as itself, or a handle (which needn't be default
// constructible) in an optional.
template <utils::type_list_like Handles, class T>
using plain_storage_t = std::conditional_t<is_handle_v<Handles, T>, std::optional<storage_t<T>>, storage_t<T>>;

template <utils::type_list_like Handles, class T>
consteval arg_kind plain_kind() {
    if constexpr (is_handle_v<Handles, T>) {
        return arg_kind::kOther;
    } else {
        return plain_arg<storage_t<T>>::kind;
    }
}

// Converts read slot `slot` (a plain argument) or pulls the handle at `index` into `out`.
template <utils::type_list_like Handles, class T>
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

template <utils::type_list_like Handles, class T>
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
//
// The hot path: taking the arguments and the call share one try block written here (call_guarded's
// rules, without a call to it): an exception from an is_alive, a std::string's allocation or the
// binding becomes the same labelled error (binding_error), raised after the try block.
template <utils::type_list_like Handles, class Entry, class Label, std::size_t... Is>
int call_plain(stack& s, Label label, [[maybe_unused]] std::index_sequence<Is...> seq) {
    using args = typename Entry::traits::args;
    using R = typename Entry::traits::return_type;

    [[maybe_unused]] std::tuple<plain_storage_t<Handles, utils::at_t<args, Is>>...> values;
    std::conditional_t<std::is_void_v<R>, char, std::optional<R>> out{};
    std::optional<error> thrown;
    bool taken = true;
    try {
        if constexpr (sizeof...(Is) > 0) {
            static constexpr arg_kind kinds[] = {plain_kind<Handles, utils::at_t<args, Is>>()...};
            constexpr bool any_read = ((kinds[Is] != arg_kind::kOther) || ...);
            arg_slot slots[sizeof...(Is)];
            taken = (!any_read || s.read_args(kinds, slots, static_cast<int>(sizeof...(Is)))) &&
                    (take_plain<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1, slots[Is], std::get<Is>(values)) && ...);
        }
        if (taken) [[likely]] {
            if constexpr (std::is_void_v<R>) {
                std::invoke(Entry::function, plain_value<Handles, utils::at_t<args, Is>>(std::get<Is>(values))...);
            } else {
                out.emplace(std::invoke(Entry::function, plain_value<Handles, utils::at_t<args, Is>>(std::get<Is>(values))...));
            }
        }
    } catch (const std::exception& e) {
        thrown.emplace(binding_error(e, label));
    }
    if (thrown) {
        s.raise(*thrown);
    }
    if (!taken) [[unlikely]] {
        return invoke_fn<Handles, Entry>(s, label, seq);
    }
    if constexpr (std::is_void_v<R>) {
        return 0;
    } else {
        return push_return<Handles>(s, label, *out);
    }
}

// ---- bindings returning views (view_result, returns_view_v: lib_traits.hpp) ---------------------------

// The memory a view binding's result points at: false when there is none (a null pointer, or a
// Rhp::result<> error).
template <class R>
bool view_find(R&& r, region& out) noexcept {
    using U = std::remove_cvref_t<R>;
    if constexpr (is_result_v<U>) {
        return r.has_value() && view_find(*r, out);
    } else if constexpr (is_span_v<U>) {
        using E = std::remove_const_t<typename U::element_type>;
        out = region{reinterpret_cast<std::byte*>(const_cast<E*>(r.data())), r.size_bytes()};
        return true;
    } else if constexpr (std::is_pointer_v<U>) {
        using T = std::remove_cv_t<std::remove_pointer_t<U>>;
        out = region{reinterpret_cast<std::byte*>(const_cast<T*>(r)), sizeof(T)};
        return r != nullptr;
    } else {
        static_assert(std::is_lvalue_reference_v<R>, "a struct view comes from a pointer or a reference");
        out = region{reinterpret_cast<std::byte*>(const_cast<std::remove_cv_t<U>*>(std::addressof(r))), sizeof(U)};
        return true;
    }
}

// view_find saying why there is no memory: the binding's error, or kStaleHandle for a null pointer.
template <class R>
result<region> view_region(R&& r) {
    if constexpr (is_result_v<std::remove_cvref_t<R>>) {
        if (!r) {
            return std::unexpected{r.error()};
        }
        return view_region(*r);
    } else {
        region out;
        if (!view_find(std::forward<R>(r), out)) {
            return fail(errc::kStaleHandle, "the object is gone (its binding returned null)");
        }
        return out;
    }
}

// Whether a handle argument of a view binding is still alive (true for every other argument).
template <utils::type_list_like Handles, class T>
bool arg_alive(const T& v) {
    if constexpr (is_handle_v<Handles, T>) {
        return std::invoke(find_handle_t<Handles, T>::is_alive, v);
    } else if constexpr (arg_traits<Handles, T>::optional_handle) {
        return !v || std::invoke(find_handle_t<Handles, typename T::value_type>::is_alive, *v);
    } else {
        return true;
    }
}

// Sets `out` when a handle argument of a view binding died since the view was made.
template <utils::type_list_like Handles, class T>
void check_alive(const T& v, std::optional<error>& out) {
    if (out) {
        return;
    }
    if constexpr (is_handle_v<Handles, T>) {
        using H = find_handle_t<Handles, T>;
        if (!std::invoke(H::is_alive, v)) {
            out = stale_handle(H::name);
        }
    } else if constexpr (arg_traits<Handles, T>::optional_handle) {
        using H = find_handle_t<Handles, typename T::value_type>;
        if (v && !std::invoke(H::is_alive, *v)) {
            out = stale_handle(H::name);
        }
    }
}

// One address per binding.
template <class Entry>
inline constexpr char binding_tag_v = 0;

// What a view source is apart from its handle checks: the binding (Entry) and copies of the
// arguments it was called with. same() compares two of these: one entry type in two lib trees with
// other handle sets makes two binding_source classes with one binding(), so the cast must stop
// here, below the Handles they differ in.
template <class Entry, class... Captured>
class binding_args : public view_source {
public:
    [[nodiscard]] bool same(const view_source& other) const noexcept final {
        if (other.binding() != binding()) {
            return false;
        }
        if constexpr ((std::equality_comparable<Captured> && ...)) {
            try {
                return static_cast<const binding_args&>(other).args_.values == args_.values;
            } catch (...) { // a throwing operator==: not known to be the same memory
                return false;
            }
        } else {
            return &other == this;
        }
    }

    [[nodiscard]] const void* binding() const noexcept final { return &binding_tag_v<Entry>; }

protected:
    template <class... A>
        requires(sizeof...(A) == sizeof...(Captured))
    explicit binding_args(A&&... captured) : args_(std::forward<A>(captured)...) {}
    binding_args(const binding_args&) = default;

    captured_args<Captured...> args_;
};

// A host view's source: the binding and copies of the arguments it was called with. Every access
// calls the binding again (handle arguments checked first), so the view never holds a pointer that
// could dangle.
template <utils::type_list_like Handles, class Entry, class... Captured>
class binding_source final : public binding_args<Entry, Captured...> {
    using base = binding_args<Entry, Captured...>;

public:
    template <class... A>
        requires(sizeof...(A) == sizeof...(Captured))
    explicit binding_source(A&&... captured) : base(std::forward<A>(captured)...) {}

    [[nodiscard]] result<region> resolve() const noexcept override {
        try {
            std::optional<error> stale;
            std::apply([&](const Captured&... a) { (check_alive<Handles>(a, stale), ...); }, this->args_.values);
            if (stale) {
                return std::unexpected{std::move(*stale)};
            }
            return std::apply(
                [](const Captured&... a) -> result<region> {
                    decltype(auto) r = std::invoke(Entry::function, a...);
                    return view_region<decltype(r)>(static_cast<decltype(r)&&>(r));
                },
                this->args_.values);
        } catch (const std::exception& e) {
            return std::unexpected{binding_error(e, {})};
        } catch (...) { // C++ only in here (no Lua call): nothing else may escape a noexcept function
            return fail(errc::kRuntime, "the binding threw an unknown exception");
        }
    }

    [[nodiscard]] bool find(region& out) const noexcept override {
        try {
            return std::apply(
                [&](const Captured&... a) {
                    if (!(arg_alive<Handles>(a) && ...)) {
                        return false;
                    }
                    decltype(auto) r = std::invoke(Entry::function, a...);
                    return view_find<decltype(r)>(static_cast<decltype(r)&&>(r), out);
                },
                this->args_.values);
        } catch (...) { // C++ only in here; resolve() says what went wrong
            return false;
        }
    }

    [[nodiscard]] std::unique_ptr<view_source> clone() const override { return std::unique_ptr<view_source>{new binding_source(*this)}; }

private:
    binding_source(const binding_source&) = default;
};

template <utils::type_list_like Handles, class Entry>
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
template <utils::type_list_like Handles, class Entry, class Label, std::size_t... Is>
int call_view(stack& s, Label label, std::index_sequence<Is...> seq) {
    using args = typename Entry::traits::args;
    using source = binding_source<Handles, Entry, capture_t<utils::at_t<args, Is>>...>;
    // Lua aligns a userdata's memory for its own types (8 bytes), not for over-aligned arguments.
    static_assert(alignof(source) <= 8, "a view binding's arguments are copied into the view: none may need more than 8-byte alignment");

    auto pulled = pull_args<Handles, Entry, std::tuple<result<pulled_t<Handles, utils::at_t<args, Is>>>...>>(s, label, seq);

    host_view_init init = view_init_of<Handles, Entry>();
    init.source_size = sizeof(source);
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
template <utils::type_list_like Handles, class Entry, class... Captured>
class async_call final : public async_wait {
public:
    using async_type = std::remove_cvref_t<typename Entry::traits::return_type>;
    using value_type = typename async_type::value_type;

    template <class... A>
    async_call(std::string label, async_type later, A&&... captured)
        : label_(std::move(label)), later_(std::move(later)), captured_(std::forward<A>(captured)...) {}

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
        // The journal entry's label is made before the result is taken: after that, only its record
        // may fail.
        [[maybe_unused]] std::string journal_label;
        if constexpr (Entry::feed != undo_feed::kNone || Entry::is_irreversible) {
            journal_label = label_;
        }
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
            record_binding_effect<Entry, value_type>(ctx, std::move(journal_label), *r);
        } else if constexpr (Entry::feed == undo_feed::kArgs) {
            std::apply([&](const Captured&... a) { record_binding_effect<Entry, Captured...>(ctx, std::move(journal_label), a...); }, captured_.values);
        } else if constexpr (Entry::is_irreversible) {
            record_binding_effect<Entry>(ctx, std::move(journal_label));
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
                    std::apply(Entry::undo_tag::function, captured_.values);
                }
            } catch (...) { // an undo that throws is dropped, as when a revert runs it
            }
            return async_settled::kUndone;
        }
    }

private:
    std::string label_;
    async_type later_;
    captured_args<Captured...> captured_;
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
template <utils::type_list_like Handles, class Entry, std::size_t... Is>
int start_async(stack& s, context& ctx, std::string_view label, std::index_sequence<Is...> seq) {
    using args = typename Entry::traits::args;
    using R = std::remove_cvref_t<typename Entry::traits::return_type>;
    constexpr bool keep_args = Entry::feed == undo_feed::kArgs;
    // Refused before anything starts: nothing could receive the result.
    if (!ctx.can_suspend(s.state())) {
        s.raise(not_suspendable(label));
    }

    auto pulled = pull_args<Handles, Entry, std::tuple<result<storage_t<utils::at_t<args, Is>>>...>>(s, label, seq);
    const auto arg = [&]<std::size_t I>() -> decltype(auto) {
        if constexpr (keep_args) {
            return static_cast<storage_t<utils::at_t<args, I>>&>(*std::get<I>(pulled));
        } else {
            return static_cast<storage_t<utils::at_t<args, I>>&&>(*std::get<I>(pulled));
        }
    };
    R out = call_guarded(s, label, [&]() -> R { return std::invoke(Entry::function, arg.template operator()<Is>()...); });

    if (out.ready()) {
        // Already over (a cache hit, an error found up front): finished here, without the shared
        // call a suspension needs. Nothing yields below; a raise unwinds `now` like any C++ object.
        if constexpr (keep_args) {
            async_call<Handles, Entry, capture_t<utils::at_t<args, Is>>...> now{std::string{label}, std::move(out), *std::get<Is>(pulled)...};
            return now.finish(s, ctx);
        } else {
            async_call<Handles, Entry> now{std::string{label}, std::move(out)};
            return now.finish(s, ctx);
        }
    }
    std::shared_ptr<async_wait> op;
    if constexpr (keep_args) {
        op = std::make_shared<async_call<Handles, Entry, capture_t<utils::at_t<args, Is>>...>>(std::string{label}, std::move(out), *std::get<Is>(pulled)...);
    } else {
        op = std::make_shared<async_call<Handles, Entry>>(std::string{label}, std::move(out));
    }
    if (ctx.await_async(s.state(), op)) {
        return -1;
    }
    return op->finish(s, ctx);
}

// Upvalue 1 of every binding closure is its full label ("game.debug.dump").
template <utils::type_list_like Handles, class Entry>
int call_fn(lua_State* L) {
    stack s{L};
    check_access<Entry>(s, binding_label{s});
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
template <utils::type_list_like Handles, class M>
int get_property(lua_State* L) {
    static_assert(plain_binding_v<Handles, M>, "a property takes only its handle and never waits or journals");
    using H = find_handle_t<Handles, typename M::self_type>;
    using label = static_label<concat_fixed<concat_fixed<H::fixed_name, utils::fixed_string{"."}>(), M::fixed_name>()>;
    stack s{L};
    check_access<M>(s, label{});
    if constexpr (returns_view_v<Handles, M>) {
        return call_view<Handles, M>(s, label{}, std::make_index_sequence<M::traits::arity>{});
    } else {
        return call_plain<Handles, M>(s, label{}, std::make_index_sequence<M::traits::arity>{});
    }
}

// Reads no upvalues and raises nothing that needs a label: the lib proxy calls it in its own frame.
template <utils::type_list_like Handles, class Entry>
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
template <utils::type_list_like Handles, class Entry>
int set_var(lua_State* L) {
    stack s{L};
    context& ctx = s.context();
    const std::string_view label = s.upvalue_string(1);
    check_role<role::kPatch>(s, label);
    using T = typename Entry::value_type;
    auto incoming = call_guarded(s, label, [&] { return pull_arg<Handles, T>(s, 1); }); // a Rhp::convert may throw
    if (!incoming) {
        s.raise(arg_error(std::move(incoming).error(), label, 1));
    }
    if constexpr (Entry::meta::has_range) {
        if (!Entry::meta::in_range(*incoming)) {
            s.raise(out_of_range(label, *Entry::meta::lower(), *Entry::meta::upper()));
        }
    }
    std::string path{label}; // before the write: once it happened, only its record may fail
    auto fx = var_layers<Entry::pointer>::assign(std::move(*incoming));
    ctx.record_effect(std::move(path), std::move(fx));
    return 0;
}

// ---- building a lib ---------------------------------------------------------------------------------------

// Out of line (puc_lua/lib_proxy.cpp): turns the three tables on top of the stack (members,
// getters, setters) into a locked userdata proxy named `label`; leaves the proxy on top.
void make_lib_proxy(stack& s, std::string_view label);

template <class Lib, utils::type_list_like Handles>
struct lib_builder;

template <utils::fixed_string Name, class... Entries, utils::type_list_like Handles>
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
            // A sub-lib the sandbox's scopes deny (`!lib:game.debug`) isn't there at all.
            if (s.context().scope_denies(scope_kind::kLib, path)) {
                return;
            }
            lib_builder<typename Entry::lib, Handles>::push(s, path);
            s.set_field(members, Entry::name);
        }
        // Handles are defined once for the whole tree before building (see install_lib_tree).
    }
};

// ---- methods and properties ---------------------------------------------------------------------------

template <utils::type_list_like Handles, class Members>
struct member_installer;

template <utils::type_list_like Handles, class... Ms>
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

template <utils::type_list_like Handles>
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

// Where a field is inside an object of its type.
template <auto Member>
void* field_address(void* object) noexcept {
    using C = member_owner_t<Member>;
    return const_cast<void*>(static_cast<const volatile void*>(std::addressof(static_cast<C*>(object)->*Member)));
}

template <utils::type_list_like Handles, class F>
consteval field_desc make_field() {
    using M = typename F::value_type;
    field_desc d{};
    d.name = F::name;
    d.writable = F::writable;
    d.address = &field_address<F::member>;
    d.shape = F::shape;
    if constexpr (F::shape == field_shape::kArray) {
        d.elem = elem_kind_of<typename array_traits<M>::element>();
        d.count = array_traits<M>::count;
    } else if constexpr (F::shape == field_shape::kObject) {
        d.nested = &view_type_of<find_view_t<Handles, M>>::get;
    } else {
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
template <utils::type_list_like Handles, class Fields, class V>
struct view_fields;

template <utils::type_list_like Handles, class... Fs, class V>
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

template <utils::type_list_like Handles, class Fields>
struct view_definer;

template <class... Hs, class Fields>
struct view_definer<utils::type_list<Hs...>, Fields> {
    using handles = utils::type_list<Hs...>;

    // Defines every view type of the tree with its fields (a type another lib defined gets the
    // fields it lacks; a field defined differently fails with kAlreadyLoaded).
    static result<void> define([[maybe_unused]] stack& s) {
        result<void> r{};
        const auto one = [&]<class V>(std::type_identity<V>) {
            if constexpr (V::kind == entry_kind::kView) {
                if (r) {
                    using fields = view_fields<handles, Fields, V>;
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
    if (auto defined = view_definer<handles, fields_in_t<Lib>>::define(s); !defined) {
        s.raise(defined.error());
    }
    member_installer<handles, members_of_t<Lib>>::install(s);
    lib_builder<Lib, handles>::push(s, Lib::name);
    return 1;
}

} // namespace Rhp::script::detail
