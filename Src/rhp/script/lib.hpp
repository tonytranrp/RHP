#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include <rhp/core/async.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/views.hpp>
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

// ---- variable tags (tunables) --------------------------------------------------------------------

// Every write to the variable (a script's, or a tune over the wire) lies in [Min, Max]; anything
// else raises kOutOfRange. Numbers only.
template <auto Min, auto Max>
struct range {
    static constexpr auto min = Min;
    static constexpr auto max = Max;
};

// The step a tool's slider moves by (a hint; writes aren't rounded). Numbers only.
template <auto Step>
struct step {
    static constexpr auto value = Step;
};

// The unit tools show next to the value ("m/s").
template <utils::fixed_string Text>
struct unit {
    static constexpr utils::fixed_string text = Text;
};

// What the variable is for, shown by tools and in the LuaLS stubs.
template <utils::fixed_string Text>
struct doc {
    static constexpr utils::fixed_string text = Text;
};

namespace detail {

// 1 range, 2 step, 3 unit, 4 doc, 0 anything else.
template <class T>
inline constexpr int var_tag_kind_v = 0;

template <auto A, auto B>
inline constexpr int var_tag_kind_v<range<A, B>> = 1;

template <auto S>
inline constexpr int var_tag_kind_v<step<S>> = 2;

template <utils::fixed_string T>
inline constexpr int var_tag_kind_v<unit<T>> = 3;

template <utils::fixed_string T>
inline constexpr int var_tag_kind_v<doc<T>> = 4;

template <class T>
concept var_tag = var_tag_kind_v<T> != 0;

template <class T>
concept ro_tag = var_tag_kind_v<T> == 3 || var_tag_kind_v<T> == 4;

// The tag of kind K among Tags (void when none).
template <int K, class... Tags>
struct var_tag_find {
    using type = void;
};

template <int K, class T, class... Rest>
struct var_tag_find<K, T, Rest...> {
    using type = std::conditional_t<var_tag_kind_v<T> == K, T, typename var_tag_find<K, Rest...>::type>;
};

template <int K, class... Tags>
inline constexpr std::size_t var_tag_count_v = (std::size_t{0} + ... + (var_tag_kind_v<Tags> == K ? 1u : 0u));

template <class T>
concept tunable_number = std::is_arithmetic_v<T> && !std::same_as<T, bool>;

template <class A>
concept tag_number = tunable_number<std::remove_cv_t<A>>;

// A bound fits the variable: integers exactly (no wrap, no truncation), floating point anyhow.
template <class T, auto B>
consteval bool bound_fits() {
    if constexpr (!tag_number<decltype(B)>) {
        return false;
    } else if constexpr (std::integral<T>) {
        if constexpr (std::floating_point<decltype(B)>) {
            return B >= static_cast<decltype(B)>((std::numeric_limits<T>::min)()) && B <= static_cast<decltype(B)>((std::numeric_limits<T>::max)()) &&
                   static_cast<long double>(static_cast<T>(B)) == static_cast<long double>(B);
        } else {
            return std::in_range<T>(B);
        }
    } else { // floating point: within T's range
        return static_cast<long double>(B) >= -static_cast<long double>((std::numeric_limits<T>::max)()) &&
               static_cast<long double>(B) <= static_cast<long double>((std::numeric_limits<T>::max)());
    }
}

template <class T, class Range>
consteval bool range_fits() {
    if constexpr (std::is_void_v<Range>) {
        return true;
    } else if constexpr (!tunable_number<T> || !bound_fits<T, Range::min>() || !bound_fits<T, Range::max>()) {
        return false;
    } else {
        return static_cast<T>(Range::min) <= static_cast<T>(Range::max);
    }
}

template <class T, class Step>
consteval bool step_fits() {
    if constexpr (std::is_void_v<Step>) {
        return true;
    } else if constexpr (!tunable_number<T> || !tag_number<decltype(Step::value)> || !bound_fits<T, Step::value>()) {
        return false;
    } else {
        return Step::value > 0; // an integer variable's step is a whole number (bound_fits)
    }
}

// At most one tag of each kind; range and step only on numbers, with bounds that fit and min <= max.
template <class T, class... Tags>
concept valid_var_tags = (var_tag_count_v<1, Tags...> <= 1) && (var_tag_count_v<2, Tags...> <= 1) && (var_tag_count_v<3, Tags...> <= 1) &&
                         (var_tag_count_v<4, Tags...> <= 1) && range_fits<T, typename var_tag_find<1, Tags...>::type>() &&
                         step_fits<T, typename var_tag_find<2, Tags...>::type>();

template <class... Tags>
concept valid_ro_tags = (var_tag_count_v<3, Tags...> <= 1) && (var_tag_count_v<4, Tags...> <= 1);

// The metadata a variable's tags carry, as tools see it.
template <class T, class... Tags>
struct var_meta {
    using range_tag = typename var_tag_find<1, Tags...>::type;
    using step_tag = typename var_tag_find<2, Tags...>::type;
    using unit_tag = typename var_tag_find<3, Tags...>::type;
    using doc_tag = typename var_tag_find<4, Tags...>::type;
    static constexpr bool has_range = !std::is_void_v<range_tag>;
    static constexpr bool has_step = !std::is_void_v<step_tag>;

    // NaN is outside every range.
    [[nodiscard]] static constexpr bool in_range([[maybe_unused]] const T& v) noexcept {
        if constexpr (has_range) {
            return v >= static_cast<T>(range_tag::min) && v <= static_cast<T>(range_tag::max);
        } else {
            return true;
        }
    }

    [[nodiscard]] static constexpr std::optional<double> lower() noexcept {
        if constexpr (has_range) {
            return static_cast<double>(range_tag::min);
        } else {
            return std::nullopt;
        }
    }

    [[nodiscard]] static constexpr std::optional<double> upper() noexcept {
        if constexpr (has_range) {
            return static_cast<double>(range_tag::max);
        } else {
            return std::nullopt;
        }
    }

    [[nodiscard]] static constexpr std::optional<double> step() noexcept {
        if constexpr (has_step) {
            return static_cast<double>(step_tag::value);
        } else {
            return std::nullopt;
        }
    }

    [[nodiscard]] static constexpr std::string_view unit() noexcept {
        if constexpr (std::is_void_v<unit_tag>) {
            return {};
        } else {
            return unit_tag::text.view();
        }
    }

    [[nodiscard]] static constexpr std::string_view doc() noexcept {
        if constexpr (std::is_void_v<doc_tag>) {
            return {};
        } else {
            return doc_tag::text.view();
        }
    }
};

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
    kSub,
    kMethod,   // a function called on a handle: e:move(1, 2)
    kProperty, // a read-only value of a handle: e.x
    kView,     // a struct type scripts read and write in place: t.x = 1
    kField     // a field of a view type
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

template <class T>
struct unwrap_result<Rhp::async<T>> {
    using type = T;
};

// ---- asynchronous bindings ---------------------------------------------------------------------

// A value that only views memory it doesn't own (a Lua string's bytes).
template <class T>
inline constexpr bool borrowed_v = std::same_as<T, std::string_view> || std::same_as<T, const char*> || std::same_as<T, char*>;

template <class T>
inline constexpr bool borrowed_v<std::optional<T>> = borrowed_v<T>;

template <class... Ts>
inline constexpr bool borrowed_v<std::tuple<Ts...>> = (borrowed_v<std::remove_cvref_t<Ts>> || ...);

template <class A, class B>
inline constexpr bool borrowed_v<std::pair<A, B>> = borrowed_v<std::remove_cvref_t<A>> || borrowed_v<std::remove_cvref_t<B>>;

// A span views memory it doesn't own (a script's buffer, or C++ memory a view found for one call).
template <class E, std::size_t N>
inline constexpr bool borrowed_v<std::span<E, N>> = true;

template <class List>
inline constexpr bool owning_params_v = false;

template <class... Args>
inline constexpr bool owning_params_v<utils::type_list<Args...>> = (!borrowed_v<std::remove_cvref_t<Args>> && ...);

// A binding returning Rhp::async<T> finishes after the call returns, so nothing it is given or
// gives back may view a Lua string (std::string, not std::string_view), and T is a plain value:
// not another async, not a Rhp::result (async<T> already carries an error). Rhp::result<async<T>>
// is refused too: an async that fails at once is Rhp::async<T>::completed(error).
template <auto F>
consteval bool async_ok() {
    using R = std::remove_cvref_t<utils::return_type_t<decltype(F)>>;
    if constexpr (is_result_v<R>) {
        return !is_async_v<std::remove_cvref_t<typename R::value_type>>;
    } else if constexpr (is_async_v<R>) {
        using T = typename R::value_type;
        return owning_params_v<utils::args_t<decltype(F)>> && !borrowed_v<T> && !is_async_v<T> && !is_result_v<T>;
    } else {
        return true;
    }
}

template <auto F>
concept async_binding_ok = async_ok<F>();

// The value an undo receives: the binding's result with any Rhp::result<> peeled off.
template <auto F>
using undo_input_t = typename unwrap_result<std::remove_cvref_t<utils::return_type_t<decltype(F)>>>::type;

template <class G, class List>
inline constexpr bool invocable_with_args_v = false;

template <class G, class... Args>
inline constexpr bool invocable_with_args_v<G, utils::type_list<Args...>> = std::invocable<G, std::remove_cvref_t<Args>&...>;

// How undo<G> is fed: kResult -> G(result), kArgs -> G(args...), kInvalid -> compile error.
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

// ---- spans -------------------------------------------------------------------------------------------

template <class T>
inline constexpr bool is_span_v = false;

template <class E, std::size_t N>
inline constexpr bool is_span_v<std::span<E, N>> = true;

// A span crosses as a typed view: a span element (const or not), dynamic extent.
template <class T>
consteval bool span_type_ok() {
    using U = std::remove_cvref_t<T>;
    if constexpr (is_span_v<U>) {
        using E = typename U::element_type;
        return U::extent == std::dynamic_extent && !std::is_volatile_v<E> && span_element<std::remove_const_t<E>>;
    } else {
        return true;
    }
}

template <class List>
inline constexpr bool span_params_ok_v = false;

template <class... Args>
inline constexpr bool span_params_ok_v<utils::type_list<Args...>> = (span_type_ok<Args>() && ...);

// A binding's result as a view: a span (a typed view), or a pointer or reference (a struct view
// when its type is a declared ::view; known at install). Rhp::result<> is peeled.
template <class R>
struct view_candidate : std::bool_constant<is_span_v<std::remove_cv_t<R>> || std::is_pointer_v<std::remove_cv_t<R>> || std::is_lvalue_reference_v<R>> {};

template <class T>
struct view_candidate<std::expected<T, error>> : view_candidate<T> {};

// Every span a binding takes or returns has a span element; a binding returning a span is called
// again on every access of its view, so it has nothing to undo and never waits.
template <auto F, class... Tags>
consteval bool spans_ok() {
    using R = utils::return_type_t<decltype(F)>;
    using U = typename unwrap_result<std::remove_cvref_t<R>>::type;
    if constexpr (!span_params_ok_v<utils::args_t<decltype(F)>> || !span_type_ok<U>()) {
        return false;
    } else if constexpr (is_span_v<std::remove_cv_t<U>>) {
        return undo_count_v<Tags...> + count_tag_v<irreversible, Tags...> == 0 && !is_async_v<std::remove_cvref_t<R>>;
    } else {
        return true;
    }
}

template <auto F, class... Tags>
concept span_binding_ok = spans_ok<F, Tags...>();

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
    // Returns Rhp::async<T>: the calling script suspends until the result arrives.
    static constexpr bool is_async = is_async_v<std::remove_cvref_t<typename traits::return_type>>;
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

template <utils::fixed_string Name, auto Ptr, class... Tags>
struct var_entry {
    static constexpr entry_kind kind = entry_kind::kVar;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto pointer = Ptr;
    using value_type = std::remove_pointer_t<decltype(Ptr)>;
    using meta = var_meta<value_type, Tags...>;
};

template <utils::fixed_string Name, auto Ptr, class... Tags>
struct ro_entry {
    static constexpr entry_kind kind = entry_kind::kRo;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto pointer = Ptr;
    using value_type = std::remove_cv_t<std::remove_pointer_t<decltype(Ptr)>>;
    using meta = var_meta<value_type, Tags...>;
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

// Methods, properties and fields live on their handle or view type, not in the lib: they never clash
// with lib names.
template <class Entry>
consteval bool lib_name_free(std::string_view name) {
    return Entry::kind == entry_kind::kMethod || Entry::kind == entry_kind::kProperty || Entry::kind == entry_kind::kField || Entry::name != name;
}

template <class... Entries>
consteval bool name_free(std::string_view name) {
    return (lib_name_free<Entries>(name) && ...);
}

// ---- methods and properties on handles ---------------------------------------------------------

template <class List>
struct first_arg {
    using type = void;
};

template <class A, class... Rest>
struct first_arg<utils::type_list<A, Rest...>> {
    using type = A;
};

// The handle a method or property belongs to: its first parameter's type (void when it has none).
template <auto F>
using self_t = std::remove_cvref_t<typename first_arg<utils::args_t<decltype(F)>>::type>;

template <auto F>
concept method_function = bindable_function<F> && (utils::function_traits<decltype(F)>::arity >= 1) && handle_value<self_t<F>> &&
                          (!std::is_reference_v<typename first_arg<utils::args_t<decltype(F)>>::type> ||
                           std::is_const_v<std::remove_reference_t<typename first_arg<utils::args_t<decltype(F)>>::type>>);

template <class T>
inline constexpr bool is_tuple_like_v = false;

template <class... Ts>
inline constexpr bool is_tuple_like_v<std::tuple<Ts...>> = true;

template <class A, class B>
inline constexpr bool is_tuple_like_v<std::pair<A, B>> = true;

// A property reads exactly one value of its handle: one parameter (the handle), one Lua value
// back (not void, not a tuple, not an async; a Rhp::result of one value is fine), nothing to
// undo, no waiting.
template <auto F>
consteval bool one_value_result() {
    using R = std::remove_cvref_t<utils::return_type_t<decltype(F)>>;
    using V = typename unwrap_result<R>::type;
    return !std::is_void_v<V> && !is_tuple_like_v<std::remove_cvref_t<V>> && !is_async_v<R> && !is_async_v<std::remove_cvref_t<V>>;
}

template <auto F, class... Tags>
concept property_function = method_function<F> && (utils::function_traits<decltype(F)>::arity == 1) && one_value_result<F>() &&
                            (undo_count_v<Tags...> + count_tag_v<irreversible, Tags...> == 0) && (role_count_v<Tags...> <= 1);

template <utils::fixed_string Name, auto F, class... Tags>
struct method_entry : fn_entry<Name, F, Tags...> {
    static constexpr entry_kind kind = entry_kind::kMethod;
    using self_type = self_t<F>;
};

template <utils::fixed_string Name, auto F, class... Tags>
struct property_entry : fn_entry<Name, F, Tags...> {
    static constexpr entry_kind kind = entry_kind::kProperty;
    using self_type = self_t<F>;
};

template <class Entry, class Self>
consteval bool member_clash(std::string_view name) {
    if constexpr (Entry::kind == entry_kind::kMethod || Entry::kind == entry_kind::kProperty) {
        return std::is_same_v<typename Entry::self_type, Self> && Entry::name == name;
    } else {
        return false;
    }
}

// No method or property of the same handle has this name yet (in this lib; install checks the tree).
template <class Self, class... Entries>
consteval bool member_free(std::string_view name) {
    return (!member_clash<Entries, Self>(name) && ...);
}

// ---- struct views ------------------------------------------------------------------------------------

// A view type is a standard-layout class: its fields sit at fixed offsets, so a view finds a field
// from the object's address and a journaled write restores just that field's bytes.
template <class T>
concept view_struct = std::is_class_v<T> && std::same_as<T, std::remove_cv_t<T>> && std::is_standard_layout_v<T> && !std::is_polymorphic_v<T>;

template <utils::fixed_string Name, class T>
struct view_entry {
    static constexpr entry_kind kind = entry_kind::kView;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    using type = T;
};

template <class M>
struct member_traits {};

template <class M, class C>
struct member_traits<M C::*> {
    using owner = C;
    using value = M;
};

template <auto Member>
concept member_object = std::is_member_object_pointer_v<decltype(Member)>;

template <auto Member>
using member_owner_t = typename member_traits<decltype(Member)>::owner;

template <auto Member>
using member_value_t = typename member_traits<decltype(Member)>::value;

template <class T>
inline constexpr bool is_std_array_v = false;

template <class E, std::size_t N>
inline constexpr bool is_std_array_v<std::array<E, N>> = true;

// What a field is to a view: 1 a value (number, bool, enum), 2 an array of span elements (read as a
// span view), 3 a struct (a nested view; its type must be a declared ::view), 0 unsupported.
template <class M>
consteval int field_shape_of() {
    using U = std::remove_cv_t<M>;
    if constexpr (std::is_arithmetic_v<U> || std::is_enum_v<U>) {
        return (std::is_floating_point_v<U> && sizeof(U) != 4 && sizeof(U) != 8) || sizeof(U) > 8 ? 0 : 1;
    } else if constexpr (std::is_bounded_array_v<U>) {
        return std::rank_v<U> == 1 && span_element<std::remove_cv_t<std::remove_extent_t<U>>> ? 2 : 0;
    } else if constexpr (is_std_array_v<U>) {
        return span_element<std::remove_cv_t<typename U::value_type>> ? 2 : 0;
    } else if constexpr (std::is_class_v<U>) {
        return view_struct<U> ? 3 : 0;
    } else {
        return 0;
    }
}

template <auto Member>
concept field_member = member_object<Member> && view_struct<member_owner_t<Member>> && (field_shape_of<member_value_t<Member>>() != 0);

template <utils::fixed_string Name, auto Member, bool ReadOnly, class... Tags>
struct field_entry {
    static constexpr entry_kind kind = entry_kind::kField;
    static constexpr utils::fixed_string fixed_name = Name;
    static constexpr std::string_view name = fixed_name.view();
    static constexpr auto member = Member;
    using owner_type = member_owner_t<Member>;
    using value_type = std::remove_cv_t<member_value_t<Member>>;
    static constexpr int shape = field_shape_of<member_value_t<Member>>();
    // A const member is read-only whatever the entry says.
    static constexpr bool writable = !ReadOnly && !std::is_const_v<member_value_t<Member>>;
    using meta = var_meta<value_type, Tags...>;
};

// Range and step only on number fields (a value, not bool or an enum): the variable tags' rules.
template <auto Member, class... Tags>
consteval bool field_tags_ok() {
    using M = std::remove_cv_t<member_value_t<Member>>;
    if constexpr (field_shape_of<M>() == 1 && !std::is_enum_v<M>) {
        return valid_var_tags<M, Tags...>;
    } else {
        return valid_ro_tags<Tags...> && var_tag_count_v<1, Tags...> + var_tag_count_v<2, Tags...> == 0;
    }
}

template <auto Member, class... Tags>
concept valid_field_tags = field_tags_ok<Member, Tags...>();

template <class Entry, class Owner>
consteval bool field_clash(std::string_view name) {
    if constexpr (Entry::kind == entry_kind::kField) {
        return std::is_same_v<typename Entry::owner_type, Owner> && Entry::name == name;
    } else {
        return false;
    }
}

// No field of the same view type has this name yet (in this lib; install checks the tree).
template <class Owner, class... Entries>
consteval bool field_free(std::string_view name) {
    return (!field_clash<Entries, Owner>(name) && ...);
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
//       ::fn <"load",    &game::load_texture>                          // returns Rhp::async<T>: the script waits
//       ::var<"gravity", &game::g_gravity>                             // read kObserve, write kPatch (journaled)
//       ::var<"speed", &game::g_speed, Rhp::range<0.0, 10.0>, Rhp::unit<"m/s">> // a tunable: writes outside raise kOutOfRange
//       ::ro <"tick",    &game::g_tick>
//       ::handle<"entity", game::entity_id, &game::is_alive>           // opaque userdata + validity check
//       ::method<"move", &game::move>                                  // e:move(dx, dy): first parameter is the entity
//       ::property<"hp", &game::health_of>                             // e.hp (read-only)
//       ::fn <"heights", &game::height_map>                            // returns std::span<float>: a typed view
//       ::view<"transform", game::transform>                           // a struct scripts read and write in place
//       ::field<"layer", &game::transform::layer, Rhp::range<0, 31>>   // t.layer = 3 (kPatch, journaled)
//       ::ro_field<"id", &game::transform::id>                         // t.id (read-only)
//       ::property<"transform", &game::transform_of>                   // returns transform*: a struct view (nil for nullptr)
//       ::sub<Rhp::lib<"debug">::fn<"dump", &game::dump_state>>;
//
// Names are Lua identifiers and unique within a lib - both checked where you write them. A method
// or property belongs to the handle type of its first parameter (declared in this lib tree; a lib
// that only adds members re-declares the ::handle) and is named uniquely on that handle.
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
                    detail::valid_fn_tags<F, Tags...> && detail::async_binding_ok<F> && detail::span_binding_ok<F, Tags...>
    using fn = lib<Name, Entries..., detail::fn_entry<N, F, Tags...>>;

    // A variable scripts read and (kPatch) write, journaled. Tags make it a described tunable:
    // Rhp::range<Min, Max> (enforced), Rhp::step<S>, Rhp::unit<"m/s">, Rhp::doc<"...">.
    template <utils::fixed_string N, auto Ptr, detail::var_tag... Tags>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::writable_variable<Ptr> &&
                    detail::valid_var_tags<std::remove_pointer_t<decltype(Ptr)>, Tags...>
    using var = lib<Name, Entries..., detail::var_entry<N, Ptr, Tags...>>;

    // A read-only variable; takes Rhp::unit<> and Rhp::doc<>.
    template <utils::fixed_string N, auto Ptr, detail::ro_tag... Tags>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::object_pointer<Ptr> &&
                    detail::valid_ro_tags<Tags...>
    using ro = lib<Name, Entries..., detail::ro_entry<N, Ptr, Tags...>>;

    template <utils::fixed_string N, class H, auto IsAlive>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::handle_value<H> &&
                    std::predicate<decltype(IsAlive), const H&>
    using handle = lib<Name, Entries..., detail::handle_entry<N, H, IsAlive>>;

    template <class Sub>
        requires(detail::name_free<Entries...>(Sub::name))
    using sub = lib<Name, Entries..., detail::sub_entry<Sub>>;

    // A function called on a handle (e:move(1, 2), label "entity:move"). Takes the fn tags.
    template <utils::fixed_string N, auto F, detail::fn_tag... Tags>
        requires(utils::is_identifier(N.view()) && detail::member_free<detail::self_t<F>, Entries...>(N.view())) &&
                    detail::method_function<F> && detail::valid_fn_tags<F, Tags...> && detail::async_binding_ok<F> &&
                    detail::span_binding_ok<F, Tags...>
    using method = lib<Name, Entries..., detail::method_entry<N, F, Tags...>>;

    // A read-only value of a handle (e.hp, label "entity.hp"): F(handle) -> value. Only
    // requires_role<> applies.
    template <utils::fixed_string N, auto F, detail::fn_tag... Tags>
        requires(utils::is_identifier(N.view()) && detail::member_free<detail::self_t<F>, Entries...>(N.view())) &&
                    detail::property_function<F, Tags...> && detail::span_binding_ok<F, Tags...>
    using property = lib<Name, Entries..., detail::property_entry<N, F, Tags...>>;

    // A struct type scripts read and write in place (views.hpp): a binding returning T* / T& (or
    // const) gives a view of the object, its ::field<>s read and written through it. T is a
    // standard-layout class; the name is its Lua type name, unique like a handle's.
    template <utils::fixed_string N, class T>
        requires(utils::is_identifier(N.view()) && detail::name_free<Entries...>(N.view())) && detail::view_struct<T>
    using view = lib<Name, Entries..., detail::view_entry<N, T>>;

    // A field of a view type (the class of &T::member): t.name reads it, t.name = v writes it (kPatch,
    // journaled; a const member is read-only). A number, bool or enum; an array of span elements (a
    // span view: t.m[3] = 1); or a struct of another declared view type (a nested view). Number
    // fields take the variable tags (Rhp::range<> enforced on writes), the others unit<> and doc<>.
    template <utils::fixed_string N, auto Member, detail::var_tag... Tags>
        requires detail::field_member<Member> && (utils::is_identifier(N.view()) && detail::field_free<detail::member_owner_t<Member>, Entries...>(N.view())) &&
                     detail::valid_field_tags<Member, Tags...>
    using field = lib<Name, Entries..., detail::field_entry<N, Member, false, Tags...>>;

    // A field scripts only read.
    template <utils::fixed_string N, auto Member, detail::ro_tag... Tags>
        requires detail::field_member<Member> && (utils::is_identifier(N.view()) && detail::field_free<detail::member_owner_t<Member>, Entries...>(N.view())) &&
                     detail::valid_ro_tags<Tags...>
    using ro_field = lib<Name, Entries..., detail::field_entry<N, Member, true, Tags...>>;
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

using script::doc;
using script::irreversible;
using script::lib;
using script::range;
using script::requires_role;
using script::step;
using script::undo;
using script::unit;

} // namespace Rhp
