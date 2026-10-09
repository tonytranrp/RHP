#pragma once

#include <concepts>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <rhp/core/convert.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script {

// Moving C++ values onto and off the Lua stack.
//
// Order of preference for a type T:
//   1. built-in fast paths (bool, integers, floats, strings, std::optional, Rhp::value)
//   2. Rhp::convert<T>::push(stack&, const T&) / Rhp::convert<T>::pull(stack&, int) -> result<T>
//   3. Rhp::convert<T>::to_value / from_value, through Rhp::value
//
// So a type with only the core (wire) conversion already works in bindings; adding push/pull to
// the same specialization makes it faster without changing anything else:
//
//   template <> struct Rhp::convert<vec3> {
//       static Rhp::value to_value(const vec3& v);
//       static Rhp::result<vec3> from_value(const Rhp::value& v);
//       static void push(Rhp::script::stack& s, const vec3& v);             // optional
//       static Rhp::result<vec3> pull(Rhp::script::stack& s, int index);    // optional
//   };
//
// std::string_view is pullable here (unlike from_value): it points into the Lua string, which
// stays alive for the duration of the binding call that received it.

template <class T>
concept has_lua_push = requires(stack& s, const T& v) { Rhp::convert<T>::push(s, v); };

template <class T>
concept has_lua_pull = requires(stack& s, int index) {
    { Rhp::convert<T>::pull(s, index) } -> std::same_as<result<T>>;
};

namespace detail {

template <class T>
inline constexpr bool is_optional_v = false;

template <class T>
inline constexpr bool is_optional_v<std::optional<T>> = true;

template <class T>
concept lua_integer = std::integral<T> && !std::same_as<T, bool> && !std::same_as<T, char>;

template <class T>
concept string_like = std::same_as<T, std::string> || std::same_as<T, std::string_view> ||
                      std::same_as<T, const char*> || std::same_as<T, char*> ||
                      (std::is_array_v<T> && std::same_as<std::remove_cv_t<std::remove_extent_t<T>>, char>);

} // namespace detail

template <class T>
struct is_pushable;

template <class T>
struct is_pullable;

// T can be pushed onto the Lua stack.
template <class T>
concept pushable = is_pushable<std::remove_cvref_t<T>>::value;

// T can be read from the Lua stack.
template <class T>
concept pullable = is_pullable<std::remove_cvref_t<T>>::value;

template <class T>
struct is_pushable
    : std::bool_constant<std::same_as<T, value> || std::same_as<T, bool> || detail::lua_integer<T> || std::floating_point<T> ||
                         detail::string_like<T> || has_lua_push<T> || to_value_convertible<T>> {};

template <class T>
struct is_pushable<std::optional<T>> : is_pushable<T> {};

template <class T>
struct is_pullable
    : std::bool_constant<std::same_as<T, value> || std::same_as<T, bool> || detail::lua_integer<T> || std::floating_point<T> ||
                         std::same_as<T, std::string> || std::same_as<T, std::string_view> || has_lua_pull<T> ||
                         from_value_convertible<T>> {};

template <class T>
struct is_pullable<std::optional<T>> : is_pullable<T> {};

// ---- push -----------------------------------------------------------------------------------

template <pushable T>
void push(stack& s, const T& v) {
    using U = std::remove_cvref_t<T>;
    if constexpr (std::same_as<U, value>) {
        s.push_value(v);
    } else if constexpr (detail::is_optional_v<U>) {
        if (v) {
            push(s, *v);
        } else {
            s.push_nil();
        }
    } else if constexpr (std::same_as<U, bool>) {
        s.push_bool(v);
    } else if constexpr (detail::lua_integer<U>) {
        if constexpr (std::is_unsigned_v<U> && sizeof(U) >= sizeof(std::int64_t)) {
            if (v > static_cast<U>(std::numeric_limits<std::int64_t>::max())) {
                s.push_number(static_cast<double>(v));
                return;
            }
        }
        s.push_integer(static_cast<std::int64_t>(v));
    } else if constexpr (std::floating_point<U>) {
        s.push_number(static_cast<double>(v));
    } else if constexpr (detail::string_like<U>) {
        s.push_string(std::string_view{v});
    } else if constexpr (has_lua_push<U>) {
        Rhp::convert<U>::push(s, v);
    } else {
        s.push_value(Rhp::to_value(v));
    }
}

// ---- pull -----------------------------------------------------------------------------------

namespace detail {

[[nodiscard]] inline std::unexpected<error> lua_type_mismatch(const stack& s, int index, std::string_view expected) {
    return fail(errc::kTypeMismatch, std::format("expected {}, got {}", expected, s.type_name(index)));
}

} // namespace detail

template <pullable T>
[[nodiscard]] result<T> pull(stack& s, int index) {
    using U = std::remove_cvref_t<T>;
    if constexpr (std::same_as<U, value>) {
        return s.to_value(index);
    } else if constexpr (detail::is_optional_v<U>) {
        if (s.is_none_or_nil(index)) {
            return U{};
        }
        auto inner = pull<typename U::value_type>(s, index);
        if (!inner) {
            return std::unexpected{std::move(inner).error()};
        }
        return U{std::move(*inner)};
    } else if constexpr (std::same_as<U, bool>) {
        if (auto b = s.to_bool(index)) {
            return *b;
        }
        return detail::lua_type_mismatch(s, index, "boolean");
    } else if constexpr (detail::lua_integer<U>) {
        const auto i = s.to_integer(index);
        if (!i) {
            if (s.to_number(index)) {
                return fail(errc::kOutOfRange, std::format("{} is not an integer", *s.to_number(index)));
            }
            return detail::lua_type_mismatch(s, index, "integer");
        }
        if (!std::in_range<U>(*i)) {
            return fail(errc::kOutOfRange, std::format("{} does not fit the target integer type", *i));
        }
        return static_cast<U>(*i);
    } else if constexpr (std::floating_point<U>) {
        if (auto d = s.to_number(index)) {
            return static_cast<U>(*d);
        }
        return detail::lua_type_mismatch(s, index, "number");
    } else if constexpr (std::same_as<U, std::string> || std::same_as<U, std::string_view>) {
        if (auto str = s.to_string(index)) {
            return U{*str};
        }
        return detail::lua_type_mismatch(s, index, "string");
    } else if constexpr (has_lua_pull<U>) {
        return Rhp::convert<U>::pull(s, index);
    } else {
        auto v = s.to_value(index);
        if (!v) {
            return std::unexpected{std::move(v).error()};
        }
        return Rhp::from_value<U>(*v);
    }
}

} // namespace Rhp::script

namespace Rhp {

// Every parameter and return type of a binding must be convertible.
template <class T>
concept convertible = script::pushable<T> && script::pullable<T>;

} // namespace Rhp
