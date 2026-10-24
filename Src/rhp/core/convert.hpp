#pragma once

#include <concepts>
#include <cstdint>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>

namespace Rhp {

// Customization point: how a C++ type becomes an Rhp::value and back.
// Specialize for your own types:
//
//   template <> struct Rhp::convert<vec3> {
//       static Rhp::value to_value(const vec3& v);
//       static Rhp::result<vec3> from_value(const Rhp::value& v);
//   };
//
// The Lua side (push/pull on a script stack) is a separate, optional pair of members added by
// the script layer; this layer only knows about Rhp::value.
template <class T>
struct convert;

template <class T>
concept to_value_convertible = requires(const std::remove_cvref_t<T>& t) {
    { convert<std::remove_cvref_t<T>>::to_value(t) } -> std::same_as<value>;
};

template <class T>
concept from_value_convertible = requires(const value& v) {
    { convert<std::remove_cvref_t<T>>::from_value(v) } -> std::same_as<result<std::remove_cvref_t<T>>>;
};

template <class T>
concept wire_convertible = to_value_convertible<T> && from_value_convertible<T>;

template <to_value_convertible T>
[[nodiscard]] value to_value(const T& t) {
    return convert<std::remove_cvref_t<T>>::to_value(t);
}

template <from_value_convertible T>
[[nodiscard]] result<T> from_value(const value& v) {
    return convert<T>::from_value(v);
}

namespace detail {

[[nodiscard]] inline std::unexpected<error> type_mismatch(std::string_view expected, const value& got) {
    return fail(errc::kTypeMismatch, std::format("expected {}, got {}", expected, to_string(got.type())));
}

} // namespace detail

// ---- built-in conversions -------------------------------------------------------------------

template <>
struct convert<value> {
    static value to_value(const value& v) { return v; }
    static result<value> from_value(const value& v) { return v; }
};

template <>
struct convert<value::nil_t> {
    static value to_value(const value::nil_t&) { return {}; }
    static result<value::nil_t> from_value(const value& v) {
        if (!v.is_nil()) {
            return detail::type_mismatch("nil", v);
        }
        return value::nil_t{};
    }
};

template <>
struct convert<bool> {
    static value to_value(bool b) { return b; }
    static result<bool> from_value(const value& v) {
        if (const auto* b = v.get_if<bool>()) {
            return *b;
        }
        return detail::type_mismatch("boolean", v);
    }
};

template <std::integral T>
    requires(!std::same_as<T, bool> && !std::same_as<T, char>)
struct convert<T> {
    static value to_value(T i) {
        if constexpr (std::is_unsigned_v<T> && sizeof(T) >= sizeof(std::int64_t)) {
            // Values above INT64_MAX don't fit Lua integers; send them as numbers.
            if (i > static_cast<T>((std::numeric_limits<std::int64_t>::max)())) {
                return static_cast<double>(i);
            }
        }
        return value{static_cast<std::int64_t>(i)};
    }

    static result<T> from_value(const value& v) {
        std::int64_t i = 0;
        if (const auto* p = v.get_if<std::int64_t>()) {
            i = *p;
        } else if (const auto* d = v.get_if<double>()) {
            // Lua numbers with an exact integer value are accepted.
            if (*d != *d || *d < -9.2233720368547758e18 || *d >= 9.2233720368547758e18 ||
                static_cast<double>(static_cast<std::int64_t>(*d)) != *d) {
                return fail(errc::kOutOfRange, std::format("{} is not an integer", *d));
            }
            i = static_cast<std::int64_t>(*d);
        } else {
            return detail::type_mismatch("integer", v);
        }
        if (!std::in_range<T>(i)) {
            return fail(errc::kOutOfRange, std::format("{} does not fit the target integer type", i));
        }
        return static_cast<T>(i);
    }
};

template <std::floating_point T>
struct convert<T> {
    static value to_value(T d) { return value{d}; }
    static result<T> from_value(const value& v) {
        if (const auto* d = v.get_if<double>()) {
            return static_cast<T>(*d);
        }
        if (const auto* i = v.get_if<std::int64_t>()) {
            return static_cast<T>(*i);
        }
        return detail::type_mismatch("number", v);
    }
};

template <>
struct convert<std::string> {
    static value to_value(const std::string& s) { return value{s}; }
    static result<std::string> from_value(const value& v) {
        if (const auto* s = v.get_if<std::string>()) {
            return *s;
        }
        return detail::type_mismatch("string", v);
    }
};

// Outgoing only: a view can't own what it would point into.
template <>
struct convert<std::string_view> {
    static value to_value(std::string_view s) { return value{s}; }
};

template <>
struct convert<const char*> {
    static value to_value(const char* s) { return value{s}; }
};

template <std::size_t N>
struct convert<char[N]> {
    static value to_value(const char (&s)[N]) { return value{std::string_view{s}}; }
};

template <>
struct convert<value::bytes> {
    static value to_value(const value::bytes& b) { return value{b}; }
    static result<value::bytes> from_value(const value& v) {
        if (const auto* b = v.get_if<value::bytes>()) {
            return *b;
        }
        if (const auto* s = v.get_if<std::string>()) {
            const auto* p = reinterpret_cast<const std::byte*>(s->data());
            return value::bytes(p, p + s->size());
        }
        return detail::type_mismatch("bytes", v);
    }
};

template <class T>
    requires(!std::same_as<T, value> && !std::same_as<T, std::byte>)
struct convert<std::vector<T>> {
    static value to_value(const std::vector<T>& items)
        requires to_value_convertible<T>
    {
        value::array out;
        out.reserve(items.size());
        for (const auto& item : items) {
            out.push_back(Rhp::to_value(item));
        }
        return value{std::move(out)};
    }

    static result<std::vector<T>> from_value(const value& v)
        requires from_value_convertible<T>
    {
        const auto* items = v.get_if<value::array>();
        if (items == nullptr) {
            return detail::type_mismatch("array", v);
        }
        std::vector<T> out;
        out.reserve(items->size());
        for (std::size_t i = 0; i < items->size(); ++i) {
            auto item = Rhp::from_value<T>((*items)[i]);
            if (!item) {
                item.error().where = std::format("[{}]", i + 1);
                return std::unexpected{std::move(item).error()};
            }
            out.push_back(std::move(*item));
        }
        return out;
    }
};

template <class T>
struct convert<std::optional<T>> {
    static value to_value(const std::optional<T>& o)
        requires to_value_convertible<T>
    {
        return o ? Rhp::to_value(*o) : value{};
    }

    static result<std::optional<T>> from_value(const value& v)
        requires from_value_convertible<T>
    {
        if (v.is_nil()) {
            return std::optional<T>{};
        }
        auto inner = Rhp::from_value<T>(v);
        if (!inner) {
            return std::unexpected{std::move(inner).error()};
        }
        return std::optional<T>{std::move(*inner)};
    }
};

template <class K, class V>
struct convert<std::map<K, V>> {
    static value to_value(const std::map<K, V>& m)
        requires to_value_convertible<K> && to_value_convertible<V>
    {
        value::map out;
        out.reserve(m.size());
        for (const auto& [k, v] : m) {
            out.emplace_back(Rhp::to_value(k), Rhp::to_value(v));
        }
        return value{std::move(out)};
    }

    static result<std::map<K, V>> from_value(const value& v)
        requires from_value_convertible<K> && from_value_convertible<V>
    {
        const auto* entries = v.get_if<value::map>();
        if (entries == nullptr) {
            return detail::type_mismatch("map", v);
        }
        std::map<K, V> out;
        for (const auto& [k, item] : *entries) {
            auto key = Rhp::from_value<K>(k);
            if (!key) {
                return std::unexpected{std::move(key).error()};
            }
            auto mapped = Rhp::from_value<V>(item);
            if (!mapped) {
                return std::unexpected{std::move(mapped).error()};
            }
            out.insert_or_assign(std::move(*key), std::move(*mapped));
        }
        return out;
    }
};

// Ids travel as their integer.
template <class Tag, class Rep>
struct convert<strong_id<Tag, Rep>> {
    static value to_value(const strong_id<Tag, Rep>& id) { return convert<Rep>::to_value(id.value()); }
    static result<strong_id<Tag, Rep>> from_value(const value& v) {
        auto raw = convert<Rep>::from_value(v);
        if (!raw) {
            return std::unexpected{std::move(raw).error()};
        }
        return strong_id<Tag, Rep>{*raw};
    }
};

// {code = "forbidden", message = ..., where = ..., traceback = ...}; empty strings are left out.
// Unknown code names decode as kRuntime, so a newer peer's codes still arrive as errors.
template <>
struct convert<error> {
    static value to_value(const error& err) {
        value::map m;
        m.emplace_back("code", value{to_string(err.code)});
        if (!err.message.empty()) {
            m.emplace_back("message", value{err.message});
        }
        if (!err.where.empty()) {
            m.emplace_back("where", value{err.where});
        }
        if (!err.traceback.empty()) {
            m.emplace_back("traceback", value{err.traceback});
        }
        return value{std::move(m)};
    }

    static result<error> from_value(const value& v) {
        if (!v.is_map()) {
            return detail::type_mismatch("error map", v);
        }
        error err;
        err.code = errc::kRuntime;
        if (const auto* code = v.find("code"); code != nullptr && code->is_string()) {
            const std::string& name = *code->get_if<std::string>();
            for (auto c = static_cast<std::uint16_t>(errc::kOk); c <= static_cast<std::uint16_t>(kLastErrc); ++c) {
                if (to_string(static_cast<errc>(c)) == name) {
                    err.code = static_cast<errc>(c);
                    break;
                }
            }
        }
        const auto text = [&v](std::string_view key) -> std::string {
            const auto* s = v.find(key);
            return s != nullptr && s->is_string() ? *s->get_if<std::string>() : std::string{};
        };
        err.message = text("message");
        err.where = text("where");
        err.traceback = text("traceback");
        return err;
    }
};

} // namespace Rhp
