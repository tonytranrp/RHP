#pragma once

#include <concepts>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/core/async.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/json.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/test/fake_registry.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/function_traits.hpp>
#include <rhp/utils/type_list.hpp>

namespace Rhp::test {

// fake<L>: a lib with L's names, types, tags and handles, whose functions are recorders. Install it
// instead of L in a test sandbox and the scripts can't tell (same Lua API, same stubs), but nothing
// reaches the real program:
//
//   runner r{options, [](Rhp::script::sandbox& box) { return box.install<Rhp::test::fake<game_lib>>(); }};
//
// Every call is recorded in fake_registry by path ("game.spawn"; a method "entity:move", a property
// "entity.hp") with its arguments as values (a handle argument records nil). It returns what
// fake_registry::set_returns gave that path (from Lua: fake.returns("game.spawn", 42)), else its type's
// default (0, "", false, a default-constructed handle, an asynchronous result that is already there),
// or with fake_registry::set_strict(true) raises "not mocked". An undo<G> tag gets a recording undo
// ("game.spawn.undo"), so reverts are recorded too. Variables get storage of their own, starting at
// their range's lower bound (or a default value); like a real lib's variables it is process-wide (one
// per path, shared by every sandbox and thread), and a test's writes are journaled and undone like
// any variable write. Handles are always alive unless "<handle>?alive"
// is set to return false. Lua tests can still stub or spy on any of it.
template <script::lib_type L>
struct fake_of;

template <script::lib_type L>
using fake = typename fake_of<L>::type;

namespace detail {

using script::detail::concat_fixed;

template <class T>
value recorded(const T& v) {
    if constexpr (to_value_convertible<std::remove_cvref_t<T>>) {
        return to_value(v);
    } else {
        return value{};
    }
}

[[noreturn]] inline void raise(errc code, std::string message, std::string_view path) {
    throw Rhp::exception{make_error(code, std::move(message), std::string{path})};
}

// T when nothing was configured: its default, or (a type that only converts from a value) an
// error asking for fake.returns. A type that does neither can't be faked.
template <class T>
T default_value(std::string_view path) {
    if constexpr (std::default_initializable<T>) {
        return T{};
    } else if constexpr (from_value_convertible<T>) {
        raise(errc::kTypeMismatch, std::format("{} returns a type with no default: give it one with fake.returns", path), path);
    } else {
        static_assert(std::default_initializable<T>, "Rhp::test::fake: a result type the fake can't make (no default constructor, no Rhp::convert from_value)");
    }
}

// One value as T: from the configured values (`vals[i]`), else T's default.
template <class T>
T one_value(const std::vector<value>& vals, std::size_t i, std::string_view path) {
    using U = std::remove_cvref_t<T>;
    if constexpr (from_value_convertible<U>) {
        auto converted = from_value<U>(i < vals.size() ? vals[i] : value{});
        if (!converted) {
            raise(errc::kTypeMismatch, std::format("fake.returns for {} doesn't fit result {}: {}", path, i + 1, converted.error().message), path);
        }
        return std::move(*converted);
    } else {
        return default_value<U>(path);
    }
}

template <class T>
struct is_tuple : std::false_type {};
template <class... Ts>
struct is_tuple<std::tuple<Ts...>> : std::true_type {};

// R from configured values (or defaults when `vals` is null).
template <class R>
R make_return(const std::vector<value>* vals, std::string_view path) {
    using U = std::remove_cvref_t<R>;
    static const std::vector<value> none{};
    const std::vector<value>& v = vals != nullptr ? *vals : none;
    if constexpr (std::is_lvalue_reference_v<R>) {
        // A struct view's object by reference: one default object per result type, for the fake's views.
        static U object{};
        return object;
    } else if constexpr (is_async_v<U>) {
        using T = typename U::value_type;
        if constexpr (std::is_void_v<T>) {
            return U::completed(result<void>{});
        } else {
            return U::completed(result<T>{vals != nullptr ? make_return<T>(vals, path) : default_value<T>(path)});
        }
    } else if constexpr (is_result_v<U>) {
        using T = typename U::value_type;
        if constexpr (std::is_void_v<T>) {
            return U{};
        } else {
            return U{vals != nullptr ? make_return<T>(vals, path) : default_value<T>(path)};
        }
    } else if constexpr (is_tuple<U>::value) {
        return [&]<std::size_t... I>(std::index_sequence<I...>) {
            return U{one_value<std::tuple_element_t<I, U>>(v, I, path)...};
        }(std::make_index_sequence<std::tuple_size_v<U>>{});
    } else {
        if (vals == nullptr) {
            return default_value<U>(path);
        }
        return one_value<U>(v, 0, path);
    }
}

// The recorder standing in for one function: same signature, a path of its own.
template <utils::fixed_string Path, class R, class Args>
struct recorder;

template <utils::fixed_string Path, class R, class... A>
struct recorder<Path, R, utils::type_list<A...>> {
    static R call(A... args) {
        auto& registry = fake_registry::instance();
        std::vector<value> recorded_args{recorded(args)...};
        const auto configured = registry.returns(Path.view());
        if (!configured && registry.strict()) {
            std::string shown;
            for (const value& a : recorded_args) {
                shown += (shown.empty() ? "" : ", ") + json::to_text(a);
            }
            registry.record(Path.view(), std::move(recorded_args));
            raise(errc::kNotFound, std::format("not mocked: {}({})", Path.view(), shown), Path.view());
        }
        registry.record(Path.view(), std::move(recorded_args));
        if constexpr (std::is_void_v<R>) {
            return;
        } else {
            return make_return<R>(configured ? &*configured : nullptr, Path.view());
        }
    }
};

// A handle's is_alive: true unless "<path>" was set to return false.
template <utils::fixed_string Path, class H>
struct alive {
    static bool call(const H&) {
        const auto configured = fake_registry::instance().returns(Path.view());
        if (configured && !configured->empty()) {
            const value& first = configured->front();
            if (const auto* b = first.get_if<bool>()) {
                return *b;
            }
        }
        return true;
    }
};

template <auto F>
using traits_of = utils::function_traits<decltype(F)>;

template <utils::fixed_string Path, auto F>
inline constexpr auto recorder_v = &recorder<Path, typename traits_of<F>::return_type, typename traits_of<F>::args>::call;

// Tags: an undo<G> gets a recording undo; the rest stay.
template <utils::fixed_string Path, class Tag>
struct fake_tag {
    using type = Tag;
};

template <utils::fixed_string Path, auto G>
struct fake_tag<Path, script::undo<G>> {
    using type = script::undo<recorder_v<concat_fixed<Path, utils::fixed_string{".undo"}>(), G>>;
};

// Storage of a fake variable, starting at its range's lower bound (else a default value).
template <class T, class Meta>
T initial_value() {
    if constexpr (Meta::has_range) {
        return static_cast<T>(Meta::range_tag::min);
    } else {
        static_assert(std::default_initializable<T>, "Rhp::test::fake: a variable type the fake can't store (it isn't default-constructible)");
        return T{};
    }
}

template <utils::fixed_string Path, class T, class Meta>
inline T storage = initial_value<T, Meta>();

template <class Root, utils::fixed_string Prefix, class Entry>
struct fake_entry;

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, auto F, class... Tags>
struct fake_entry<Root, Prefix, script::detail::fn_entry<N, F, Tags...>> {
    static constexpr auto path = concat_fixed<concat_fixed<Prefix, utils::fixed_string{"."}>(), N>();
    using type = script::detail::fn_entry<N, recorder_v<path, F>, typename fake_tag<path, Tags>::type...>;
};

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, auto Ptr, class... Tags>
struct fake_entry<Root, Prefix, script::detail::var_entry<N, Ptr, Tags...>> {
    static constexpr auto path = concat_fixed<concat_fixed<Prefix, utils::fixed_string{"."}>(), N>();
    using entry = script::detail::var_entry<N, Ptr, Tags...>;
    using type = script::detail::var_entry<N, &storage<path, typename entry::value_type, typename entry::meta>, Tags...>;
};

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, auto Ptr, class... Tags>
struct fake_entry<Root, Prefix, script::detail::ro_entry<N, Ptr, Tags...>> {
    static constexpr auto path = concat_fixed<concat_fixed<Prefix, utils::fixed_string{"."}>(), N>();
    using entry = script::detail::ro_entry<N, Ptr, Tags...>;
    using type = script::detail::ro_entry<N, &storage<path, typename entry::value_type, typename entry::meta>, Tags...>;
};

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, class H, auto IsAlive>
struct fake_entry<Root, Prefix, script::detail::handle_entry<N, H, IsAlive>> {
    static constexpr auto path = concat_fixed<N, utils::fixed_string{"?alive"}>();
    using type = script::detail::handle_entry<N, H, &alive<path, H>::call>;
};

// View types and their fields stay as they are: a fake's view bindings return an empty span, a null
// pointer (nil) or one default object.
template <class Root, utils::fixed_string Prefix, utils::fixed_string N, class T>
struct fake_entry<Root, Prefix, script::detail::view_entry<N, T>> {
    using type = script::detail::view_entry<N, T>;
};

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, auto Member, bool ReadOnly, class... Tags>
struct fake_entry<Root, Prefix, script::detail::field_entry<N, Member, ReadOnly, Tags...>> {
    using type = script::detail::field_entry<N, Member, ReadOnly, Tags...>;
};

template <class Root, class Self>
using handle_of = script::detail::find_handle_t<script::detail::handles_of_t<Root>, Self>;

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, auto F, class... Tags>
struct fake_entry<Root, Prefix, script::detail::method_entry<N, F, Tags...>> {
    static constexpr auto path = concat_fixed<concat_fixed<handle_of<Root, script::detail::self_t<F>>::fixed_name, utils::fixed_string{":"}>(), N>();
    using type = script::detail::method_entry<N, recorder_v<path, F>, typename fake_tag<path, Tags>::type...>;
};

template <class Root, utils::fixed_string Prefix, utils::fixed_string N, auto F, class... Tags>
struct fake_entry<Root, Prefix, script::detail::property_entry<N, F, Tags...>> {
    static constexpr auto path = concat_fixed<concat_fixed<handle_of<Root, script::detail::self_t<F>>::fixed_name, utils::fixed_string{"."}>(), N>();
    using type = script::detail::property_entry<N, recorder_v<path, F>, Tags...>;
};

template <class Root, utils::fixed_string Prefix, class Lib>
struct fake_lib;

template <class Root, utils::fixed_string Prefix, class Lib>
struct fake_entry<Root, Prefix, script::detail::sub_entry<Lib>> {
    using type = script::detail::sub_entry<typename fake_lib<Root, concat_fixed<concat_fixed<Prefix, utils::fixed_string{"."}>(), Lib::fixed_name>(), Lib>::type>;
};

template <class Root, utils::fixed_string Prefix, utils::fixed_string Name, class... Entries>
struct fake_lib<Root, Prefix, script::lib<Name, Entries...>> {
    using type = script::lib<Name, typename fake_entry<Root, Prefix, Entries>::type...>;
};

} // namespace detail

template <script::lib_type L>
struct fake_of {
    using type = typename detail::fake_lib<L, L::fixed_name, L>::type;
};

} // namespace Rhp::test
