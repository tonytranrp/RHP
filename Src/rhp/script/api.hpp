#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include <rhp/core/convert.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/type_list.hpp>

namespace Rhp::script::api {

// A lib as a value tree: what it offers a caller of a given role, with LuaLS type names (the same
// as stubs::generate). Test runners build fakes from it when the real program isn't there
// (rhp-cli test --api), and scripts read the installed libs' descriptions with rhp.api().
// Needs no Lua, so it also works with RHP_ENABLE=OFF.
//
//   {name = "game", path = "game",
//    functions = {{name, params = {"integer", ...}, returns = {"entity"}, async, role, undo, irreversible}},
//    variables = {{name, type, writable, min?, max?, step?, unit?, doc?}},
//    handles = {{name, methods = {<function>...}, properties = {{name, type, role}}}},
//    views = {{name, fields = {{name, type, writable, min?, max?, step?, unit?, doc?}}}}, (only when the lib declares one)
//    libs = {<sub-lib>...}}
//
// A method's params leave out the handle itself. Handles are listed on the lib that declares them.

namespace detail {

class object {
public:
    object& set(std::string_view key, value v) {
        fields_.emplace_back(value{std::string{key}}, std::move(v));
        return *this;
    }
    [[nodiscard]] value done() { return value{std::move(fields_)}; }

private:
    value::map fields_;
};

template <utils::type_list_like Handles, class R>
void append_returns(value::array& out) {
    using U = std::remove_cvref_t<R>;
    if constexpr (std::is_void_v<U>) {
        return;
    } else if constexpr (script::detail::is_tuple_v<U>) {
        [&]<class... Ts>(std::type_identity<std::tuple<Ts...>>) {
            (out.emplace_back(stubs::detail::type_name<Handles, Ts>()), ...);
        }(std::type_identity<U>{});
    } else if constexpr (is_result_v<U> || is_async_v<U>) {
        append_returns<Handles, typename U::value_type>(out);
    } else {
        out.emplace_back(stubs::detail::type_name<Handles, U>());
    }
}

template <utils::type_list_like Handles, utils::type_list_like Args, std::size_t First, std::size_t... Is>
value params([[maybe_unused]] std::index_sequence<Is...>) {
    value::array out;
    (out.emplace_back(stubs::detail::type_name<Handles, utils::at_t<Args, Is + First>>()), ...);
    return value{std::move(out)};
}

// A function or method entry; `skip` parameters are left out (1: a method's handle).
template <utils::type_list_like Handles, class Entry, std::size_t Skip>
value function() {
    using traits = typename Entry::traits;
    value::array returns;
    append_returns<Handles, typename traits::return_type>(returns);
    object o;
    o.set("name", value{std::string{Entry::name}})
        .set("params", params<Handles, typename traits::args, Skip>(std::make_index_sequence<traits::arity - Skip>{}))
        .set("returns", value{std::move(returns)})
        .set("async", value{Entry::is_async})
        .set("role", value{std::string{to_string(Entry::required)}})
        .set("undo", value{Entry::feed != script::detail::undo_feed::kNone})
        .set("irreversible", value{Entry::is_irreversible});
    return o.done();
}

template <class Meta>
void describe_tags(object& o) {
    if (const auto lo = Meta::lower()) {
        o.set("min", value{*lo});
    }
    if (const auto hi = Meta::upper()) {
        o.set("max", value{*hi});
    }
    if (const auto step = Meta::step()) {
        o.set("step", value{*step});
    }
    if (!Meta::unit().empty()) {
        o.set("unit", value{std::string{Meta::unit()}});
    }
    if (!Meta::doc().empty()) {
        o.set("doc", value{std::string{Meta::doc()}});
    }
}

template <utils::type_list_like Handles, class H, class... Ms>
value handle(role caller, utils::type_list<Ms...>) {
    value::array methods;
    value::array properties;
    const auto member = [&]<class M>(std::type_identity<M>) {
        if constexpr (std::is_same_v<typename M::self_type, typename H::type>) {
            if (!allows(caller, M::required)) {
                return;
            }
            if constexpr (M::kind == script::detail::entry_kind::kProperty) {
                object p;
                p.set("name", value{std::string{M::name}})
                    .set("type", value{stubs::detail::result_types<Handles, typename M::traits::return_type>()})
                    .set("role", value{std::string{to_string(M::required)}});
                properties.push_back(p.done());
            } else {
                methods.push_back(function<Handles, M, 1>());
            }
        }
    };
    (member(std::type_identity<Ms>{}), ...);
    object o;
    o.set("name", value{std::string{H::name}}).set("methods", value{std::move(methods)}).set("properties", value{std::move(properties)});
    return o.done();
}

// A view type: its fields as variables are described ({name, type, writable, min?, ...}).
template <utils::type_list_like Handles, class V, class... Fs>
value view(role caller, utils::type_list<Fs...>) {
    value::array fields;
    const auto field = [&]<class F>(std::type_identity<F>) {
        if constexpr (std::is_same_v<typename F::owner_type, typename V::type>) {
            object o;
            o.set("name", value{std::string{F::name}})
                .set("type", value{stubs::detail::field_type<Handles, F>()})
                .set("writable", value{F::shape == 1 && F::writable && allows(caller, role::kPatch)});
            describe_tags<typename F::meta>(o);
            fields.push_back(o.done());
        }
    };
    (field(std::type_identity<Fs>{}), ...);
    object o;
    o.set("name", value{std::string{V::name}}).set("fields", value{std::move(fields)});
    return o.done();
}

template <utils::type_list_like Handles, class Members, class Fields, class Lib>
struct lib_describer;

template <utils::type_list_like Handles, class Members, class Fields, utils::fixed_string Name, class... Entries>
struct lib_describer<Handles, Members, Fields, lib<Name, Entries...>> {
    static value describe(std::string_view path, role caller) {
        value::array functions;
        value::array variables;
        value::array handles;
        value::array views;
        value::array subs;
        (add<Entries>(path, caller, functions, variables, handles, views, subs), ...);
        object o;
        o.set("name", value{std::string{Name.view()}})
            .set("path", value{std::string{path}})
            .set("functions", value{std::move(functions)})
            .set("variables", value{std::move(variables)})
            .set("handles", value{std::move(handles)});
        if (!views.empty()) {
            o.set("views", value{std::move(views)});
        }
        o.set("libs", value{std::move(subs)});
        return o.done();
    }

private:
    template <class Entry>
    static void add(std::string_view path, role caller, value::array& functions, value::array& variables, value::array& handles,
                    value::array& views, value::array& subs) {
        using script::detail::entry_kind;
        if constexpr (Entry::kind == entry_kind::kFn) {
            if (allows(caller, Entry::required)) {
                functions.push_back(function<Handles, Entry, 0>());
            }
        } else if constexpr (Entry::kind == entry_kind::kVar || Entry::kind == entry_kind::kRo) {
            object o;
            o.set("name", value{std::string{Entry::name}})
                .set("type", value{stubs::detail::type_name<Handles, typename Entry::value_type>()})
                .set("writable", value{Entry::kind == entry_kind::kVar && allows(caller, role::kPatch)});
            describe_tags<typename Entry::meta>(o);
            variables.push_back(o.done());
        } else if constexpr (Entry::kind == entry_kind::kHandle) {
            handles.push_back(handle<Handles, Entry>(caller, Members{}));
        } else if constexpr (Entry::kind == entry_kind::kView) {
            views.push_back(view<Handles, Entry>(caller, Fields{}));
        } else if constexpr (Entry::kind == entry_kind::kSub) {
            subs.push_back(
                lib_describer<Handles, Members, Fields, typename Entry::lib>::describe(std::string{path} + "." + std::string{Entry::name}, caller));
        }
    }
};

} // namespace detail

// One lib (and its sub-libs) for a caller role.
template <lib_type L>
[[nodiscard]] value describe(role caller = role::kAdmin) {
    using handles = script::detail::handles_of_t<L>;
    return detail::lib_describer<handles, script::detail::members_of_t<L>, script::detail::fields_in_t<L>, L>::describe(L::name, caller);
}

} // namespace Rhp::script::api
