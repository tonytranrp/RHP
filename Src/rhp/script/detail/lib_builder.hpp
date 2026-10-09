#pragma once

#include <algorithm>
#include <cstddef>
#include <exception>
#include <expected>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/var_layers.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/stack.hpp>
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

// ---- collecting handles across a lib tree --------------------------------------------------------

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

// The handle entry for C++ type T in Handles, or void.
template <class Handles, class T>
struct find_handle {
    using type = void;
};

template <class T, class Entry, class... Rest>
struct find_handle<utils::type_list<Entry, Rest...>, T> {
    using type = std::conditional_t<std::is_same_v<typename Entry::type, T>, Entry, typename find_handle<utils::type_list<Rest...>, T>::type>;
};

template <class Handles, class T>
using find_handle_t = typename find_handle<Handles, std::remove_cvref_t<T>>::type;

template <class Handles, class T>
inline constexpr bool is_handle_v = !std::is_void_v<find_handle_t<Handles, T>>;

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
    static constexpr bool by_value_or_const_ref = !std::is_reference_v<T> || std::is_const_v<std::remove_reference_t<T>>;
    static constexpr bool pull_ok = by_value_or_const_ref && (handle || optional_handle || pullable<U>);
    static constexpr bool push_ok = handle || optional_handle || pushable<U>;
};

template <class Handles, class T>
result<std::remove_cvref_t<T>> pull_arg(stack& s, int index) {
    using U = std::remove_cvref_t<T>;
    if constexpr (is_handle_v<Handles, U>) {
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

// Pushes a binding's result; returns the number of Lua results. Rhp::result errors are raised.
template <class Handles, class R>
int push_return(stack& s, std::string_view label, R& r) {
    if constexpr (is_tuple_v<R>) {
        std::apply([&](const auto&... items) { (push_arg<Handles>(s, items), ...); }, r);
        return static_cast<int>(std::tuple_size_v<R>);
    } else if constexpr (is_result_v<R>) {
        if (!r) {
            error err = r.error();
            if (err.where.empty()) {
                err.where = std::string{label};
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

[[nodiscard]] inline error arg_error(error err, std::string_view label, std::size_t position) {
    err.where = std::format("{} (argument {})", label, position);
    return err;
}

// Effect recorded by a binding tagged Rhp::undo<G>: calls G with the captured values.
template <auto G, class... Captured>
class undo_call_effect final : public effect {
public:
    explicit undo_call_effect(Captured... captured) : captured_(std::move(captured)...) {}

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

// What an undo keeps of an argument: views into Lua strings are copied, they die with the call.
template <class T>
using capture_t = std::conditional_t<std::is_same_v<storage_t<T>, std::string_view>, std::string, storage_t<T>>;

template <class Handles, class Entry, std::size_t... Is>
int invoke_fn(stack& s, context& ctx, std::string_view label, std::index_sequence<Is...>) {
    using args = typename Entry::traits::args;
    using R = typename Entry::traits::return_type;
    constexpr bool keep_args = Entry::feed == undo_feed::kArgs;

    std::tuple<result<storage_t<utils::at_t<args, Is>>>...> pulled{
        pull_arg<Handles, utils::at_t<args, Is>>(s, static_cast<int>(Is) + 1)...};
    std::optional<error> bad;
    ((bad || std::get<Is>(pulled) ? void() : void(bad = arg_error(std::get<Is>(pulled).error(), label, Is + 1))), ...);
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
        thrown = make_error(errc::kRuntime, e.what(), std::string{label});
    }
    if (thrown) {
        if (thrown->where.empty()) {
            thrown->where = std::string{label};
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
                ctx.record_effect(std::string{label}, std::make_unique<undo_call_effect<Entry::undo_tag::function, V>>(**out));
            } else {
                ctx.record_effect(std::string{label}, std::make_unique<undo_call_effect<Entry::undo_tag::function, V>>(*out));
            }
        } else if constexpr (Entry::feed == undo_feed::kArgs) {
            ctx.record_effect(std::string{label},
                              std::make_unique<undo_call_effect<Entry::undo_tag::function, capture_t<utils::at_t<args, Is>>...>>(
                                  *std::get<Is>(pulled)...));
        } else if constexpr (Entry::is_irreversible) {
            ctx.record_effect(std::string{label}, std::make_unique<irreversible_effect>());
        }
    }

    if constexpr (std::is_void_v<R>) {
        return 0;
    } else {
        return push_return<Handles>(s, label, *out);
    }
}

// Upvalue 1 of every binding closure is its full label ("game.debug.dump").
template <class Handles, class Entry>
int call_fn(lua_State* L) {
    stack s{L};
    context& ctx = s.context();
    const std::string_view label = s.upvalue_string(1);
    if (!allows(ctx.caller_role(), Entry::required)) {
        s.raise(forbidden(label, Entry::required));
    }
    return invoke_fn<Handles, Entry>(s, ctx, label, std::make_index_sequence<Entry::traits::arity>{});
}

template <class Handles, class Entry>
int get_var(lua_State* L) {
    stack s{L};
    push_arg<Handles>(s, *Entry::pointer);
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
    auto fx = std::make_unique<typename var_layers<Entry::pointer>::write_effect>(*Entry::pointer);
    *Entry::pointer = std::move(*incoming);
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
            s.push_string(path);
            s.push_function(&get_var<Handles, Entry>, 1);
            s.set_field(getters, Entry::name);
            s.push_string(path);
            s.push_function(&set_var<Handles, Entry>, 1);
            s.set_field(setters, Entry::name);
        } else if constexpr (Entry::kind == entry_kind::kRo) {
            s.push_string(path);
            s.push_function(&get_var<Handles, Entry>, 1);
            s.set_field(getters, Entry::name);
        } else if constexpr (Entry::kind == entry_kind::kSub) {
            lib_builder<typename Entry::lib, Handles>::push(s, path);
            s.set_field(members, Entry::name);
        }
        // Handles are defined once for the whole tree before building (see install_lib_tree).
    }
};

template <class Handles>
struct handle_definer;

template <class... Hs>
struct handle_definer<utils::type_list<Hs...>> {
    static result<void> define([[maybe_unused]] stack& s) {
        result<void> r{};
        ((r = r ? s.define_userdata_type(handle_key_v<Hs>.view(), Hs::name, &handle_type_tag_v<typename Hs::type>,
                                         &handle_eq<Hs>, &handle_tostring<Hs>)
                : r),
         ...);
        return r;
    }
};

// Runs in protected mode (sandbox::install): defines the handle types, then pushes the lib proxy.
template <class Lib>
int install_lib_tree(lua_State* L) {
    stack s{L};
    using handles = handles_of_t<Lib>;
    if (auto defined = handle_definer<handles>::define(s); !defined) {
        s.raise(defined.error());
    }
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

template <utils::fixed_string N, auto F, class... Tags, class Handles>
struct entry_installable<fn_entry<N, F, Tags...>, Handles>
    : std::bool_constant<params_ok<utils::args_t<decltype(F)>, Handles>::value &&
                         return_traits<Handles, std::remove_cvref_t<utils::return_type_t<decltype(F)>>>::ok &&
                         !std::is_reference_v<utils::return_type_t<decltype(F)>>> {};

template <utils::fixed_string N, auto Ptr, class Handles>
struct entry_installable<var_entry<N, Ptr>, Handles>
    : std::bool_constant<arg_traits<Handles, typename var_entry<N, Ptr>::value_type>::pull_ok &&
                         arg_traits<Handles, typename var_entry<N, Ptr>::value_type>::push_ok> {};

template <utils::fixed_string N, auto Ptr, class Handles>
struct entry_installable<ro_entry<N, Ptr>, Handles>
    : std::bool_constant<arg_traits<Handles, typename ro_entry<N, Ptr>::value_type>::push_ok> {};

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

} // namespace Rhp::script::detail

namespace Rhp::script {

// Every binding's parameter and result type crosses the Lua boundary (as a handle or through
// Rhp::convert), and handle names/types are unique across the whole lib tree.
template <class L>
concept installable = lib_type<L> && detail::lib_installable<L, detail::handles_of_t<L>>::value &&
                      detail::handles_distinct<detail::handles_of_t<L>>::value;

} // namespace Rhp::script
