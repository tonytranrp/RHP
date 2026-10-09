#pragma once

#include <cstddef>
#include <type_traits>

#include <rhp/utils/type_list.hpp>

namespace Rhp::utils {

// Signature introspection for free functions, function pointers, member function pointers
// and callables with a single non-template operator() (lambdas, functors).
template <class F>
struct function_traits;

namespace detail {

template <class R, bool NoExcept, class Class, class... Args>
struct function_traits_base {
    using return_type = R;
    using args = type_list<Args...>;
    using class_type = Class;
    static constexpr std::size_t arity = sizeof...(Args);
    static constexpr bool is_noexcept = NoExcept;
    static constexpr bool is_member = !std::is_void_v<Class>;
};

} // namespace detail

template <class R, class... Args>
struct function_traits<R(Args...)> : detail::function_traits_base<R, false, void, Args...> {};

template <class R, class... Args>
struct function_traits<R(Args...) noexcept> : detail::function_traits_base<R, true, void, Args...> {};

template <class R, class... Args>
struct function_traits<R (*)(Args...)> : function_traits<R(Args...)> {};

template <class R, class... Args>
struct function_traits<R (*)(Args...) noexcept> : function_traits<R(Args...) noexcept> {};

template <class R, class C, class... Args>
struct function_traits<R (C::*)(Args...)> : detail::function_traits_base<R, false, C, Args...> {};

template <class R, class C, class... Args>
struct function_traits<R (C::*)(Args...) noexcept> : detail::function_traits_base<R, true, C, Args...> {};

template <class R, class C, class... Args>
struct function_traits<R (C::*)(Args...) const> : detail::function_traits_base<R, false, const C, Args...> {};

template <class R, class C, class... Args>
struct function_traits<R (C::*)(Args...) const noexcept> : detail::function_traits_base<R, true, const C, Args...> {};

// Callables: forward to operator(), but report them as non-member functions.
template <class F>
    requires requires { &F::operator(); }
struct function_traits<F> {
private:
    using call = function_traits<decltype(&F::operator())>;

public:
    using return_type = typename call::return_type;
    using args = typename call::args;
    using class_type = void;
    static constexpr std::size_t arity = call::arity;
    static constexpr bool is_noexcept = call::is_noexcept;
    static constexpr bool is_member = false;
};

template <class F>
struct function_traits<F&> : function_traits<F> {};

template <class F>
struct function_traits<F&&> : function_traits<F> {};

template <class F>
struct function_traits<const F> : function_traits<F> {};

template <class F>
concept has_function_traits = requires { typename function_traits<F>::return_type; };

template <class F>
using return_type_t = typename function_traits<F>::return_type;

template <class F>
using args_t = typename function_traits<F>::args;

template <class F>
inline constexpr std::size_t arity_v = function_traits<F>::arity;

} // namespace Rhp::utils
