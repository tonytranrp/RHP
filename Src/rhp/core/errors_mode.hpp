#pragma once

#include <concepts>
#include <type_traits>

#include <rhp/core/result.hpp>

namespace Rhp::errors {

// Error-mode policies for Rhp::config<>::errors<...>. Front-end APIs compute their results as
// Rhp::result<T> internally and hand them to Mode::finish, which decides the public shape.

struct expected {
    template <class T>
    using return_t = result<T>;

    template <class T>
    static return_t<T> finish(result<T>&& r) noexcept(std::is_nothrow_move_constructible_v<result<T>>) {
        return std::move(r);
    }
};

struct throwing {
    template <class T>
    using return_t = T;

    template <class T>
    static return_t<T> finish(result<T>&& r) {
        return unwrap(std::move(r));
    }
};

template <class M>
concept mode = requires(result<int>&& r) {
    { M::finish(std::move(r)) } -> std::same_as<typename M::template return_t<int>>;
};

} // namespace Rhp::errors
