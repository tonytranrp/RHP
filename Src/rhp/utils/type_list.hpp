#pragma once

#include <cstddef>
#include <type_traits>
#include <utility>

namespace Rhp::utils {

template <class... Ts>
struct type_list {
    [[nodiscard]] static consteval std::size_t size() noexcept { return sizeof...(Ts); }
    [[nodiscard]] static consteval bool empty() noexcept { return sizeof...(Ts) == 0; }
};

template <class T>
inline constexpr bool is_type_list_v = false;

template <class... Ts>
inline constexpr bool is_type_list_v<type_list<Ts...>> = true;

template <class T>
concept type_list_like = is_type_list_v<T>;

namespace detail {

template <std::size_t I, class T>
struct indexed {
    using type = T;
};

template <class Seq, class... Ts>
struct indexer;

template <std::size_t... Is, class... Ts>
struct indexer<std::index_sequence<Is...>, Ts...> : indexed<Is, Ts>... {};

template <std::size_t I, class T>
indexed<I, T> select(const indexed<I, T>&);

template <class T, class... Ts>
consteval std::size_t index_of() noexcept {
    constexpr bool matches[] = {std::is_same_v<T, Ts>..., false};
    for (std::size_t i = 0; i < sizeof...(Ts); ++i) {
        if (matches[i]) {
            return i;
        }
    }
    return sizeof...(Ts);
}

template <class T, class... Ts>
consteval std::size_t count_of() noexcept {
    return (std::size_t{0} + ... + (std::is_same_v<T, Ts> ? 1u : 0u));
}

} // namespace detail

// ---- size / contains / index_of ------------------------------------------------------------

template <type_list_like List>
inline constexpr std::size_t size_v = List::size();

template <class List, class T>
inline constexpr bool contains_v = false;

template <class... Ts, class T>
inline constexpr bool contains_v<type_list<Ts...>, T> = (std::is_same_v<T, Ts> || ...);

template <class List, class T>
inline constexpr std::size_t index_of_v = 0;

template <class... Ts, class T>
    requires(contains_v<type_list<Ts...>, T>)
inline constexpr std::size_t index_of_v<type_list<Ts...>, T> = detail::index_of<T, Ts...>();

template <class List>
inline constexpr bool is_unique_v = false;

template <class... Ts>
inline constexpr bool is_unique_v<type_list<Ts...>> = ((detail::count_of<Ts, Ts...>() == 1) && ...);

// ---- at ------------------------------------------------------------------------------------

template <class List, std::size_t I>
struct at;

template <class... Ts, std::size_t I>
    requires(I < sizeof...(Ts))
struct at<type_list<Ts...>, I> {
    using type = typename decltype(detail::select<I>(detail::indexer<std::index_sequence_for<Ts...>, Ts...>{}))::type;
};

template <class List, std::size_t I>
using at_t = typename at<List, I>::type;

// ---- push / concat -------------------------------------------------------------------------

template <class List, class T>
struct push_back;

template <class... Ts, class T>
struct push_back<type_list<Ts...>, T> {
    using type = type_list<Ts..., T>;
};

template <class List, class T>
using push_back_t = typename push_back<List, T>::type;

template <class List, class T>
struct push_front;

template <class... Ts, class T>
struct push_front<type_list<Ts...>, T> {
    using type = type_list<T, Ts...>;
};

template <class List, class T>
using push_front_t = typename push_front<List, T>::type;

template <class... Lists>
struct concat {
    using type = type_list<>;
};

template <class... Ts>
struct concat<type_list<Ts...>> {
    using type = type_list<Ts...>;
};

template <class... Ts, class... Us, class... Rest>
struct concat<type_list<Ts...>, type_list<Us...>, Rest...> {
    using type = typename concat<type_list<Ts..., Us...>, Rest...>::type;
};

template <class... Lists>
using concat_t = typename concat<Lists...>::type;

// ---- transform / filter ------------------------------------------------------------------

template <class List, template <class> class F>
struct transform;

template <class... Ts, template <class> class F>
struct transform<type_list<Ts...>, F> {
    using type = type_list<typename F<Ts>::type...>;
};

template <class List, template <class> class F>
using transform_t = typename transform<List, F>::type;

template <class List, template <class> class Pred>
struct filter;

template <class... Ts, template <class> class Pred>
struct filter<type_list<Ts...>, Pred> {
    using type = concat_t<type_list<>, std::conditional_t<Pred<Ts>::value, type_list<Ts>, type_list<>>...>;
};

template <class List, template <class> class Pred>
using filter_t = typename filter<List, Pred>::type;

// ---- for_each_type -----------------------------------------------------------------------

template <class T>
struct type_tag {
    using type = T;
};

// Calls fn(type_tag<T>{}) for every T in the list, in order.
template <type_list_like List, class Fn>
constexpr void for_each_type(Fn&& fn) {
    [&]<class... Ts>(type_list<Ts...>) {
        (fn(type_tag<Ts>{}), ...);
    }(List{});
}

} // namespace Rhp::utils
