#pragma once

// Reply bodies as the client's calls return them: shared by client<Cfg> (blocking and async calls)
// and fleet<Cfg>. Header-only: client.hpp uses them in RHP_ENABLE=OFF builds too.

#include <utility>

#include <rhp/core/convert.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::client_detail {

// The returned values (what exec and call return): an array reply as it is, any other value as a
// list of one.
[[nodiscard]] inline result<value_list> values(result<value>&& r) {
    if (!r) {
        return std::unexpected{std::move(r).error()};
    }
    if (auto* items = r->get_if<value::array>()) {
        return std::move(*items);
    }
    return value_list{std::move(*r)};
}

// The reply converted to T.
template <from_value_convertible T>
[[nodiscard]] result<T> as(result<value>&& r) {
    if (!r) {
        return std::unexpected{std::move(r).error()};
    }
    return Rhp::from_value<T>(*r);
}

// The first returned value converted to T (nil when nothing was returned).
template <from_value_convertible T>
[[nodiscard]] result<T> first(result<value>&& r) {
    auto list = values(std::move(r));
    if (!list) {
        return std::unexpected{std::move(list).error()};
    }
    return Rhp::from_value<T>(list->empty() ? value{} : list->front());
}

// Only whether it succeeded.
[[nodiscard]] inline result<void> nothing(result<value>&& r) {
    if (!r) {
        return std::unexpected{std::move(r).error()};
    }
    return {};
}

} // namespace Rhp::client_detail
