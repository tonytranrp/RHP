#pragma once

#include <cstddef>
#include <limits>

namespace Rhp::literals {

namespace detail {

consteval std::size_t scale(unsigned long long value, unsigned long long factor) {
    if (value > (std::numeric_limits<std::size_t>::max)() / factor) {
        throw "Rhp size literal overflows std::size_t";
    }
    return static_cast<std::size_t>(value * factor);
}

} // namespace detail

consteval std::size_t operator""_KiB(unsigned long long value) {
    return detail::scale(value, 1024ull);
}
consteval std::size_t operator""_MiB(unsigned long long value) {
    return detail::scale(value, 1024ull * 1024ull);
}
consteval std::size_t operator""_GiB(unsigned long long value) {
    return detail::scale(value, 1024ull * 1024ull * 1024ull);
}

} // namespace Rhp::literals
