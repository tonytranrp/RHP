#pragma once

#include <exception>
#include <expected>
#include <format>
#include <string>
#include <type_traits>
#include <utility>

#include <rhp/core/error.hpp>

namespace Rhp {

template <class T>
using result = std::expected<T, error>;

// return Rhp::fail(errc::kNotFound, "no module 'x'");
[[nodiscard]] inline std::unexpected<error> fail(errc code, std::string message = {}, std::string where = {}) {
    return std::unexpected<error>{make_error(code, std::move(message), std::move(where))};
}

[[nodiscard]] inline std::unexpected<error> fail(error err) {
    return std::unexpected<error>{std::move(err)};
}

// Thrown only in Rhp::errors::throwing mode or by Rhp::unwrap.
class exception : public std::exception {
public:
    explicit exception(error err) : err_(std::move(err)), what_(std::format("{}", err_)) {}

    [[nodiscard]] const char* what() const noexcept override { return what_.c_str(); }
    [[nodiscard]] const error& err() const noexcept { return err_; }

private:
    error err_;
    std::string what_;
};

template <class T>
inline constexpr bool is_result_v = false;

template <class T>
inline constexpr bool is_result_v<std::expected<T, error>> = true;

// Converts one call from expected-style to throwing-style.
template <class R>
    requires is_result_v<std::remove_cvref_t<R>>
decltype(auto) unwrap(R&& r) {
    if (!r) {
        throw exception{std::forward<R>(r).error()};
    }
    if constexpr (std::is_void_v<typename std::remove_cvref_t<R>::value_type>) {
        return;
    } else {
        return *std::forward<R>(r);
    }
}

} // namespace Rhp
