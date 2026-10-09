#pragma once

#include <concepts>
#include <functional>
#include <type_traits>
#include <utility>

namespace Rhp::utils {

// Runs a callable when the scope ends unless release() was called.
// Used for rollback paths: build up state, release() the guard once everything succeeded.
template <std::invocable F>
class scope_guard {
public:
    explicit constexpr scope_guard(F fn) noexcept(std::is_nothrow_move_constructible_v<F>)
        : fn_(std::move(fn)) {}

    scope_guard(const scope_guard&) = delete;
    scope_guard& operator=(const scope_guard&) = delete;
    scope_guard(scope_guard&&) = delete;
    scope_guard& operator=(scope_guard&&) = delete;

    constexpr ~scope_guard() {
        if (active_) {
            std::invoke(fn_);
        }
    }

    constexpr void release() noexcept { active_ = false; }
    [[nodiscard]] constexpr bool active() const noexcept { return active_; }

private:
    F fn_;
    bool active_ = true;
};

template <class F>
scope_guard(F) -> scope_guard<F>;

} // namespace Rhp::utils
