#pragma once

#include <exception>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

// The error a C++ exception from user code (a binding, a patch point's default) becomes: an
// Rhp::exception's own error, else kRuntime with what(); labelled `label` when it names no place.
[[nodiscard]] inline error binding_error(const std::exception& e, std::string_view label) {
    const auto* own = dynamic_cast<const Rhp::exception*>(&e);
    error err = own != nullptr ? own->err() : make_error(errc::kRuntime, e.what());
    if (err.where.empty()) {
        err.where = std::string{label};
    }
    return err;
}

// Returns fn() (user code) from a Lua C function. An exception it throws becomes a Lua error
// (binding_error), raised after the try block: Lua's own errors aren't std::exceptions and pass
// through, so nothing here catches (...). `label` converts to std::string_view and is read only
// when something was thrown.
template <class Label, class Fn>
std::invoke_result_t<Fn> call_guarded(stack& s, const Label& label, Fn&& fn) {
    std::optional<error> thrown;
    try {
        return std::forward<Fn>(fn)();
    } catch (const std::exception& e) {
        thrown.emplace(binding_error(e, label));
    }
    s.raise(*thrown);
}

} // namespace Rhp::script::detail
