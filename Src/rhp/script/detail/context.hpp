#pragma once

#include <memory>
#include <string>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/role.hpp>

struct lua_State;

namespace Rhp::script {

class effect;

namespace detail {

// What binding trampolines and patch layers need from the sandbox that owns a Lua state.
// Implemented by the sandbox; reached from a stack through the state's extra space.
class context {
public:
    // Role of the identity this state belongs to.
    [[nodiscard]] virtual role caller_role() const noexcept = 0;

    // Module whose code is running right now (the scratch module for exec).
    [[nodiscard]] virtual module_id current_module() const noexcept = 0;

    // Records a reversible (or irreversible) effect owned by the current module.
    virtual void record_effect(std::string label, std::unique_ptr<effect> e) = 0;

    // Runs `fn` with `owner` as the current module (used by patch handlers).
    [[nodiscard]] virtual module_id swap_current_module(module_id owner) noexcept = 0;

    // A patch handler of `owner` failed outside of a sandbox call; revert it on the next pump().
    virtual void report_fault(module_id owner, error err) noexcept = 0;

    // The main Lua state of the sandbox.
    [[nodiscard]] virtual lua_State* main_state() const noexcept = 0;

protected:
    context() = default;
    ~context() = default;
    context(const context&) = default;
    context& operator=(const context&) = default;
};

} // namespace detail
} // namespace Rhp::script
