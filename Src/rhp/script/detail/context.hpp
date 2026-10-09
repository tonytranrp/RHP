#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

// What binding trampolines, patch layers and event deliveries need from the sandbox that owns a
// Lua state. Implemented by the sandbox; reached from a stack through the state's extra space.
class context {
public:
    // Role of the identity this state belongs to.
    [[nodiscard]] virtual role caller_role() const noexcept = 0;

    // Module (revision, request) whose code is running right now; the scratch module for exec.
    [[nodiscard]] virtual effect_owner current_owner() const noexcept = 0;

    // Records a reversible (or irreversible) effect owned by the running code. Returns its sequence.
    virtual std::uint64_t record_effect(std::string label, std::unique_ptr<effect> e) = 0;

    // Runs fn (protected, on the main state, `data` as its argument) as `owner`'s code. Inside a
    // running script it is part of that run; triggered by game code it is a small run of its own,
    // so cancel and every limit apply to it.
    virtual result<void> run_handler(const effect_owner& owner, c_function fn, void* data) = 0;

    // A handler of `owner` failed outside of a sandbox operation: fault it at the next operation or pump().
    virtual void report_fault(const effect_owner& owner, error err) noexcept = 0;

    // The main Lua state of the sandbox.
    [[nodiscard]] virtual lua_State* main_state() const noexcept = 0;

protected:
    context() = default;
    ~context() = default;
    context(const context&) = default;
    context& operator=(const context&) = default;
};

} // namespace Rhp::script::detail
