#pragma once

#include <cstdint>
#include <functional>
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

class context;

// What settling an orphaned asynchronous call did with its result.
enum class async_settled : std::uint8_t {
    kNothing, // no result yet, or a failure: nothing to take back
    kUndone,  // a success, taken back through the binding's undo<G>
    kDropped, // a success with no undo (a pure or irreversible binding): it stays
};

// A call of an asynchronous binding (Rhp::async<T>) whose request waits for its result. Made by
// the binding trampoline (lib_builder.hpp), kept by the sandbox while the request waits and, once
// the request is gone, until the result arrives (settle()). Owned on the sandbox's thread only:
// completing threads reach it through a weak_ptr in the inbox. Destroying one that holds an
// untaken success settles it (so no path loses a success).
class async_wait {
public:
    virtual ~async_wait() = default;
    async_wait(const async_wait&) = delete;
    async_wait& operator=(const async_wait&) = delete;

    [[nodiscard]] virtual bool ready() const = 0;
    // Calls `wake` once, on the completing thread; false (nothing armed) when the result is already there.
    [[nodiscard]] virtual bool arm(std::function<void()> wake) = 0;
    // Tells the producer nobody waits any more (Rhp::promise::stop_requested()).
    virtual void request_stop() noexcept = 0;
    // On the waiting request's thread: records the binding's effect and pushes its results, or
    // raises its error. Returns the number of results.
    virtual int finish(stack& s, context& ctx) = 0;
    // Nobody will read the result: stops reading atomically (a later complete() returns false) and
    // takes back a success that already arrived through the binding's undo<G>.
    virtual async_settled settle() noexcept = 0;

    request_id request{}; // the request waiting for it (set by the sandbox)
    bool detached = false;  // its request is gone

protected:
    async_wait() = default;
};

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

    // Asynchronous bindings. `L` is a request's own thread and may yield right now.
    [[nodiscard]] virtual bool can_suspend(lua_State* L) const noexcept = 0;
    // The running request waits for `op` (L must be able to suspend). False when `op` is already
    // ready: the binding finishes at once.
    [[nodiscard]] virtual bool await_async(lua_State* L, std::shared_ptr<async_wait> op) = 0;
    // After the request resumed: what it waited for, or nullptr when limits.async_ms ran out first.
    [[nodiscard]] virtual std::shared_ptr<async_wait> take_async(lua_State* L) = 0;

protected:
    context() = default;
    ~context() = default;
    context(const context&) = default;
    context& operator=(const context&) = default;
};

// Suspends the running request until the call it handed to context::await_async completes; the
// binding then returns what async_wait::finish pushes (puc_lua/stack.cpp). Only from a binding's C
// function, as its last action, holding no C++ object with a destructor (the yield may jump).
[[noreturn]] void yield_async(lua_State* L);

} // namespace Rhp::script::detail
