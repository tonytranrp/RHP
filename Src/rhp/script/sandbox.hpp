#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/lib_builder.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/stubs.hpp>

#if !defined(RHP_ENABLE)
#define RHP_ENABLE 1
#endif

namespace Rhp::script {

using value_list = std::vector<value>;

enum class module_state : std::uint8_t {
    kActive,   // loaded, effects live
    kReverted, // loaded, every effect undone; inert until reloaded or unloaded
    kFaulted,  // a runtime error auto-reverted it; kept for inspection until reloaded or unloaded
    kLoading   // its first top level (or on_load) is suspended in rhp.wait / a time slice
};

[[nodiscard]] constexpr std::string_view to_string(module_state s) noexcept {
    switch (s) {
    case module_state::kLoading: return "loading";
    case module_state::kActive: return "active";
    case module_state::kReverted: return "reverted";
    case module_state::kFaulted: return "faulted";
    }
    return "unknown";
}

struct module_info {
    module_id id;
    std::string name;
    module_state state = module_state::kActive;
    bool scratch = false;    // the identity's exec() module
    std::size_t effects = 0; // live ledger entries
    std::size_t irreversible_effects = 0;
    std::optional<error> fault;            // why it is kFaulted
    revision_id revision{};                // current revision (1 = first load); 0 for the scratch module
    std::uint32_t source_hash = 0;         // CRC-32C of the current revision's source
    std::size_t revisions = 0;             // revisions kept for rollback, current included
    bool reloading = false;                // a new revision is loading next to the current one
    std::vector<module_id> dependencies{}; // modules this one require()s
};

// What a failing timer, frame callback, event handler or task does (rhp.* `on_error` option,
// sandbox_options::handler_errors). A memory stop always faults: the state's memory is shared.
enum class handler_error_policy : std::uint8_t {
    kReport, // report it and undo what that one call did; the handler and its module stay
    kRemove, // the same, and remove the handler
    kFault   // fault the module (revert it, kFaulted until reloaded), as any request failure
};

[[nodiscard]] constexpr std::string_view to_string(handler_error_policy p) noexcept {
    switch (p) {
    case handler_error_policy::kReport: return "report";
    case handler_error_policy::kRemove: return "remove";
    case handler_error_policy::kFault: return "fault";
    }
    return "unknown";
}

enum class handler_kind : std::uint8_t {
    kTimer, // rhp.timer / rhp.after / rhp.every
    kFrame, // rhp.every_frame / rhp.every_frames
    kEvent, // rhp.on / rhp.once
    kTask   // rhp.spawn
};

[[nodiscard]] constexpr std::string_view to_string(handler_kind k) noexcept {
    switch (k) {
    case handler_kind::kTimer: return "timer";
    case handler_kind::kFrame: return "frame";
    case handler_kind::kEvent: return "event";
    case handler_kind::kTask: return "task";
    }
    return "unknown";
}

// One failed handler call (sandbox_options::on_handler_error).
struct handler_failure {
    request_id request{};
    module_id module{};
    std::string module_name{};
    handler_kind kind = handler_kind::kTimer;
    std::string source{};   // the event name, or "timer" / "frame" / "task"
    std::uint64_t handler = 0; // the id the script holds (rhp.off), 0 if none
    handler_error_policy action = handler_error_policy::kReport; // what was done
    error err{};
};

// One rhp.publish as C++ sees it (sandbox::on_script_event). Views are valid during the call only.
struct script_event {
    std::string_view name{};
    module_id module{};             // the publishing module (0: the sandbox itself, e.g. rhp.handler_failed)
    std::string_view module_name{}; // empty when module is 0 or it was unloaded meanwhile
    std::span<const value> args{};
};

using script_event_fn = std::function<void(const script_event&)>;

// Counters of one sandbox (sandbox::stats, rhp.stats()).
struct sandbox_stats {
    std::uint64_t dropped_events = 0;   // queued events refused because limits.event_queue was full
    std::size_t queued_events = 0;      // waiting for the next pump()
    std::size_t schedule_entries = 0;   // timers and frame callbacks
    std::size_t subscriptions = 0;      // rhp.on / rhp.once handlers
    std::size_t tasks = 0;              // unfinished rhp.spawn tasks
    std::size_t waiting = 0;            // requests in rhp.wait_event or task:join()
    std::uint64_t handler_failures = 0; // handler calls that failed so far
};

// Tag for unload(mod, Rhp::script::force): unload even if other modules require this one.
struct force_t {
    explicit constexpr force_t() = default;
};
inline constexpr force_t force{};

// Script time for rhp.sleep and rhp.timer (limits always use std::chrono::steady_clock).
using clock_fn = std::function<std::chrono::steady_clock::time_point()>;

struct sandbox_options {
    // Role of the identity this sandbox runs for. Local C++ callers default to kPatch.
    role caller_role = role::kPatch;
    Rhp::limits limits{};
    // Every Lua allocation of this sandbox; nullptr = std::pmr::get_default_resource().
    std::pmr::memory_resource* memory = nullptr;
    // Receives each print() line (without the newline); empty = standard output.
    std::function<void(std::string_view)> output{};
    // Receives each print() line with the request and module that printed it (0 when none runs);
    // when set, `output` is not called.
    std::function<void(request_id, module_id, std::string_view)> on_output{};
    // Receives each rhp.emit(value) as it happens, with the request and module that emitted it.
    std::function<void(request_id, module_id, const value&)> on_emit{};
    // Receives the result of every request that suspended before finishing (see exec()).
    std::function<void(request_id, const result<value_list>&)> on_result{};
    // Script time; empty = std::chrono::steady_clock::now.
    clock_fn clock{};
    // Shown in errors and module listings.
    std::string identity = "local";
    // What a failing timer, frame callback, event handler or task does when it sets no on_error.
    handler_error_policy handler_errors = handler_error_policy::kReport;
    // Receives every failed handler call, on the sandbox's thread at the end of the operation,
    // pump() or game-code event fire it failed in (it may re-enter the sandbox); empty = one
    // "[handler failed] ..." line through on_output / output.
    std::function<void(const handler_failure&)> on_handler_error{};
};

namespace detail {
class sandbox_impl;
} // namespace detail

// One identity's script runtime: one lua_State, one _ENV per module, one undo ledger.
//
// Single-threaded: use it from one thread (the pump thread). The only exceptions are cancel(),
// which any thread may call, patch points, which any thread may hit (they run the C++ default off
// the owning thread), and Rhp::lua_event::fire, which queues for the next pump() off that thread.
//
// Every exec / load / call starts a request: a coroutine that runs to completion unless the
// script suspends itself (rhp.wait, rhp.next_frame, rhp.sleep) or limits.slice_us is set and its
// time slice runs out. A suspended request continues in pump(); the operation that started it
// returns early (exec / call with an empty list, load with the module kLoading) and the final
// result goes to sandbox_options::on_result.
//
//   Rhp::script::sandbox box;
//   box.install<game_lib>();
//   auto mod = box.load("low_grav", "game.gravity = -1.6");
//   box.revert(*mod);                        // gravity is back
//
// With RHP_ENABLE=0 every operation fails with errc::kDisabled and no Lua is linked.
class sandbox {
public:
    explicit sandbox(sandbox_options options = {});
    ~sandbox(); // reverts and unloads everything, then closes the state

    sandbox(const sandbox&) = delete;
    sandbox& operator=(const sandbox&) = delete;
    sandbox(sandbox&&) noexcept;
    sandbox& operator=(sandbox&&) noexcept;

    // Makes a lib visible to every module of this sandbox as a global (`game`).
    // Fails with kAlreadyLoaded if the name is taken.
    template <installable L>
    result<void> install() {
#if RHP_ENABLE
        return install_lib(L::name, &detail::install_lib_tree<L>, &::Rhp::script::stubs::generate<L>);
#else
        return fail(errc::kDisabled, "RHP is compiled out (RHP_ENABLE=0)", std::string{L::name});
#endif
    }

    // Runs source in the scratch module; effects are kept and owned by the scratch module.
    // On error only the effects of this run are reverted. Returns every value the chunk returned.
    result<value_list> exec(std::string_view source, std::string_view chunk_name = "exec");

    // Same, converting the first returned value (nil if none).
    template <from_value_convertible T>
    result<T> exec(std::string_view source, std::string_view chunk_name = "exec") {
        auto values = exec(source, chunk_name);
        if (!values) {
            return std::unexpected{std::move(values).error()};
        }
        return from_value<T>(values->empty() ? value{} : values->front());
    }

    // Compiles (text only) and runs a module chunk with its own _ENV, then calls M.on_load().
    // The chunk's returned table is the module's export table (its _ENV if it returns nothing).
    // Names are dotted lowercase. Loading a name that is already loaded reloads it (see reload).
    // A runtime error auto-reverts the module and leaves it kFaulted.
    result<module_id> load(std::string_view name, std::string_view source);

    // Transactional reload. The new revision runs next to the live one (its own _ENV), then
    // new.on_restore(old.on_save()) carries state over and the old revision is reverted. If any step
    // fails, the new revision's effects are reverted and the old one is untouched. Works on active,
    // reverted and faulted modules. Returns the new revision (0 if still loading, or deferred).
    result<revision_id> reload(module_id mod, std::string_view source);
    // Reloads the source of the revision `steps` before the current one (1 = the previous one).
    result<revision_id> rollback(module_id mod, std::size_t steps = 1);

    // Calls an exported function of an active module. A runtime error faults the module.
    result<value_list> call(module_id mod, std::string_view function, std::span<const value> args = {});

    template <to_value_convertible A0, to_value_convertible... A>
    result<value_list> call(module_id mod, std::string_view function, const A0& a0, const A&... rest) {
        const value args[] = {to_value(a0), to_value(rest)...};
        return call(mod, function, std::span<const value>{args});
    }

    // Undoes every effect of the module, newest first; the module stays loaded but kReverted.
    result<revert_report> revert(module_id mod);
    // M.on_unload() (errors ignored), revert, forget the module. Fails with kHasDependents while
    // other modules require it; with `force` they stay loaded and touching it raises kUnloaded.
    result<revert_report> unload(module_id mod);
    result<revert_report> unload(module_id mod, force_t);

    // Called from inside a running script (a C++ binding re-entering the sandbox), revert, unload,
    // reload, rollback, revert_to and revert_all are queued and applied when the outermost run
    // returns; they report `deferred` (reload / rollback return revision 0).

    // Global marks over this sandbox's ledger. revert_to undoes every effect recorded after the
    // mark (any module) and drops later checkpoints.
    result<void> checkpoint(std::string_view tag);
    result<revert_report> revert_to(std::string_view tag);

    // Panic button: unloads every module and reverts the scratch module.
    revert_report revert_all();

    [[nodiscard]] result<module_id> find(std::string_view name) const;
    [[nodiscard]] std::optional<module_info> status(module_id mod) const;
    [[nodiscard]] std::vector<module_info> list() const;
    [[nodiscard]] module_id scratch_module() const noexcept;

    // Stops the script running right now (sticky until it returns). Callable from any thread;
    // a no-op while nothing runs.
    void cancel() noexcept;
    // Stops one request, running or suspended (its whole coroutine). Callable from any thread.
    // Like any runtime error, it faults the owning module (a scratch request reverts its own effects).
    void cancel(request_id request) noexcept;

    // One frame: delivers queued events, fires due timers, resumes suspended requests whose wait
    // is over (within limits.slice_us when set), and applies faults and deferred operations.
    void pump();

    // The request the latest exec / load / call / reload started.
    [[nodiscard]] request_id last_request() const noexcept;
    // Requests suspended right now.
    [[nodiscard]] std::size_t suspended() const noexcept;
    // True while `request` has started and not finished (it is suspended or running).
    [[nodiscard]] bool pending(request_id request) const noexcept;
    // pump() calls so far (rhp.frame()).
    [[nodiscard]] std::uint64_t frame() const noexcept;

    [[nodiscard]] role caller_role() const noexcept;
    [[nodiscard]] std::size_t memory_used() const noexcept;
    [[nodiscard]] const ledger& effects() const noexcept;

    // Calls fn for every rhp.publish of `name` ("*": every name) this sandbox delivers, at the end of
    // the pump() that delivered it, until the returned subscription dies (it may outlive the
    // sandbox). Thread-safe to subscribe and unsubscribe; fn runs on the sandbox's thread and may
    // re-enter the sandbox. With RHP_ENABLE=0 it is never called.
    [[nodiscard]] Rhp::subscription on_script_event(std::string_view name, script_event_fn fn);

    [[nodiscard]] sandbox_stats stats() const noexcept;

    // LuaLS annotations for everything this identity can use: the rhp API and every installed lib,
    // filtered by caller_role().
    [[nodiscard]] std::string stubs() const;

private:
    using stub_fn = std::string (*)(role);

    result<void> install_lib(std::string_view name, c_function build, stub_fn describe);

    std::unique_ptr<detail::sandbox_impl> impl_;
};

} // namespace Rhp::script

template <>
struct std::formatter<Rhp::script::handler_error_policy> : std::formatter<std::string_view> {
    auto format(Rhp::script::handler_error_policy p, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::script::to_string(p), ctx);
    }
};

template <>
struct std::formatter<Rhp::script::handler_kind> : std::formatter<std::string_view> {
    auto format(Rhp::script::handler_kind k, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::script::to_string(k), ctx);
    }
};

template <>
struct std::formatter<Rhp::script::module_state> : std::formatter<std::string_view> {
    auto format(Rhp::script::module_state s, std::format_context& ctx) const {
        return std::formatter<std::string_view>::format(Rhp::script::to_string(s), ctx);
    }
};
