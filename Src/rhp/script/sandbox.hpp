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

#include <rhp/build_config.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/limits.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/scopes.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/api.hpp>
#include <rhp/script/debug.hpp>
#include <rhp/script/detail/caps.hpp>
#include <rhp/script/detail/lib_traits.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/script/stubs.hpp>
#include <rhp/script/testing.hpp>
#include <rhp/script/tunables.hpp>

#if RHP_ENABLE
#include <rhp/script/detail/lib_builder.hpp> // install<L>: the lib's trampolines
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
    std::string source{};                                        // the event name, or "timer" / "frame" / "task"
    std::uint64_t handler = 0;                                   // the id the script holds (rhp.off), 0 if none
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
    std::size_t async_waiting = 0;      // requests waiting for an asynchronous binding (Rhp::async<T>)
    // Asynchronous successes that arrived after their request was gone (cancelled, unloaded, timed
    // out): taken back through the binding's undo<G>, or (a binding with no undo: pure or
    // irreversible) dropped, the effect staying.
    std::uint64_t async_compensated = 0;
    std::uint64_t async_dropped = 0;
    std::size_t paused = 0; // requests the debugger paused
    // Modules (and reloads) given trusted bytecode (sandbox::load with a trusted_bytecode): loaded
    // from it, or refused by Lua (another Lua build, truncated, compiled under another name) and
    // parsed from their source instead.
    std::uint64_t bytecode_loaded = 0;
    std::uint64_t bytecode_rejected = 0;
};

// Lua bytecode a sandbox may load in place of parsing a module's source (sandbox::load / reload):
// whoever makes one vouches that this program compiled it (sandbox::compile_module) and that nothing
// could change it since. Lua doesn't verify bytecode: a forged chunk escapes the sandbox. Never
// wrap bytecode a client sent, or read from somewhere others can write without authenticating it
// (the release store MACs its cache). The view must stay valid during the call.
class trusted_bytecode {
public:
    constexpr explicit trusted_bytecode(std::string_view bytes) noexcept : bytes_(bytes) {}
    [[nodiscard]] constexpr std::string_view bytes() const noexcept { return bytes_; }

private:
    std::string_view bytes_;
};

// What Lua bytecode depends on in this build: Lua's release number, its bytecode header (format;
// sizes of int, Instruction, lua_Integer, lua_Number) and the dump of a probe chunk, so a change to
// the compiler or to the dump format shows. Bytecode made by a build whose bytecode_build() differs
// must not be loaded. Computed once; empty with RHP_ENABLE=0 (no Lua) or if it couldn't be made.
[[nodiscard]] std::string_view bytecode_build();

namespace detail {
struct async_inbox;
class async_wait;
class sandbox_impl;
} // namespace detail

// Asynchronous calls a sandbox still waited for when it was about to go (sandbox::release_async):
// a success that arrives later is still taken back through its binding's undo<G> when pump() runs.
// Destroying it gives up on the rest (their complete() returns false: the producers clean up).
// Pump it on the thread that pumped the sandbox.
class async_leftovers {
public:
    async_leftovers();
    ~async_leftovers();
    async_leftovers(async_leftovers&&) noexcept;
    async_leftovers& operator=(async_leftovers&&) noexcept;
    async_leftovers(const async_leftovers&) = delete;
    async_leftovers& operator=(const async_leftovers&) = delete;

    // Settles the calls whose results arrived; returns how many are still pending.
    std::size_t pump();
    [[nodiscard]] std::size_t pending() const noexcept { return pending_.size(); }
    [[nodiscard]] bool empty() const noexcept { return pending_.empty(); }
    [[nodiscard]] std::uint64_t undone() const noexcept { return undone_; }
    [[nodiscard]] std::uint64_t dropped() const noexcept { return dropped_; }

private:
    friend class detail::sandbox_impl;
    void close() noexcept;

    std::shared_ptr<detail::async_inbox> inbox_;
    std::vector<std::shared_ptr<detail::async_wait>> pending_;
    std::uint64_t undone_ = 0;
    std::uint64_t dropped_ = 0;
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
    // What the identity may reach (decision AL13; a host passes its keyring entry's scopes). A lib
    // `lib:` patterns don't allow isn't installed (install<L> succeeds, nothing is there: not in
    // rhp.api(), stubs or tunables; a sub-lib a deny pattern names is left out of its lib); a
    // binding whose Rhp::cap<> they deny raises kForbidden; rhp.patch refuses a point `patch:`
    // doesn't allow, and rhp.on / once / wait_event an event `event:` doesn't. Default: everything.
    scope_set scopes{};
    // An admin sandbox opens Lua's whole standard library (io, os, package, debug, collectgarbage,
    // string.dump, dofile, loadfile, __gc finalizers) while this is true - in a dev build only
    // (RHP_HARDENING=dev: the others leave that code out). false, or another build: admin gets
    // patch's libraries. A host sets it from its hardening level (kDev only).
    bool admin_stdlib = true;
    Rhp::limits limits{};
    // Every Lua allocation of this sandbox; nullptr = the C heap (malloc / realloc / free, as Lua's own
    // allocator: blocks grow in place). Either way limits.memory is enforced.
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
    // Lua's garbage collector mode from the start (set_gc_mode switches it later).
    gc_mode gc = gc_mode::kIncremental;
};

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
        return install_lib(L::name, &detail::install_lib_tree<L>, &::Rhp::script::stubs::generate<L>, &detail::collect_tunables<L>,
                           &::Rhp::script::api::describe<L>, detail::cap_refs_v<L>);
#else
        // Refused (kDisabled), but the lib is still described by api() (api::describe needs no Lua).
        return install_lib(L::name, nullptr, nullptr, nullptr, &::Rhp::script::api::describe<L>, {});
#endif
    }

    // Narrows what the next exec / load / reload run (until narrow({}) clears it) to these scopes on
    // top of sandbox_options::scopes (decision AL13; a host passes an operator certificate's): the
    // code checks against both (cap:, patch:, event:) for as long as it runs, the handlers, patches
    // and tasks of a narrowed module revision included; a rollback runs as the revision it goes back
    // to was narrowed. Libs aren't taken away for one script: a narrowed operation whose scopes deny a
    // lib or sub-lib the sandbox has is refused (kForbidden). A narrowed exec may not leave lasting
    // handlers or patches (kForbidden from rhp.after / every / on / spawn / patch ...): load a module.
    void narrow(scope_set scopes);

    // Runs source in the scratch module; effects are kept and owned by the scratch module.
    // On error only the effects of this run are reverted. Returns every value the chunk returned.
    result<value_list> exec(std::string_view source, std::string_view chunk_name = "exec");

    // exec for trusted sources run in many sandboxes (the test framework): each distinct (chunk
    // name, source) is compiled once per process and later sandboxes load its bytecode. Never use it
    // for sources a client sent.
    result<value_list> exec_cached(std::string_view source, std::string_view chunk_name);

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

    // ---- compiled chunks ----------------------------------------------------------------------
    // Compiles `source` (text only) as module `name` is compiled by load() and returns its bytecode
    // (lua_dump, debug information kept: tracebacks, the debugger and coverage see the same lines).
    // Runs nothing. kCompile on a syntax error, kInvalidArgument for a name load() refuses.
    result<std::string> compile_module(std::string_view name, std::string_view source);
    // load / reload taking `code`, bytecode compile_module made of this name and source, instead of
    // parsing `source` (which stays the module's source: rollback, module_info::source_hash).
    // Bytecode Lua refuses (another Lua build, truncated, made for another name) is set aside and
    // the source parsed instead (stats().bytecode_rejected). See trusted_bytecode: never pass
    // bytecode that came from the wire. A reload deferred while a script runs parses the source.
    result<module_id> load(std::string_view name, std::string_view source, trusted_bytecode code);
    result<revision_id> reload(module_id mod, std::string_view source, trusted_bytecode code);

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
    // Puts the library tables every module shares (string, table, math, utf8, coroutine, os, rhp,
    // rhp.buffer, the string metatable) back as they were when the sandbox was made, as revert_all
    // does after unloading everything: for an owner that reverts an identity but keeps some of its
    // modules (a host's pinned ones), which must not rely on builtins they changed.
    void restore_builtins();

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

    // Gives Lua's garbage collector time the frame has to spare (after pump(), when the frame is
    // ahead of its deadline), so less of its work lands inside the next frame's scripts. Incremental
    // mode: collector steps until `budget` is spent or the cycle ends (a step can overrun the budget
    // by its own length). Generational mode: one step, a minor collection or one increment of a major
    // one, whatever the budget (0 does nothing). True when a collection cycle ended. Finalizers
    // (__gc) may run. Pump thread.
    result<bool> collect_idle(std::chrono::microseconds budget);

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

    // Pump thread.
    [[nodiscard]] sandbox_stats stats() const;

    // Hands over the asynchronous calls whose requests are gone but whose results haven't arrived,
    // before the sandbox is destroyed (or reverted) by an owner that outlives it: a host keeps them
    // after an identity's sandbox closes. Without this, destroying the sandbox gives up on them.
    [[nodiscard]] async_leftovers release_async();

    // LuaLS annotations for everything this identity can use: the rhp API and every installed lib,
    // filtered by caller_role().
    [[nodiscard]] std::string stubs() const;

    // Everything this identity's scripts can use, as a value tree (rhp.api() in Lua): {libs = {<api::describe>...},
    // events = {{name, arity}...}, points = {{id, arity, callable}...}} (events and patch points: every one this
    // program registered), filtered by caller_role().
    [[nodiscard]] value api() const;

    // Every variable the installed libs expose (::var and ::ro) with its value now: what tools tune.
    // `prefix` keeps one lib or one path ("game", "game.speed"). Pump thread.
    [[nodiscard]] result<std::vector<tunable_info>> tunables(std::string_view prefix = {});

    // Writes a ::var as a script would (`game.speed = v`): needs kPatch, honours Rhp::range<>, and is
    // journaled in the scratch module like an exec() (revert_all or the identity's last session
    // ending undo it). kNotFound for an unknown path, kForbidden for a ::ro.
    result<void> tune(std::string_view path, const value& v);

    // ---- debugger (see debug.hpp) ---------------------------------------------------------------
    // Pump thread. A paused request is published as the script event "rhp.debug" ({kind = "paused",
    // request, reason, source, line, label}); a breakpoint it can't pause at as {kind = "hit", ...}.

    // Replaces the breakpoints of one source (a module name, or an exec chunk name); returns the
    // lines kept (sorted, unique, above 0). An empty list clears that source.
    result<std::vector<std::uint32_t>> set_breakpoints(std::string_view source, std::span<const std::uint32_t> lines);
    // The next line any request runs (that can pause) pauses, reason "pause".
    void debug_pause();
    // Clears every breakpoint, step and pause, and resumes every paused request.
    void debug_reset();
    [[nodiscard]] std::vector<debug_stop> paused() const;
    // Resumes a paused request (at the next pump()), running on or stepping.
    result<void> debug_resume(request_id request, step_mode mode = step_mode::kContinue);
    result<std::vector<debug_frame>> debug_stack(request_id request);
    // The variables of a paused request's frame (0: innermost). `path` descends into tables: the
    // variable's name, then field names ("[1]" for an integer key).
    result<std::vector<debug_variable>> debug_variables(request_id request, std::uint32_t frame, debug_scope scope,
                                                        std::span<const std::string> path = {});
    // A dotted path ("player.pos.x", "list[2]") looked up in the frame's locals, upvalues, module
    // globals, then libs. Runs no Lua: no calls, no metamethods.
    result<debug_variable> debug_evaluate(request_id request, std::uint32_t frame, std::string_view expression);

    // ---- profiler (see debug.hpp) ---------------------------------------------------------------
    // Pump thread. Starts sampling (kAlreadyLoaded while it runs).
    result<void> start_profile(profile_options options = {});
    // What was sampled so far (running or not).
    [[nodiscard]] profile_report profile() const;
    // Stops sampling and returns the report (an empty one if it wasn't running).
    profile_report stop_profile();

    // ---- testing (testing.hpp) --------------------------------------------------------------------
    // Pump thread. What test runners (Rhp::test) measure and drive; every one is harmless in a live
    // program, but they cost while on.

    // From now on count VM instructions exactly and time the Lua that runs (the count hook is armed
    // on every run, like the profiler's). Allocation counters always run.
    void start_metering();
    void stop_metering();
    // The counters now (it folds in the instructions threads ran since their last hook tick).
    [[nodiscard]] run_meter meter();
    // The peak starts over from what is in use now.
    void reset_peak() noexcept;
    // Full garbage collections: two by default (objects with finalizers go in the second); the test
    // runner takes one around each test.
    result<void> collect_garbage(int cycles = 2);
    result<void> set_gc_mode(gc_mode mode);
    // Records which lines run: every chunk compiled from now on is known with all its executable
    // lines; lines of code compiled before (or by load()) are reported as `extra`.
    result<void> start_coverage();
    [[nodiscard]] coverage_report coverage() const;
    coverage_report stop_coverage();
    // Installs `__rhp_test` (the bridge the Lua test framework uses) in the scratch module's
    // environment, and os.time / os.clock on the script clock when asked. Once per sandbox.
    result<void> enable_testing(testing_options options = {});
    // The earliest script time a timer or a sleeping request is due; nullopt when none waits for time.
    [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> next_due() const;
    // Calls a patch point by id with values, as C++ code would (overrides included).
    result<value_list> call_point(std::string_view id, std::span<const value> args);
    // Fires a C++ event by name with values, as its Rhp::lua_event::fire would.
    result<void> fire_event(std::string_view name, std::span<const value> args);

private:
    using stub_fn = std::string (*)(role);
    using api_fn = value (*)(role);

    result<void> install_lib(std::string_view name, c_function build, stub_fn describe, detail::tunables_fn collect, api_fn api,
                             std::span<const detail::cap_ref> caps);

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
