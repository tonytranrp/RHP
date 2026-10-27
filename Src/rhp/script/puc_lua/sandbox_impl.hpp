#pragma once

// Private to Src/rhp/script/puc_lua: the sandbox behind Rhp::script::sandbox. Deliberately free of
// lua.h (the .cpp files that include this one include lua.h themselves).

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <memory_resource>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/listener_table.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/script/debug.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/puc_lua/small_alloc.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stack.hpp>

struct lua_Debug;

namespace Rhp::script::detail {

using steady = std::chrono::steady_clock;

inline constexpr int kNoRef = -2; // LUA_NOREF

// Finished requests whose map node, record and coroutine wait for reuse: enough for a frame's worth
// of handler calls without holding on to a burst.
inline constexpr std::size_t kSpareRequests = 64;
// sandbox::call's interned function names (call_keys_).
inline constexpr std::size_t kCallKeys = 32;

class sandbox_impl;

// The sandbox that owns a Lua state (any of its threads).
[[nodiscard]] sandbox_impl& impl_of(lua_State* L) noexcept;

// Converts the Lua error object on top of the stack (popped) into an Rhp::error. `status` is the
// lua_pcall / lua_resume status. Recovers the structured error raised by stack::raise.
[[nodiscard]] error take_lua_error(lua_State* L, int status);

// Message handler for lua_pcall: stores a traceback in the sandbox and returns the error unchanged.
int traceback_handler(lua_State* L);

// Runs fn() inside lua_pcall (stack::run_protected), so every Lua API call it makes is protected: an
// error (an allocation that fails under a memory limit) becomes an error result instead of a panic.
template <class F>
result<void> protect(lua_State* L, F&& fn) {
    struct holder {
        std::remove_reference_t<F>* fn;
    } h{&fn};
    return stack{L}.run_protected(
        [](lua_State* inner) -> int {
            (*static_cast<holder*>(stack{inner}.to_light_userdata(1))->fn)();
            return 0;
        },
        &h);
}

// lua_dump's writer into the std::string `out` points to (modules.cpp).
int dump_writer(lua_State* L, const void* p, std::size_t size, void* out);

// Arguments of the rhp builtins: each raises (naming `where`) when the argument doesn't fit.
double checked_ms(lua_State* L, int index, std::string_view where);        // milliseconds >= 0
void check_function(lua_State* L, int index, std::string_view where);      // a function
std::uint64_t checked_id(lua_State* L, int index, std::string_view where); // an id the script holds (> 0)

steady::duration milliseconds(double ms);
[[nodiscard]] inline double milliseconds_of(steady::duration d) noexcept {
    return std::chrono::duration<double, std::milli>{d}.count();
}

// The '@' (a module) or '=' (an exec, the loader) in front of a chunk name RHP gives; a chunk a
// script load()s without a name has its source text there instead.
[[nodiscard]] constexpr bool has_chunk_marker(std::string_view source) noexcept {
    return !source.empty() && (source.front() == '@' || source.front() == '=');
}
// "@game.combat" -> "game.combat"; a source without a marker as it is.
[[nodiscard]] constexpr std::string_view without_chunk_marker(std::string_view source) noexcept {
    return has_chunk_marker(source) ? source.substr(1) : source;
}

// Nil, booleans and numbers cross between C++ and Lua without an allocation (stack.cpp).
// Pushes a scalar as stack::push_value does (no stack check: the caller made room).
void push_scalar(lua_State* L, const value& v) noexcept;
// Appends what stack::to_value makes of the scalar at `index`; false (nothing appended) for anything else.
bool append_scalar(value_list& out, lua_State* L, int index);

// Stops a run for good once a limit is hit: re-raised at every hook tick, so pcall can't swallow it.
enum class sticky_stop : std::uint8_t {
    kNone,
    kCancelled,
    kBudget,
    kMemory,
    kWall
};

// Limit accounting of one request (summed over all its resumes) or of one handler call.
struct run_budget {
    std::uint64_t instructions = 0;
    steady::duration active{};
    sticky_stop sticky = sticky_stop::kNone;
};

// One revision of a module: its _ENV, its exports and what it require()s.
struct module_instance {
    revision_id revision{};
    int env_ref = kNoRef;
    int exports_ref = kNoRef;
    std::set<module_id> dependencies{};
};

struct revision_source {
    revision_id revision;
    std::string source;
    std::uint32_t hash = 0;
};

struct module_record {
    module_id id;
    std::string name;
    module_state state = module_state::kActive;
    bool scratch = false;
    module_instance live;
    std::optional<module_instance> pending;        // a reload in flight
    std::optional<revision_source> pending_source; // its source, kept once it swaps in
    std::deque<revision_source> history;           // oldest first; back() is the live revision
    std::uint32_t revisions_made = 0;
    std::optional<error> fault;
};

// The _ENV of a module's code of `revision`: the reload in flight's when it is that revision, else
// the live one's.
[[nodiscard]] inline int env_ref_of(const module_record& mod, revision_id revision) noexcept {
    return mod.pending && mod.pending->revision == revision ? mod.pending->env_ref : mod.live.env_ref;
}

enum class request_kind : std::uint8_t {
    kExec,
    kLoad, // a module's top level + on_load, for its first load or a reload
    kCall,
    kTimer, // rhp.timer / rhp.after / rhp.every
    kEvent, // rhp.on / rhp.once
    kFrame, // rhp.every_frame / rhp.every_frames
    kTask   // rhp.spawn
};

// Requests that run a script's handler: a failure follows the handler error policy, not the fault policy.
[[nodiscard]] constexpr bool is_handler(request_kind k) noexcept {
    return k == request_kind::kTimer || k == request_kind::kEvent || k == request_kind::kFrame || k == request_kind::kTask;
}

// What a suspended request waits for besides a frame or a time.
enum class wait_kind : std::uint8_t {
    kNone,
    kEvent, // rhp.wait_event: resumed by a delivery (woken) or its timeout (wake_time)
    kTask,  // task:join(): resumed when the task ends (woken)
    kAsync, // an asynchronous binding: resumed when its result arrives (woken) or limits.async_ms (wake_time)
    kDebug  // paused by the debugger: resumed by debug_resume (woken) or debug_reset
};

// Everything a request record holds but its pooled strings: request_record::reset assigns it whole.
struct request_state {
    request_id id;
    request_kind kind = request_kind::kExec;
    effect_owner owner; // owner.request == id
    lua_State* thread = nullptr;
    int thread_ref = kNoRef;
    run_budget budget;
    bool running = false;
    bool listed = false;         // in requests_ (it suspended, or it's a task); while it runs, in unlisted_
    bool checked = false;        // armed for cancels and limits when it started (start_request; rearm_all keeps it)
    bool suspended_once = false; // its result goes to on_result
    std::uint64_t wake_frame = 0;
    std::optional<steady::time_point> wake_time; // script clock
    int start_args = -1;                         // >= 0: not started yet; the first resume passes this many arguments (tasks)
    bool woken = false;                          // a delivery or a joined task's end: resume at the next resume pass
    wait_kind waiting = wait_kind::kNone;
    std::uint64_t wait_task = 0;         // kTask: the task joined
    int resume_ref = kNoRef;             // kEvent: the delivered arguments, packed {n = count, ...}
    std::shared_ptr<async_wait> async{}; // kAsync: the call it waits for
    // Handlers: what started it, for the overlap guard, rhp.off and failure reports.
    std::uint64_t schedule_key = 0;
    std::uint64_t task_key = 0;
    std::uint64_t handler_seq = 0;
    handler_error_policy policy = handler_error_policy::kReport;
    std::optional<error> start_error{}; // set up but can't start (its arguments didn't fit): fails at its first step
};

// One script request: a coroutine the scheduler runs, suspends and resumes.
struct request_record : request_state {
    std::string label;        // error location when the script gives none ("combat.boost", "timer")
    std::string wait_event{}; // kEvent: the event waited for
    std::string source{};     // the event name, or "timer" / "frame" / "task"

    // Back to a new record for the next request (records are pooled): every field to its default,
    // the strings keeping their buffers.
    void reset() noexcept {
        static_cast<request_state&>(*this) = request_state{};
        label.clear();
        wait_event.clear();
        source.clear();
    }
};
// A field added to request_record instead of request_state would survive reset().
static_assert(sizeof(request_record) == sizeof(request_state) + 3 * sizeof(std::string), "request_record's fields belong in request_state");

enum class schedule_kind : std::uint8_t {
    kTimer, // script clock
    kFrames // pump() count
};

// A timer or a frame callback: one call per due time, each as its own request.
struct schedule_entry {
    effect_owner owner{};
    int fn_ref = kNoRef;
    schedule_kind kind = schedule_kind::kTimer;
    bool repeating = false;
    bool paused = false;
    steady::time_point due{};             // timers: next call
    steady::duration interval{};          // timers: period (or the one delay)
    steady::duration remaining{};         // timers: left when paused
    std::uint64_t next_frame = 0;         // frame callbacks: next call once frame_ >= next_frame
    std::uint64_t every = 1;              // frame callbacks: pumps between calls
    std::uint64_t remaining_frames = 0;   // frame callbacks: left when paused
    std::uint32_t runs = 0;               // calls started
    std::optional<std::uint32_t> times{}; // calls before it removes itself
    handler_error_policy policy = handler_error_policy::kReport;
    request_id active{};   // its latest call (no new call while that one is suspended)
    std::uint64_t seq = 0; // its ledger entry (the id the script holds)
};

struct subscription {
    std::uint64_t key = 0;
    effect_owner owner;
    int fn_ref = kNoRef;
    std::uint64_t seq = 0; // its ledger entry (the id rhp.off takes)
    std::int64_t priority = 0;
    bool once = false;
    bool paused = false;
    handler_error_policy policy = handler_error_policy::kReport;
};

enum class task_state : std::uint8_t {
    kSuspended, // not started yet, or waiting
    kRunning,
    kDone,
    kFailed,
    kCancelled
};

[[nodiscard]] constexpr std::string_view to_string(task_state s) noexcept {
    switch (s) {
    case task_state::kSuspended: return "suspended";
    case task_state::kRunning: return "running";
    case task_state::kDone: return "done";
    case task_state::kFailed: return "failed";
    case task_state::kCancelled: return "cancelled";
    }
    return "unknown";
}

// An rhp.spawn task: one request of its own, owned by the spawning module.
struct task_record {
    std::uint64_t key = 0;
    std::uint64_t seq = 0; // its ledger entry (the id the script holds)
    effect_owner owner{};  // spawning module and revision
    request_id request{};  // while it runs or waits
    bool finished = false;
    task_state state = task_state::kSuspended; // meaningful once finished
    int results_ref = kNoRef;                  // kDone: the results, packed {n = count, ...}
    std::optional<error> failure{};
    std::vector<request_id> joiners{};
    std::uint32_t handles = 0;     // live Lua handles (rhp.task userdata)
    bool cancel_requested = false; // its end is a cancellation, not a failure
};

// An rhp.publish waiting for the next pump(), or for the C++ listeners at the end of one.
struct queued_script_event {
    std::string name;
    module_id publisher{};
    value_list args{};
};

// A failed handler call waiting for its policy.
struct pending_failure {
    effect_owner owner{};
    request_kind kind = request_kind::kTimer;
    std::string source{};
    std::uint64_t handler_seq = 0;
    handler_error_policy policy = handler_error_policy::kReport;
    error err{};
};

// C++ callbacks for script events (sandbox::on_script_event), by name ("*": every name). Shared so
// subscriptions may outlive the sandbox; subscribe and unsubscribe from any thread (an unsubscribe
// waits for a call of that callback on the sandbox's thread to finish).
class script_listener_table final : public subscribable {
public:
    std::uint64_t add(std::string name, script_event_fn fn) { return table_.add(std::move(name), std::move(fn)); }
    void unsubscribe(std::uint64_t id) noexcept override { (void)table_.remove(id); }
    [[nodiscard]] bool empty() const noexcept { return table_.empty(); }
    // Calls the callbacks for `name` ("*" entries included).
    void dispatch(std::string_view name, const script_event& e) const {
        table_.dispatch([name](const std::string& n) { return n == name || n == "*"; }, e);
    }

private:
    core::listener_table<std::string, script_event_fn> table_;
};

// Results of asynchronous bindings that arrived (on any thread) for the next pump(). Shared with
// the wakers the calls hold, so a call completing after the sandbox is gone finds it closed.
struct async_inbox {
    std::mutex mutex;
    bool closed = false;
    bool overflow = false; // an arrival couldn't be recorded (out of memory): look at every call
    std::vector<std::weak_ptr<async_wait>> arrived;
    std::atomic<bool> any{false};

    // Any thread (the waker); never throws, so complete() never does.
    void post(const std::weak_ptr<async_wait>& op) noexcept;
    // The pump thread: what arrived since the last take.
    [[nodiscard]] std::vector<std::weak_ptr<async_wait>> take(bool& overflowed);
};

// Options from the table a script passes last (rhp.every(ms, fn, {times = 3})).
struct handler_opts {
    std::optional<std::uint32_t> times{};
    std::int64_t priority = 0;
    std::optional<handler_error_policy> on_error{};
};

struct profiler_state;
struct debugger_state;
struct coverage_state;

class sandbox_impl final : public context, public event_listener {
public:
    explicit sandbox_impl(sandbox_options options);
    ~sandbox_impl();

    sandbox_impl(const sandbox_impl&) = delete;
    sandbox_impl& operator=(const sandbox_impl&) = delete;

    // ---- context ----------------------------------------------------------------------------
    [[nodiscard]] role caller_role() const noexcept override { return options_.caller_role; }
    [[nodiscard]] effect_owner current_owner() const noexcept override { return current_; }
    std::uint64_t record_effect(std::string label, std::unique_ptr<effect> e) override;
    result<void> run_handler(const effect_owner& owner, c_function fn, void* data) override;
    void report_fault(const effect_owner& owner, error err) noexcept override;
    [[nodiscard]] lua_State* main_state() const noexcept override { return state_; }
    [[nodiscard]] bool can_suspend(lua_State* L) const noexcept override;
    [[nodiscard]] bool await_async(lua_State* L, std::shared_ptr<async_wait> op) override;
    [[nodiscard]] std::shared_ptr<async_wait> take_async(lua_State* L) override;

    // ---- event_listener ------------------------------------------------------------------------
    [[nodiscard]] std::thread::id listener_thread() const noexcept override { return thread_.load(std::memory_order_acquire); }
    void deliver(std::string_view event, const event_args& args) override;
    void enqueue(std::string_view event, const event_args& args) noexcept override;

    // ---- sandbox operations ------------------------------------------------------------------
    result<void> install_lib(std::string_view name, c_function build, std::string (*describe)(role), tunables_fn collect, value (*api)(role));
    [[nodiscard]] value api() const;
    result<value_list> exec(std::string_view source, std::string_view chunk_name, bool cached = false);
    result<std::vector<tunable_info>> tunables(std::string_view prefix);
    result<void> tune(std::string_view path, const value& v);
    // Every variable of the installed libs, without values (rhp.tunables reads them).
    [[nodiscard]] const std::vector<tunable_info>& tunable_list() const noexcept { return tunables_; }

    // ---- debugger (debug.cpp) and profiler (profile.cpp) ------------------------------------------
    result<std::vector<std::uint32_t>> set_breakpoints(std::string_view source, std::span<const std::uint32_t> lines);
    void debug_pause();
    void debug_reset();
    [[nodiscard]] std::vector<debug_stop> paused() const;
    result<void> debug_resume(request_id id, step_mode mode);
    result<std::vector<debug_frame>> debug_stack(request_id id);
    result<std::vector<debug_variable>> debug_variables(request_id id, std::uint32_t frame, debug_scope scope, std::span<const std::string> path);
    result<debug_variable> debug_evaluate(request_id id, std::uint32_t frame, std::string_view expression);
    result<void> start_profile(const profile_options& options);
    [[nodiscard]] profile_report profile() const;
    profile_report stop_profile();

    // ---- testing (testing.cpp) ----------------------------------------------------------------
    void start_metering();
    void stop_metering();
    [[nodiscard]] run_meter meter();
    void reset_peak() noexcept { peak_ = memory_used_; }
    void raise_peak(std::size_t at_least) noexcept { peak_ = std::max(peak_, at_least); }
    result<void> collect_garbage(int cycles);
    result<void> set_gc_mode(gc_mode mode);
    result<void> start_coverage();
    [[nodiscard]] coverage_report coverage() const;
    coverage_report stop_coverage();
    result<void> enable_testing(testing_options options);
    [[nodiscard]] std::optional<steady::time_point> next_due() const;
    [[nodiscard]] std::vector<steady::time_point> due_times() const; // every timer and sleeping request, sorted
    result<value_list> call_point(std::string_view id, std::span<const value> args);
    result<void> fire_event(std::string_view name, std::span<const value> args);
    [[nodiscard]] bool metering() const noexcept { return metering_; }
    // Folds the instructions L ran since its last hook tick into the meter (and into the budgets of
    // the runs on the stack, so a limit still sees them). Cheap; a no-op unless metering.
    void credit_hook_progress(lua_State* L) noexcept;
    // The test bridge's services (testing.cpp).
    [[nodiscard]] const testing_options& test_options() const noexcept { return testing_; }
    [[nodiscard]] steady::duration script_elapsed() const { return script_now() - testing_started_; }
    // Swaps `key` of a lib proxy's members, a module's exports or a plain table for the value on
    // top of L's stack (popped), journaled: undoing the effect puts the original back. Pushes the
    // original. Raises for anything else.
    void swap_member(lua_State* L, int target, int key);
    // Swaps a lib variable's getter and setter (`getter` / `setter` stack slots), journaled. Pushes
    // the original getter and setter.
    void swap_variable(lua_State* L, int target, int key, int getter, int setter);
    // The module behind a require() proxy at `index` (nullptr if it isn't one, or the module is gone).
    [[nodiscard]] const module_record* module_of_proxy(lua_State* L, int index) const noexcept;
    // `bytecode`: trusted bytecode of the source (sandbox::load with a trusted_bytecode), or empty.
    result<module_id> load(std::string_view name, std::string_view source, std::string_view bytecode = {});
    result<revision_id> reload(module_id mod, std::string_view source, std::string_view bytecode = {});
    result<std::string> compile_module(std::string_view name, std::string_view source);
    [[nodiscard]] std::uint64_t bytecode_loaded() const noexcept { return bytecode_loaded_; }
    [[nodiscard]] std::uint64_t bytecode_rejected() const noexcept { return bytecode_rejected_; }
    result<revision_id> rollback(module_id mod, std::size_t steps);
    result<value_list> call(module_id mod, std::string_view function, std::span<const value> args);
    result<revert_report> revert(module_id mod);
    result<revert_report> unload(module_id mod, bool forced);
    result<void> checkpoint(std::string_view tag);
    result<revert_report> revert_to(std::string_view tag);
    revert_report revert_all();
    [[nodiscard]] result<module_id> find(std::string_view name) const;
    [[nodiscard]] std::optional<module_info> status(module_id mod) const;
    [[nodiscard]] std::vector<module_info> list() const;
    [[nodiscard]] module_id scratch_module() const noexcept { return scratch_; }
    void cancel() noexcept;
    void cancel(request_id request) noexcept;
    void pump();
    result<bool> collect_idle(std::chrono::microseconds budget);
    // set_gc_mode and the test bridge's gc_mode() report the mode they switched to.
    void note_gc_mode(gc_mode mode) noexcept { gc_mode_ = mode; }
    [[nodiscard]] request_id last_request() const noexcept { return last_request_; }
    [[nodiscard]] std::size_t suspended() const noexcept;
    // A request that is suspended or running (one that never suspended isn't in requests_): sandbox::pending.
    [[nodiscard]] bool live(request_id request) const noexcept;
    [[nodiscard]] std::uint64_t frame() const noexcept { return frame_; }
    [[nodiscard]] std::size_t memory_used() const noexcept { return memory_used_; }
    [[nodiscard]] const ledger& effects() const noexcept { return ledger_; }
    [[nodiscard]] std::string stubs() const;
    [[nodiscard]] Rhp::subscription on_script_event(std::string_view name, script_event_fn fn);
    [[nodiscard]] sandbox_stats stats() const;

    // ---- used by stack.cpp, the hook, the allocator and the Lua-side builtins -------------------
    struct raised_error {
        std::string text;
        error err;
    };
    std::optional<raised_error> last_raised;
    std::string pending_traceback;

    void output_line(std::string_view line);
    void emit(const value& v);
    [[nodiscard]] module_record* record(module_id mod) noexcept;
    [[nodiscard]] const module_record* record(module_id mod) const noexcept;
    // _ENV of the running code's revision (the scratch env when nothing runs).
    [[nodiscard]] int current_env() const noexcept;

    // The request whose own thread is `L` and may yield right now; raises (naming `what`) otherwise.
    request_record& suspendable(lua_State* L, std::string_view what);
    [[nodiscard]] steady::time_point script_now() const;
    // The request running right now (innermost), or nullptr.
    [[nodiscard]] request_record* running_request() noexcept;

    // The Lua-side builtins (sandbox.cpp, schedule.cpp, script_events.cpp, tasks.cpp): push their
    // result or raise.
    // `where`: the builtin (rhp.after, rhp.every_frames, ...), for errors.
    std::uint64_t add_timer(lua_State* L, std::string_view where, double ms, int fn_index, bool repeating, const handler_opts& opts, std::string label);
    std::uint64_t add_frames(lua_State* L, std::string_view where, std::uint64_t every, int fn_index, const handler_opts& opts);
    // add_timer's and add_frames' common part: `entry` with the function at `fn_index`, as the running code's.
    std::uint64_t add_schedule(lua_State* L, std::string_view where, int fn_index, schedule_entry entry, std::string label);
    std::uint64_t subscribe(lua_State* L, std::string_view event, int fn_index, bool once, const handler_opts& opts);
    void remove_by_id(lua_State* L, std::uint64_t seq);
    void set_paused(lua_State* L, std::uint64_t seq, bool paused);
    void reschedule(lua_State* L, std::uint64_t seq, double interval);
    void push_timers(lua_State* L);
    bool publish(lua_State* L, std::string_view event, int first_arg);
    int wait_event(lua_State* L, std::string_view event, std::optional<double> timeout_ms);
    int finish_wait_event(lua_State* L); // the continuation of rhp.wait_event
    void push_stats(lua_State* L);
    void push_required(lua_State* L, std::string_view name);
    // Reads the options table at `index` (none / nil: defaults); raises naming `where`.
    static constexpr unsigned kOptTimes = 1;
    static constexpr unsigned kOptPriority = 2;
    static constexpr unsigned kOptOnError = 4;
    handler_opts read_opts(lua_State* L, int index, std::string_view where, unsigned allowed);

    // Tasks (tasks.cpp).
    void spawn(lua_State* L);
    void push_tasks(lua_State* L);
    [[nodiscard]] task_record* task(std::uint64_t key) noexcept;
    [[nodiscard]] task_record* task_by_seq(std::uint64_t seq) noexcept;
    [[nodiscard]] std::string_view task_status(const task_record& t) const noexcept;
    bool cancel_task(std::uint64_t key, std::string_view why);
    int join_task(lua_State* L, std::uint64_t key);   // pushes the results, raises, or yields
    int finish_join(lua_State* L, std::uint64_t key); // the continuation of a join
    void push_task_handle(lua_State* L, task_record& t);
    void handle_released(std::uint64_t key) noexcept; // a task handle was collected
    // Raises (naming `where`) while lua_close runs finalizers: nothing may be scheduled, subscribed or spawned.
    void refuse_while_closing(lua_State* L, std::string_view where) const;

    // Called by the effects behind the schedule and subscriptions when undone or destroyed.
    void remove_schedule(std::uint64_t key) noexcept;
    void unsubscribe(const std::string& event, std::uint64_t key) noexcept;

    static void* allocate(void* ud, void* ptr, std::size_t old_size, std::size_t new_size) noexcept;
    // allocate's two homes: a block of `size` bytes back to small_ or (larger) to the C heap or
    // memory_; a new block too large for small_.
    void free_block(void* block, std::size_t size) noexcept;
    [[nodiscard]] void* heap_allocate(std::size_t size) noexcept;
    // The hook: count events (limits, cancels, time slices, profiler samples) and, while the debugger
    // needs them, line events.
    static void count_hook(lua_State* L, lua_Debug* ar);

private:
    struct active_scope;
    struct slice_scope;

    // One entry per nested run on this state, innermost last.
    struct active_run {
        run_budget* budget = nullptr; // nullptr: a handler inside another run, part of that run's budget
        lua_State* thread = nullptr;  // the request's coroutine; nullptr for handlers (never sliced)
        request_record* request = nullptr;
        steady::time_point started;
        bool checked = false; // a run of a checked request kind (enter_checked)
    };

    void open_libraries();
    void open_stage7_libraries(); // the task metatable (tasks.cpp)
    // Coverage (testing.cpp): a line event, and a chunk just compiled (its function on top of the stack).
    void coverage_line(lua_State* L, lua_Debug* ar) noexcept;
    void coverage_compiled(lua_State* L, std::string_view chunk) noexcept;
    // The hook counts instructions on every run (the profiler or the meter is on).
    [[nodiscard]] bool counts_everywhere() const noexcept { return profiler_ != nullptr || metering_; }
    // Whether a hook with `mask` counts at safe points (see install_hook).
    [[nodiscard]] bool counts_at_safepoints(int mask) const noexcept;
    void install_hook(lua_State* L, int mask, int count) noexcept;
    // What line events the hook needs: none; on every line (coverage, the debugger's step or pause);
    // or by function (breakpoints only: call and return events turn them on in functions that have
    // one, scope_lines).
    enum class line_mode : std::uint8_t {
        kNone,
        kEverywhere,
        kByFunction
    };
    [[nodiscard]] line_mode lines_wanted() const noexcept;
    [[nodiscard]] int line_mask() const noexcept;
    // A call or return event in kByFunction: line events on in the function now running (debug.cpp).
    void scope_lines(lua_State* L, lua_Debug* ar) noexcept;
    // The debugger's line hook: breakpoints, steps and pause() (debug.cpp).
    void line_event(lua_State* L, lua_Debug* ar);
    // One profiler sample of L's stack (profile.cpp).
    void profile_sample(lua_State* L) noexcept;
    // The hook's count and mask changed (the profiler or the debugger started or stopped): every
    // request coroutine and the main thread get the new one.
    void rearm_all() noexcept;
    // Whether the run on top is checked (cancels, limits): what its thread's hook is armed for,
    // besides the profiler and the debugger.
    [[nodiscard]] bool checked_now() const noexcept;
    // Gives L the hook mask and count it should have now (a thread armed before the profiler or the
    // debugger changed them: a coroutine a script made, a run that was re-armed meanwhile).
    void sync_hook(lua_State* L, bool checked) noexcept;
    // One profiler tick of `elapsed` instructions: a sample once they add up to the interval.
    void profile_tick(lua_State* L, std::uint64_t elapsed) noexcept;
    // The coroutine of a request the debugger paused (kNotFound otherwise).
    [[nodiscard]] result<lua_State*> paused_thread(request_id id) const;
    void publish_debug_event(std::string_view kind, const debug_stop& stop);
    // The name of a request's outermost function, which Lua doesn't know (C++ called it): the
    // exported function's name for a call, "(timer)", "(event x)", ... for handlers, "?" otherwise.
    [[nodiscard]] static std::string outer_name(const request_record& req);
    // The registry ref of the environment of a request's module (kNoRef when it has none).
    [[nodiscard]] int env_of(const request_record& req) const noexcept;
    void forget_paused(request_id id) noexcept; // a paused request ended (stop_waiting)
    // The hook: armed on every run when hook_everywhere() (a limit needs it, or cancel_checks is
    // kEverything), else on request coroutines and, while an operation runs, the main thread.
    void reset_hook() noexcept;
    void arm_hook(lua_State* L, bool armed) noexcept;
    // The hook mask of a thread `armed` (or not) for cancels and limits, with what the meter, the
    // profiler, coverage and the debugger add.
    [[nodiscard]] int hook_mask(bool armed) const noexcept;
    // Whether a request's coroutine is armed for cancels and limits.
    [[nodiscard]] bool armed_for(const request_record& req) const noexcept { return hook_everywhere() || req.checked; }
    [[nodiscard]] bool hook_everywhere() const noexcept;
    [[nodiscard]] bool checks_requests() const noexcept; // cancel_checks isn't kNone
    // Requests that check for cancel() (exec, load, call, tasks; cancel_scope::kRequests).
    [[nodiscard]] static constexpr bool checked_kind(request_kind k) noexcept {
        return k == request_kind::kExec || k == request_kind::kLoad || k == request_kind::kCall || k == request_kind::kTask;
    }
    [[nodiscard]] std::uint32_t check_interval() const noexcept;
    // Instructions between count events: check_interval(), or the profiler's interval when lower.
    [[nodiscard]] std::uint32_t hook_count() const noexcept;
    struct operation_scope;
    // An operation or a checked request run starts / ends: while any is active the main thread (patch
    // handlers, on_save / on_restore) and handler coroutines started meanwhile check too.
    void enter_checked() noexcept;
    void leave_checked() noexcept;
    void check_cancels() noexcept;
    // Consumes a pending cancel(request) for `id`; a request with one is ended instead of resumed.
    [[nodiscard]] bool take_cancel(request_id id);
    [[nodiscard]] int new_environment();
    // Pushes the compiled chunk with its _ENV set; fails with kCompile.
    // `cached`: a trusted source compiled once per process; later compiles load its bytecode.
    // `bytecode`: trusted bytecode of `source` to load instead of parsing it (when Lua refuses it,
    // the source is parsed: bytecode_rejected_).
    [[nodiscard]] result<void> compile(std::string_view source, const std::string& chunk_name, int env_ref, bool cached = false,
                                       std::string_view bytecode = {});

    // Requests. start_request moves the function and `nargs` arguments on top of the main stack
    // into a new coroutine; step runs it until it finishes (the result), fails, or suspends (nullopt).
    // `label` names the request in errors; handlers (timers, frame callbacks, events, tasks) pass none
    // and get one from where_of() when they fail.
    // A request enters requests_ (the scheduler's map) only when it first suspends; until then its
    // map node waits in unlisted_ (tasks, which start at a later pump(), are listed at once). Most
    // requests finish in their first step and never touch the map. `host`: where a new coroutine is
    // made when the pool has none (rhp.spawn passes its own coroutine; default the main state).
    request_record& start_request(request_kind kind, const effect_owner& owner, std::string_view label, int nargs, bool from_operation,
                                  lua_State* host = nullptr);
    // The next handler of one delivery in the record and coroutine the previous one finished in
    // (both unlisted and idle): a new request id, owner and state, the same coroutine (re-armed).
    request_record& restart_request(request_record& req, request_kind kind, const effect_owner& owner, int nargs);
    // An idle record kept for a next handler that never came: its coroutine and node go back to the pools.
    void release_kept(request_record& req) noexcept;
    // A finished request's map node (with its record) back to the pool, while it has room (else freed).
    void recycle(std::map<request_id, std::unique_ptr<request_record>>::node_type&& node) noexcept;
    // Where a failure of `req` happened when the script gives no location.
    [[nodiscard]] std::string where_of(const request_record& req) const;
    // `kept` (deliveries): a request that finishes normally keeps its record and coroutine for the
    // caller's next handler (restart_request) and sets *kept; anything else recycles them as usual.
    std::optional<result<value_list>> step(request_record& req, int nargs, bool* kept = nullptr);
    // step's two halves after its checks: one lua_resume (returns its status), and what follows it.
    int resume_request(request_record& req, int nargs, int& nresults);
    std::optional<result<value_list>> finish_step(request_record& req, int status, int nresults, bool* kept);
    // `results`: an exec's or a call's results already converted (call_unprotected).
    result<value_list> complete(request_record& req, result<int> outcome, bool* kept = nullptr, value_list* results = nullptr);
    // sandbox::call without the protected run around its setup, when nothing before or after its
    // lua_resume can raise or throw (sandbox.cpp says when). nullopt: not taken, nothing done.
    std::optional<result<value_list>> call_unprotected(module_record& mod, std::string_view function, std::span<const value> args);
    // The registry ref of an exported function's name sandbox::call looked up before (kNoRef if none);
    // remember_call_key (protected) interns one.
    [[nodiscard]] int call_key(std::string_view function) const noexcept;
    void remember_call_key(std::string_view function);
    // The map node of an unlisted record (empty if it isn't in unlisted_).
    [[nodiscard]] std::map<request_id, std::unique_ptr<request_record>>::node_type take_unlisted(const request_record& req) noexcept;
    // A request suspends for the first time: into requests_.
    void list_request(request_record& req) noexcept;
    // Makes `req` request `id` and moves the function and `nargs` arguments on the main stack into `co`.
    void prepare_request(request_record& req, lua_State* co, request_kind kind, const effect_owner& owner, request_id id, int nargs);
    result<value_list> complete_load(module_record& mod, revision_id revision, lua_State* thread);
    // Pushes the exported function `name` (on_save, on_restore, on_unload) of the exports table
    // `exports_ref` onto the main stack (true), or nothing when it exports none (false).
    bool push_export(int exports_ref, const char* name);
    // Ends suspended requests matching `pred` without faulting anyone (their module is going away).
    template <class Pred>
    void abandon_requests(Pred pred, std::string_view why);
    void close_thread(request_record& req, bool failed) noexcept;

    // A synchronous call of the function below `nargs` args on the main stack, as `owner`'s code.
    [[nodiscard]] result<void> call_sync(const effect_owner& owner, int nargs, int nresults);
    // Runs fn() (a result<void>) as `owner`'s code: inside a running script part of that run, from
    // outside one a run of its own (a budget of its own, whose stop is the result's error).
    template <class F>
    [[nodiscard]] result<void> run_as(const effect_owner& owner, F&& fn);
    [[nodiscard]] error sticky_error(sticky_stop stop) const;
    [[nodiscard]] value_list collect_results(lua_State* L, int first, int last);

    // Faults (auto-revert) per the fault policy; deferred while a run is active.
    void fault_or_defer(const effect_owner& owner, error err);
    void fault(const effect_owner& owner, error err);
    void abort_reload(module_record& mod) noexcept;
    void release(module_instance& instance) noexcept;
    void forget_proxy(module_id mod) noexcept;
    [[nodiscard]] bool depends_on(module_id from, module_id to, std::vector<module_id>& path) const;
    [[nodiscard]] std::vector<std::string> dependents_of(module_id mod) const;
    [[nodiscard]] module_instance* instance_of(module_record& mod, revision_id revision) noexcept;

    // Applies queued faults, cancels, deferred operations and on_result notifications. Only acts
    // when no run is active (the end of the outermost operation, or pump()).
    void drain();
    // Runs `op` now, or queues it if a run is active (returns true when queued).
    bool defer_if_running(std::function<void()> op);
    void fire_schedule();
    void fire_entry(std::uint64_t key, steady::time_point now);
    void resume_ready();

    // Every request's end (complete() and abandon_requests()): waiters, joiners, tasks, overlap guards.
    // `abandoned`: ended by abandon_requests (its module is going away), not by its own outcome.
    void request_ended(request_record& req, const result<value_list>* outcome, bool abandoned) noexcept;
    void finish_task(request_record& req, const result<value_list>* outcome, bool abandoned) noexcept;
    void stop_waiting(request_record& req) noexcept;
    // Asynchronous bindings (async.cpp). wake_async() (pump) wakes the requests whose results
    // arrived and settles calls nobody waits for any more; drop_async() lets go of a call whose
    // request is gone (taking back a success that already arrived).
    void wake_async();
    void arrive(const std::shared_ptr<async_wait>& op);
    void drop_async(std::shared_ptr<async_wait> op) noexcept;
    void count(async_settled outcome) noexcept;
    void close_async() noexcept; // the destructor: no result is received any more

public:
    // sandbox::release_async.
    [[nodiscard]] async_leftovers release_async();

private:
    // Ends one suspended request (abandon_requests for a single id).
    void abandon_request(request_id id, std::string_view why);
    // A handler request failed: apply its policy now, or when the run around it ends.
    void handler_failed_or_defer(const request_record& req, error err);
    void apply_failure(pending_failure f);
    // Interest in an event name (subscriptions and waiters) attaches to a C++ event while any exists.
    // `state` is nullptr for script events.
    void acquire_interest(std::string_view event, event_state* state);
    void release_interest(const std::string& event) noexcept;
    // Resolves a name for rhp.on / rhp.wait_event: the C++ event's state, nullptr for a script
    // event, or raises (a name two C++ events share, a name that isn't dotted lowercase).
    event_state* resolve_event(lua_State* L, std::string_view event, std::string_view where);
    // Runs the handlers and wakes the waiters of one delivery. `values` is set for script events.
    void deliver_now(std::string_view event, event_pusher args, module_id publisher, const value_list* values);
    // Queues a script event for the next pump(); false when limits.event_queue is full.
    bool queue_script_event(std::string name, module_id publisher, value_list args);
    void call_listeners();
    void report_failures();
    // Packs the `n` values on top of L into a registry table {n = n, ...} (pops them).
    int pack_top(lua_State* L, int n);
    // Pushes a packed table's values onto L; returns how many.
    int unpack_ref(lua_State* L, int ref);
    [[nodiscard]] schedule_entry* schedule_by_seq(std::uint64_t seq) noexcept;
    [[nodiscard]] subscription* subscription_by_seq(std::uint64_t seq) noexcept;
    // The calling module owns the ledger entry `seq`.
    [[nodiscard]] bool owns_entry(std::uint64_t seq) const noexcept;
    void output_for(request_id request, module_id mod, std::string_view line);

    revert_report revert_module(module_record& mod);
    revert_report unload_module(module_record& mod);

    sandbox_options options_;
    std::pmr::memory_resource* memory_; // nullptr: the C heap (realloc)
    // Blocks up to small_alloc::kMaxSize, in regions from memory_. A member, so it outlives the
    // destructor's lua_close (which gives every block back) and then gives back the regions.
    small_alloc small_;
    std::size_t memory_used_ = 0;
    // The innermost run with a budget of its own (what a memory stop is charged to), kept by
    // active_scope so the allocator doesn't walk running_.
    run_budget* budget_ = nullptr;
    // What lua_gc was last switched to through RHP (collect_idle); an admin script's collectgarbage()
    // can change the mode behind it, which only makes collect_idle step more or less than it could.
    gc_mode gc_mode_ = gc_mode::kIncremental;
    // Allocation counters (sandbox::meter): always on, a few increments per allocation.
    std::size_t peak_ = 0;
    std::uint64_t allocations_ = 0;
    std::uint64_t frees_ = 0;
    std::uint64_t bytes_allocated_ = 0;
    std::array<std::uint64_t, kAllocKinds> objects_{};
    // The meter (start_metering): exact instruction counts and the time Lua runs.
    bool metering_ = false;
    std::uint64_t meter_instructions_ = 0;
    steady::duration meter_active_{};
    steady::time_point meter_run_started_{}; // the outermost run started (while metering)
    // The test bridge (enable_testing).
    bool testing_on_ = false;
    testing_options testing_{};
    steady::time_point testing_started_{};
    bool timed_ = false; // limits.wall_ms: runs read the clock
    lua_State* state_ = nullptr;
    int loader_ref_ = kNoRef;

    ledger ledger_;
    std::map<module_id, module_record> modules_;
    std::map<std::string, std::uint64_t, std::less<>> checkpoints_;
    std::vector<std::string (*)(role)> describers_;
    std::vector<value (*)(role)> api_describers_;
    std::vector<tunable_info> tunables_; // every ::var and ::ro of the installed libs
    id_generator<module_id> ids_;
    module_id scratch_;
    effect_owner current_;

    // Scheduler.
    id_generator<request_id> request_ids_;
    std::map<request_id, std::unique_ptr<request_record>> requests_;
    // Finished requests' map nodes (record included) and coroutines, reused by start_request.
    std::vector<decltype(requests_)::node_type> spare_requests_;
    // Records of requests that run but never suspended (and a delivery's idle record between two
    // handlers): their nodes wait here instead of in requests_, innermost last.
    std::vector<decltype(requests_)::node_type> unlisted_;
    // Names of exported functions sandbox::call found, interned and pinned in the registry (name, ref):
    // a call of one again looks it up without allocating (call_unprotected). Bounded; replaced in turn.
    std::vector<std::pair<std::string, int>> call_keys_;
    std::size_t call_keys_next_ = 0;
    std::vector<std::pair<lua_State*, int>> spare_threads_; // (thread, registry ref)
    std::uint32_t checked_depth_ = 0;                       // operations and checked request runs active (enter_checked)
    // The earliest frame / script time a suspended request wakes at, so an idle pump() doesn't walk
    // them all. Anything that may wake one sooner (a request starting or suspending, a delivery)
    // sets requests_dirty_ and the next resume pass walks them anyway.
    bool requests_dirty_ = true;
    std::uint64_t requests_next_frame_ = 0;
    steady::time_point requests_next_wake_{};
    request_id last_request_;
    request_id last_resumed_; // round robin in resume_ready()
    std::uint64_t frame_ = 0;
    // Keyed by creation (keys only grow): what needs creation order sorts the keys (fire_schedule, push_timers).
    std::unordered_map<std::uint64_t, schedule_entry> schedule_;
    std::uint64_t schedule_keys_ = 0;
    // Likewise for timers and frame callbacks: added, resumed or rescheduled entries set schedule_dirty_.
    bool schedule_dirty_ = true;
    std::uint64_t schedule_next_frame_ = 0;
    steady::time_point schedule_next_due_{};
    std::map<std::string, std::vector<subscription>, std::less<>> subscriptions_;
    std::uint64_t subscriptions_version_ = 0;                             // bumped when a list is added, removed or changes length
    std::map<std::string, std::vector<request_id>, std::less<>> waiters_; // rhp.wait_event
    std::map<std::string, event_state*, std::less<>> attached_;
    std::uint64_t subscription_keys_ = 0;
    std::map<std::uint64_t, task_record> tasks_;
    std::uint64_t task_keys_ = 0;
    std::vector<std::uint64_t> collected_tasks_;     // handles collected (__gc only appends)
    bool closing_ = false;                           // the destructor runs: __gc does nothing
    bool closing_lua_ = false;                       // lua_close runs: builtins refuse, effects are undone at once
    std::vector<queued_script_event> script_events_; // for the next pump()
    std::uint64_t handler_failures_ = 0;
    std::shared_ptr<async_inbox> async_inbox_ = std::make_shared<async_inbox>();
    std::vector<std::shared_ptr<async_wait>> detached_async_; // calls whose request is gone, until their result arrives
    std::uint64_t async_compensated_ = 0;
    std::uint64_t async_dropped_ = 0;
    std::uint64_t bytecode_loaded_ = 0;   // compile(): trusted bytecode loaded
    std::uint64_t bytecode_rejected_ = 0; // compile(): trusted bytecode Lua refused (the source was parsed)
    std::shared_ptr<script_listener_table> listeners_ = std::make_shared<script_listener_table>();

    // Work applied when no run is active.
    std::vector<std::pair<effect_owner, error>> pending_faults_;
    std::vector<pending_failure> pending_failures_;
    std::vector<handler_failure> failure_reports_;
    std::vector<queued_script_event> listener_calls_;
    std::vector<std::function<void()>> deferred_;
    std::vector<std::pair<request_id, result<value_list>>> finished_;

    // Run state.
    std::vector<active_run> running_;
    std::optional<steady::time_point> slice_deadline_;
    bool hook_dirty_ = false;
    std::unique_ptr<profiler_state> profiler_; // while profiling
    std::unique_ptr<coverage_state> coverage_; // while recording coverage
    std::unique_ptr<debugger_state> debugger_; // breakpoints, steps, paused requests (created on first use)

    // Shared with other threads.
    std::atomic<std::thread::id> thread_;
    std::atomic<bool> cancel_running_{false};
    std::atomic<bool> cancel_ids_pending_{false};
    mutable std::mutex inbox_mutex_; // guards cancel_ids_ and inbox_ (stats() reads inbox_)
    std::vector<request_id> cancel_ids_;
    std::vector<std::pair<std::string, std::function<int(stack&)>>> inbox_;
    std::atomic<std::uint64_t> dropped_events_{0};
};

// ---- run scopes (sandbox.cpp, requests.cpp, modules.cpp, tools.cpp) ------------------------------

// One entry on the run stack: makes `owner` the running code and accounts its time to `budget`.
// The outermost scope clears a cancel() that arrived while nothing ran, and resets the hook after a
// stop switched it to every instruction.
struct sandbox_impl::active_scope {
    sandbox_impl& self;
    effect_owner previous;
    run_budget* previous_budget;

    active_scope(sandbox_impl& s, run_budget* budget, lua_State* thread, request_record* request, const effect_owner& owner)
        : self(s), previous(s.current_), previous_budget(s.budget_) {
        if (self.running_.empty()) {
            self.cancel_running_.store(false, std::memory_order_release);
        }
        const bool checked = request != nullptr && checked_kind(request->kind);
        if (self.metering_ && self.running_.empty()) {
            self.meter_run_started_ = steady::now();
        }
        self.running_.push_back(active_run{budget, thread, request, self.timed_ ? steady::now() : steady::time_point{}, checked});
        if (budget != nullptr) {
            self.budget_ = budget;
        }
        self.current_ = owner;
        if (checked) {
            self.enter_checked();
        }
    }

    active_scope(const active_scope&) = delete;
    active_scope& operator=(const active_scope&) = delete;

    ~active_scope() {
        const active_run& top = self.running_.back();
        if (top.budget != nullptr && self.timed_) {
            top.budget->active += steady::now() - top.started;
        }
        const bool checked = top.checked;
        self.running_.pop_back();
        self.budget_ = previous_budget;
        self.current_ = previous;
        if (self.metering_ && self.running_.empty()) {
            self.credit_hook_progress(self.state_);
            self.meter_active_ += steady::now() - self.meter_run_started_;
        }
        if (checked) {
            self.leave_checked();
        }
        if (self.running_.empty() && self.hook_dirty_) {
            self.hook_dirty_ = false;
            self.rearm_all(); // every coroutine, in case the profiler or the debugger changed the hook meanwhile
        }
    }
};

// limits.slice_us of wall time for everything started from here (an operation, pump(), an event).
struct sandbox_impl::slice_scope {
    sandbox_impl& self;
    bool owns;

    explicit slice_scope(sandbox_impl& s)
        : self(s), owns(s.options_.limits.slice_us != 0 && !s.slice_deadline_ && s.running_.empty()) {
        if (owns) {
            self.slice_deadline_ = steady::now() + std::chrono::microseconds{self.options_.limits.slice_us};
        }
    }

    slice_scope(const slice_scope&) = delete;
    slice_scope& operator=(const slice_scope&) = delete;

    ~slice_scope() {
        if (owns) {
            self.slice_deadline_.reset();
        }
    }
};

// An operation (exec, load, call, reload, unload, revert_all): while it runs, the main thread checks
// for cancel() too (on_save / on_restore / on_unload, and patch handlers its code hits), like its
// request coroutine does. Outside operations the main thread runs handlers, unchecked by default.
struct sandbox_impl::operation_scope {
    sandbox_impl& self;

    explicit operation_scope(sandbox_impl& s) : self(s) { self.enter_checked(); }

    operation_scope(const operation_scope&) = delete;
    operation_scope& operator=(const operation_scope&) = delete;

    ~operation_scope() { self.leave_checked(); }
};

template <class Pred>
void sandbox_impl::abandon_requests(Pred pred, std::string_view why) {
    std::vector<request_id> doomed;
    for (const auto& [id, req] : requests_) {
        if (!req->running && pred(*req)) {
            doomed.push_back(id);
        }
    }
    for (const request_id id : doomed) {
        auto node = requests_.extract(id);
        if (node.empty()) {
            continue;
        }
        request_record& req = *node.mapped();
        req.listed = false;
        const result<value_list> outcome = fail(errc::kCancelled, std::string{why}, where_of(req));
        close_thread(req, true);
        request_ended(req, &outcome, true);
        if (req.suspended_once) {
            finished_.emplace_back(id, outcome);
        }
        recycle(std::move(node));
    }
}

} // namespace Rhp::script::detail
