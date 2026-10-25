#pragma once

// Private to Src/rhp/script/puc_lua: the sandbox behind Rhp::script::sandbox. Deliberately free of
// lua.h (the .cpp files that include this one include lua.h themselves).

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
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/ids.hpp>
#include <rhp/core/listener_table.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stack.hpp>

struct lua_Debug;

namespace Rhp::script::detail {

using steady = std::chrono::steady_clock;

inline constexpr int kNoRef = -2; // LUA_NOREF

class sandbox_impl;

// The sandbox that owns a Lua state (any of its threads).
[[nodiscard]] sandbox_impl& impl_of(lua_State* L) noexcept;

// Converts the Lua error object on top of the stack (popped) into an Rhp::error. `status` is the
// lua_pcall / lua_resume status. Recovers the structured error raised by stack::raise.
[[nodiscard]] error take_lua_error(lua_State* L, int status);

// Message handler for lua_pcall: stores a traceback in the sandbox and returns the error unchanged.
int traceback_handler(lua_State* L);

// Milliseconds argument (>= 0) or a raised error naming `where`.
double checked_ms(lua_State* L, int index, std::string_view where);
steady::duration milliseconds(double ms);

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
    kAsync  // an asynchronous binding: resumed when its result arrives (woken) or limits.async_ms (wake_time)
};

// One script request: a coroutine the scheduler runs, suspends and resumes.
struct request_record {
    request_id id;
    request_kind kind = request_kind::kExec;
    effect_owner owner; // owner.request == id
    std::string label;  // error location when the script gives none ("combat.boost", "timer")
    lua_State* thread = nullptr;
    int thread_ref = kNoRef;
    run_budget budget;
    bool running = false;
    bool suspended_once = false; // its result goes to on_result
    bool sliced = false;         // the hook yielded it at the end of a time slice
    std::uint64_t wake_frame = 0;
    std::optional<steady::time_point> wake_time; // script clock
    int start_args = -1;                         // >= 0: not started yet; the first resume passes this many arguments (tasks)
    bool woken = false;                          // a delivery or a joined task's end: resume at the next resume pass
    wait_kind waiting = wait_kind::kNone;
    std::string wait_event{};    // kEvent: the event waited for
    std::uint64_t wait_task = 0; // kTask: the task joined
    int resume_ref = kNoRef;     // kEvent: the delivered arguments, packed {n = count, ...}
    std::shared_ptr<async_wait> async{}; // kAsync: the call it waits for
    // Handlers: what started it, for the overlap guard, rhp.off and failure reports.
    std::uint64_t schedule_key = 0;
    std::uint64_t task_key = 0;
    std::uint64_t handler_seq = 0;
    std::string source{}; // the event name, or "timer" / "frame" / "task"
    handler_error_policy policy = handler_error_policy::kReport;
    std::optional<error> start_error{}; // set up but can't start (its arguments didn't fit): fails at its first step

    // Back to a new record for the next request (records are pooled): every field to its default,
    // the strings keeping their buffers.
    void reset() noexcept {
        std::string l = std::move(label);
        std::string s = std::move(source);
        std::string w = std::move(wait_event);
        *this = request_record{};
        l.clear();
        s.clear();
        w.clear();
        label = std::move(l);
        source = std::move(s);
        wait_event = std::move(w);
    }
};

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
    result<void> install_lib(std::string_view name, c_function build, std::string (*describe)(role));
    result<value_list> exec(std::string_view source, std::string_view chunk_name);
    result<module_id> load(std::string_view name, std::string_view source);
    result<revision_id> reload(module_id mod, std::string_view source);
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
    [[nodiscard]] request_id last_request() const noexcept { return last_request_; }
    [[nodiscard]] std::size_t suspended() const noexcept;
    [[nodiscard]] bool pending(request_id request) const noexcept { return requests_.contains(request); }
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
    std::uint64_t add_timer(lua_State* L, double ms, int fn_index, bool repeating, const handler_opts& opts, std::string label);
    std::uint64_t add_frames(lua_State* L, std::uint64_t every, int fn_index, const handler_opts& opts);
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
    [[nodiscard]] bool closing() const noexcept { return closing_; }
    // Raises (naming `where`) while lua_close runs finalizers: nothing may be scheduled, subscribed or spawned.
    void refuse_while_closing(lua_State* L, std::string_view where) const;

    // Called by the effects behind the schedule and subscriptions when undone or destroyed.
    void remove_schedule(std::uint64_t key) noexcept;
    void unsubscribe(const std::string& event, std::uint64_t key) noexcept;

    static void* allocate(void* ud, void* ptr, std::size_t old_size, std::size_t new_size) noexcept;
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
    // The hook: armed on every run when hook_everywhere() (a limit needs it, or cancel_checks is
    // kEverything), else on request coroutines and, while an operation runs, the main thread.
    void reset_hook() noexcept;
    void arm_hook(lua_State* L, bool armed) noexcept;
    [[nodiscard]] bool hook_everywhere() const noexcept;
    [[nodiscard]] bool checks_requests() const noexcept; // cancel_checks isn't kNone
    // Requests that check for cancel() (exec, load, call, tasks; cancel_scope::kRequests).
    [[nodiscard]] static constexpr bool checked_kind(request_kind k) noexcept {
        return k == request_kind::kExec || k == request_kind::kLoad || k == request_kind::kCall || k == request_kind::kTask;
    }
    [[nodiscard]] std::uint32_t check_interval() const noexcept;
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
    [[nodiscard]] result<void> compile(std::string_view source, const std::string& chunk_name, int env_ref);

    // Requests. start_request moves the function and `nargs` arguments on top of the main stack
    // into a new coroutine; step runs it until it finishes (the result), fails, or suspends (nullopt).
    // `label` names the request in errors; handlers (timers, frame callbacks, events, tasks) pass none
    // and get one from where_of() when they fail.
    request_record& start_request(request_kind kind, const effect_owner& owner, std::string_view label, int nargs, bool from_operation);
    // Where a failure of `req` happened when the script gives no location.
    [[nodiscard]] std::string where_of(const request_record& req) const;
    std::optional<result<value_list>> step(request_record& req, int nargs);
    result<value_list> complete(request_id id, result<int> outcome);
    result<value_list> complete_load(module_record& mod, revision_id revision, lua_State* thread);
    // Ends suspended requests matching `pred` without faulting anyone (their module is going away).
    template <class Pred>
    void abandon_requests(Pred pred, std::string_view why);
    void close_thread(request_record& req, bool failed) noexcept;

    // A synchronous call of the function below `nargs` args on the main stack, as `owner`'s code.
    [[nodiscard]] result<void> call_sync(const effect_owner& owner, int nargs, int nresults);
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
    std::size_t memory_used_ = 0;
    bool timed_ = false; // limits.wall_ms: runs read the clock
    lua_State* state_ = nullptr;
    int loader_ref_ = kNoRef;

    ledger ledger_;
    std::map<module_id, module_record> modules_;
    std::map<std::string, std::uint64_t, std::less<>> checkpoints_;
    std::vector<std::string (*)(role)> describers_;
    id_generator<module_id> ids_;
    module_id scratch_;
    effect_owner current_;

    // Scheduler.
    id_generator<request_id> request_ids_;
    std::map<request_id, std::unique_ptr<request_record>> requests_;
    // Finished requests' map nodes (record included) and coroutines, reused by start_request.
    std::vector<decltype(requests_)::node_type> spare_requests_;
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
    std::map<std::uint64_t, schedule_entry> schedule_;
    std::uint64_t schedule_keys_ = 0;
    // Likewise for timers and frame callbacks: added, resumed or rescheduled entries set schedule_dirty_.
    bool schedule_dirty_ = true;
    std::uint64_t schedule_next_frame_ = 0;
    steady::time_point schedule_next_due_{};
    std::map<std::string, std::vector<subscription>, std::less<>> subscriptions_;
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

    // Shared with other threads.
    std::atomic<std::thread::id> thread_;
    std::atomic<bool> cancel_running_{false};
    std::atomic<bool> cancel_ids_pending_{false};
    std::mutex inbox_mutex_; // guards cancel_ids_ and inbox_
    std::vector<request_id> cancel_ids_;
    std::vector<std::pair<std::string, std::function<int(stack&)>>> inbox_;
    std::atomic<std::uint64_t> dropped_events_{0};
};

} // namespace Rhp::script::detail
