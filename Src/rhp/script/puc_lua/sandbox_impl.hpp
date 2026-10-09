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
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/script/detail/context.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/ledger.hpp>
#include <rhp/script/sandbox.hpp>
#include <rhp/script/stack.hpp>

struct lua_Debug;

namespace Rhp::script::detail {

using steady = std::chrono::steady_clock;

inline constexpr int kNoRef = -2; // LUA_NOREF

// Converts the Lua error object on top of the stack (popped) into an Rhp::error. `status` is the
// lua_pcall / lua_resume status. Recovers the structured error raised by stack::raise.
[[nodiscard]] error take_lua_error(lua_State* L, int status);

// Message handler for lua_pcall: stores a traceback in the sandbox and returns the error unchanged.
int traceback_handler(lua_State* L);

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
    kTimer,
    kEvent
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
};

struct timer_record {
    effect_owner owner;
    int fn_ref = kNoRef;
    steady::time_point due;
    steady::duration interval{};
    bool repeating = false;
    std::uint64_t seq = 0; // its ledger entry (the id rhp.off takes)
};

struct subscription {
    std::uint64_t key = 0;
    effect_owner owner;
    int fn_ref = kNoRef;
    std::uint64_t seq = 0; // its ledger entry (the id rhp.off takes)
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

    // ---- event_listener ------------------------------------------------------------------------
    [[nodiscard]] std::thread::id listener_thread() const noexcept override { return thread_.load(std::memory_order_acquire); }
    void deliver(std::string_view event, event_pusher args) override;
    void enqueue(std::string_view event, std::function<int(stack&)> args) noexcept override;

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
    // rhp.timer / rhp.on / rhp.off / require: push their result or raise.
    std::uint64_t add_timer(lua_State* L, double ms, int fn_index, bool repeating);
    std::uint64_t subscribe(lua_State* L, std::string_view event, int fn_index);
    void remove_by_id(lua_State* L, std::uint64_t seq);
    void push_required(lua_State* L, std::string_view name);
    // Called by the effects behind rhp.timer / rhp.on when they are undone or destroyed.
    void remove_timer(std::uint64_t key) noexcept;
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
    };

    void open_libraries();
    void reset_hook() noexcept;
    [[nodiscard]] std::uint32_t check_interval() const noexcept;
    void check_cancels() noexcept;
    // Consumes a pending cancel(request) for `id`; a request with one is ended instead of resumed.
    [[nodiscard]] bool take_cancel(request_id id);
    [[nodiscard]] int new_environment();
    // Pushes the compiled chunk with its _ENV set; fails with kCompile.
    [[nodiscard]] result<void> compile(std::string_view source, const std::string& chunk_name, int env_ref);

    // Requests. start_request moves the function and `nargs` arguments on top of the main stack
    // into a new coroutine; step runs it until it finishes (the result), fails, or suspends (nullopt).
    request_record& start_request(request_kind kind, const effect_owner& owner, std::string label, int nargs, bool from_operation);
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
    void fire_timers();
    void resume_ready();

    revert_report revert_module(module_record& mod);
    revert_report unload_module(module_record& mod);

    sandbox_options options_;
    std::pmr::memory_resource* memory_;
    std::size_t memory_used_ = 0;
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
    request_id last_request_;
    request_id last_resumed_; // round robin in resume_ready()
    std::uint64_t frame_ = 0;
    std::map<std::uint64_t, timer_record> timers_;
    std::uint64_t timer_keys_ = 0;
    std::map<std::string, std::vector<subscription>, std::less<>> subscriptions_;
    std::map<std::string, event_state*, std::less<>> attached_;
    std::uint64_t subscription_keys_ = 0;

    // Work applied when no run is active.
    std::vector<std::pair<effect_owner, error>> pending_faults_;
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
};

} // namespace Rhp::script::detail
