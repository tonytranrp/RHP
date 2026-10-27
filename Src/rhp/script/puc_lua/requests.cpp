// Requests: starting one (pooled records and coroutines), running and resuming it, its end
// (complete, request_ended, abandon), handler failures, calls made for C++ (run_handler, call_sync),
// deferred work (drain) and the resume pass of pump().

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/keys.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/tools.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

// ---- calls for C++ ------------------------------------------------------------------------------

template <class F>
result<void> sandbox_impl::run_as(const effect_owner& owner, F&& fn) {
    // Inside a running script this is part of that run; from game code it is a run of its own.
    run_budget local;
    run_budget* budget = running_.empty() ? &local : nullptr;
    result<void> ran;
    {
        const active_scope scope{*this, budget, nullptr, nullptr, owner};
        ran = fn();
    }
    if (budget != nullptr && local.sticky != sticky_stop::kNone) {
        error stop = sticky_error(local.sticky);
        if (ran) {
            return std::unexpected{std::move(stop)};
        }
        ran.error().code = stop.code;
    }
    return ran;
}

result<void> sandbox_impl::run_handler(const effect_owner& owner, c_function fn, void* data) {
    return run_as(owner, [&] { return stack{state_}.run_protected(fn, data); });
}

// ---- requests --------------------------------------------------------------------------------------

void sandbox_impl::abandon_request(request_id id, std::string_view why) {
    abandon_requests([id](const request_record& r) { return r.id == id; }, why);
}

request_record& sandbox_impl::start_request(request_kind kind, const effect_owner& owner, std::string_view label, int nargs, bool from_operation,
                                            lua_State* host) {
    // Where a new coroutine is made and registered: the main state, or the running coroutine that
    // asks (rhp.spawn), so an allocation that fails raises there, never on the main state while a
    // request runs (a call may run with the main state outside any protected run: call_unprotected).
    lua_State* L = host != nullptr ? host : state_;
    const request_id id = request_ids_.next();
    // A finished request's map node and record when one is spare, else new ones (made in the map and
    // taken out again: every record lives in a node, listed or not).
    decltype(requests_)::node_type node;
    if (!spare_requests_.empty()) {
        node = std::move(spare_requests_.back());
        spare_requests_.pop_back();
        node.mapped()->reset();
    } else {
        node = requests_.extract(requests_.emplace(id, std::make_unique<request_record>()).first);
    }
    request_record& req = *node.mapped();
    req.label.assign(label);

    luaL_checkstack(L, 5, "rhp: request setup"); // callers on the main state run protected (or made room first: call_unprotected)
    lua_State* co = nullptr;
    if (!spare_threads_.empty()) {
        std::tie(co, req.thread_ref) = spare_threads_.back();
        spare_threads_.pop_back();
    } else {
        co = lua_newthread(L);
        lua_getfield(L, LUA_REGISTRYINDEX, kRequestThreadsKey);
        lua_pushvalue(L, -2);
        lua_pushboolean(L, 1);
        lua_rawset(L, -3);
        lua_pop(L, 1);
        req.thread_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    try {
        prepare_request(req, co, kind, owner, id, nargs);
        node.key() = id;
        if (kind == request_kind::kTask) {
            // A task starts at a later pump(): the scheduler must see it now.
            req.listed = true;
            requests_.insert(std::move(node)); // reuses the node: no allocation
            requests_dirty_ = true;
        } else {
            unlisted_.push_back(std::move(node)); // reserved in the constructor (deeper nesting grows it)
        }
    } catch (...) { // out of memory part way: the coroutine is emptied and kept (the pool has room: it was just taken from, or reserved)
        lua_settop(co, 0);
        if (spare_threads_.size() < spare_threads_.capacity()) {
            spare_threads_.emplace_back(co, req.thread_ref);
        } else {
            luaL_unref(L, LUA_REGISTRYINDEX, req.thread_ref);
        }
        throw;
    }

    if (from_operation) {
        last_request_ = id;
    }
    return req;
}

void sandbox_impl::prepare_request(request_record& req, lua_State* co, request_kind kind, const effect_owner& owner, request_id id, int nargs) {
    req.id = id;
    req.kind = kind;
    req.owner = owner;
    req.owner.request = id;
    // Requests check for cancel() (handlers only when a limit or cancel_scope::kEverything asks).
    // A handler started while a checked run is active is part of that run's work (an event fired
    // synchronously by its code): it checks too.
    req.checked = checks_requests() && (checked_kind(kind) || checked_depth_ != 0);
    arm_hook(co, armed_for(req));
    // lua_xmove never grows the destination: a new coroutine has room for about 20 values.
    if (lua_checkstack(co, nargs + 1) == 0) {
        req.start_error = make_error(errc::kLimitExceeded, std::format("{} arguments don't fit a coroutine stack", nargs));
    }
    req.thread = co;
    if (req.start_error) {
        lua_pop(state_, nargs + 1); // the request ends at its first step
    } else {
        lua_xmove(state_, co, nargs + 1); // the function and its arguments
    }
}

request_record& sandbox_impl::restart_request(request_record& req, request_kind kind, const effect_owner& owner, int nargs) {
    lua_State* co = req.thread;
    const int ref = req.thread_ref;
    req.reset();
    req.thread = co; // release_kept still finds the coroutine if the rest throws
    req.thread_ref = ref;
    prepare_request(req, co, kind, owner, request_ids_.next(), nargs);
    return req;
}

void sandbox_impl::release_kept(request_record& req) noexcept {
    auto node = take_unlisted(req); // compares addresses only: `req` may be a record already recycled
    if (node.empty()) {
        return;
    }
    if (req.thread != nullptr) {
        close_thread(req, false);
    }
    recycle(std::move(node));
}

void sandbox_impl::recycle(std::map<request_id, std::unique_ptr<request_record>>::node_type&& node) noexcept {
    if (!node.empty() && spare_requests_.size() < kSpareRequests) {
        spare_requests_.push_back(std::move(node)); // reserved in the constructor: no allocation
    }
}

std::map<request_id, std::unique_ptr<request_record>>::node_type sandbox_impl::take_unlisted(const request_record& req) noexcept {
    for (auto it = unlisted_.end(); it != unlisted_.begin();) {
        --it;
        if (it->mapped().get() == &req) {
            auto node = std::move(*it);
            unlisted_.erase(it);
            return node;
        }
    }
    return {};
}

void sandbox_impl::list_request(request_record& req) noexcept {
    requests_dirty_ = true; // suspended with a new wake
    if (req.listed) {
        return;
    }
    auto node = take_unlisted(req);
    if (node.empty()) {
        return;
    }
    node.key() = req.id;
    requests_.insert(std::move(node)); // reuses the node: no allocation
    req.listed = true;
    // A profiler or debugger that started while it ran re-armed the listed coroutines only (rearm_all).
    if (!hook_dirty_) {
        sync_hook(req.thread, armed_for(req));
    }
}

bool sandbox_impl::live(request_id request) const noexcept {
    if (requests_.contains(request)) {
        return true;
    }
    return std::ranges::any_of(running_, [request](const active_run& run) { return run.request != nullptr && run.request->id == request; });
}

std::string sandbox_impl::where_of(const request_record& req) const {
    if (!req.label.empty()) {
        return req.label;
    }
    const module_record* mod = record(req.owner.module);
    const std::string_view name = mod != nullptr ? std::string_view{mod->name} : std::string_view{"?"};
    switch (req.kind) {
    case request_kind::kFrame: return std::format("{} (frame callback)", name);
    case request_kind::kTimer: return std::format("{} (timer)", name);
    case request_kind::kEvent: return std::format("{} (event {})", name, req.source);
    case request_kind::kTask: return std::format("{} (task)", mod != nullptr && !mod->scratch ? name : std::string_view{"exec"});
    case request_kind::kExec:
    case request_kind::kLoad:
    case request_kind::kCall: break;
    }
    return {};
}

std::optional<result<value_list>> sandbox_impl::step(request_record& req, int nargs, bool* kept) {
    if (kept != nullptr) {
        *kept = false;
    }
    if (take_cancel(req.id)) {
        return complete(req, std::unexpected{make_error(errc::kCancelled, "script cancelled")}, kept); // never resumed again
    }
    if (req.start_error) {
        return complete(req, std::unexpected{*req.start_error}, kept);
    }
    int nresults = 0;
    const int status = resume_request(req, nargs, nresults);
    return finish_step(req, status, nresults, kept);
}

int sandbox_impl::resume_request(request_record& req, int nargs, int& nresults) {
    req.wake_frame = 0;
    req.wake_time.reset();
    req.woken = false;
    if (req.kind == request_kind::kTask && req.budget.sticky == sticky_stop::kNone) {
        req.budget.instructions = 0; // a task's instruction and wall limits bound each resume
        req.budget.active = {};
    }
    req.running = true;
    lua_State* from = running_.empty() || running_.back().thread == nullptr ? state_ : running_.back().thread;
    int status = LUA_OK;
    {
        const active_scope scope{*this, &req.budget, req.thread, &req, req.owner};
        status = lua_resume(req.thread, from, nargs, &nresults);
        credit_hook_progress(req.thread);
    }
    req.running = false;
    return status;
}

std::optional<result<value_list>> sandbox_impl::finish_step(request_record& req, int status, int nresults, bool* kept) {
    const sticky_stop stop = req.budget.sticky;

    if (status == LUA_YIELD) {
        lua_pop(req.thread, nresults);
        if (stop == sticky_stop::kNone) {
            if (req.wake_frame == 0 && !req.wake_time && req.waiting == wait_kind::kNone) {
                req.wake_frame = frame_ + 1; // a time slice ran out, or a plain coroutine.yield()
            }
            req.suspended_once = true;
            list_request(req); // the scheduler resumes it from now on (sets requests_dirty_)
            return std::nullopt;
        }
        return complete(req, std::unexpected{sticky_error(stop)}, kept);
    }
    // Done: nothing it leaves behind wakes sooner than requests_next_* say (what it woke, a joiner or a
    // waiter, set requests_dirty_ itself).
    if (status == LUA_OK) {
        // A stop wins even if the script swallowed it with pcall and returned normally.
        if (stop != sticky_stop::kNone) {
            return complete(req, std::unexpected{sticky_error(stop)}, kept);
        }
        return complete(req, nresults, kept);
    }
    // The dead coroutine's stack is still intact: take the traceback before the error object
    // (unless memory ran out: building it would need more).
    if (status != LUA_ERRMEM && stop != sticky_stop::kMemory) {
        luaL_traceback(state_, req.thread, nullptr, 0);
        pending_traceback = lua_tostring(state_, -1);
        lua_pop(state_, 1);
    }
    lua_xmove(req.thread, state_, 1);
    error err = take_lua_error(state_, status);
    if (stop != sticky_stop::kNone) {
        err.code = sticky_error(stop).code;
    }
    return complete(req, std::unexpected{std::move(err)}, kept);
}

result<value_list> sandbox_impl::complete(request_record& req, result<int> outcome, bool* kept, value_list* results) {
    // Out of the scheduler first: nothing below (a fault abandoning its module's requests) may find
    // it. A record the caller wants to keep stays in unlisted_ until it is known to be reusable.
    const bool keepable = kept != nullptr && !req.listed;
    decltype(requests_)::node_type node;
    if (req.listed) {
        node = requests_.extract(req.id);
        req.listed = false;
    } else if (!keepable) {
        node = take_unlisted(req);
    }
    module_record* mod = req.kind == request_kind::kLoad ? record(req.owner.module) : nullptr;

    result<value_list> out = value_list{};
    if (!outcome) {
        out = std::unexpected{std::move(outcome).error()};
    } else if (req.kind == request_kind::kExec || req.kind == request_kind::kCall) {
        out = results != nullptr ? std::move(*results) : collect_results(req.thread, 1, *outcome);
    } else if (req.kind == request_kind::kLoad) {
        out = mod != nullptr ? complete_load(*mod, req.owner.revision, req.thread) : fail(errc::kNotFound, "the module was unloaded");
    } else if (req.kind == request_kind::kTask) {
        out = collect_results(req.thread, 1, *outcome);
        if (task_record* t = task(req.task_key)) {
            const int n = *outcome;
            auto packed = protect(state_, [&] {
                luaL_checkstack(state_, n + 3, "rhp: too many task results");
                lua_xmove(req.thread, state_, n); // the finished coroutine holds exactly its results
                t->results_ref = pack_top(state_, n);
            });
            if (!packed) {
                out = std::unexpected{std::move(packed).error()};
            }
        }
    }

    if (!out && out.error().where.empty()) {
        out.error().where = where_of(req);
    }
    const task_record* t = req.kind == request_kind::kTask ? task(req.task_key) : nullptr;
    const bool cancelled_task = t != nullptr && t->cancel_requested;
    // The coroutine closes (its to-be-closed variables run) and the request ends (a task's record
    // gets its outcome, joiners wake) before any policy undoes effects: undoing a task's own ledger
    // entry must not turn its failure into a cancellation. A coroutine that returned normally to a
    // caller that keeps it is only emptied: the caller's next handler runs in it.
    const bool reuse = keepable && out.has_value() && !closing_lua_ && lua_status(req.thread) == LUA_OK;
    if (reuse) {
        lua_settop(req.thread, 0);
    } else {
        close_thread(req, !out.has_value());
    }
    request_ended(req, &out, false);
    if (!out) {
        if (req.kind == request_kind::kExec) {
            (void)ledger_.revert_request(scratch_, req.id); // only this request's effects
        } else if (req.kind == request_kind::kLoad && mod != nullptr && mod->pending && mod->pending->revision == req.owner.revision) {
            abort_reload(*mod); // the old revision is untouched
        } else if (cancelled_task) {
            // a cancelled task: not a failure
        } else if (is_handler(req.kind)) {
            handler_failed_or_defer(req, out.error());
        } else {
            fault_or_defer(req.owner, out.error());
        }
    }
    if (req.suspended_once) {
        finished_.emplace_back(req.id, out);
    }
    if (reuse) {
        *kept = true;
        return out;
    }
    if (keepable) {
        node = take_unlisted(req);
    }
    recycle(std::move(node));
    return out;
}

void sandbox_impl::close_thread(request_record& req, bool failed) noexcept {
    if (failed) {
        // Runs the pending to-be-closed variables of a coroutine that didn't return normally.
        (void)protect(state_, [&] {
            run_budget local;
            const active_scope scope{*this, running_.empty() ? &local : nullptr, nullptr, nullptr, req.owner};
            (void)lua_closethread(req.thread, state_);
        });
    }
    // A coroutine that returned normally is reusable: empty it and keep it for the next request.
    if (!failed && !closing_lua_ && lua_status(req.thread) == LUA_OK && spare_threads_.size() < kSpareRequests) {
        lua_settop(req.thread, 0);
        spare_threads_.emplace_back(req.thread, req.thread_ref); // reserved in the constructor: no allocation
    } else {
        luaL_unref(state_, LUA_REGISTRYINDEX, req.thread_ref);
    }
    req.thread_ref = kNoRef;
    req.thread = nullptr;
}

result<void> sandbox_impl::call_sync(const effect_owner& owner, int nargs, int nresults) {
    const int base = lua_gettop(state_) - nargs - 1;
    result<void> called = run_as(owner, [&] { return stack{state_}.call(nargs, nresults); });
    if (!called) {
        lua_settop(state_, base); // a stop after the call returned: its results go (a failed call left none)
    }
    return called;
}

value_list sandbox_impl::collect_results(lua_State* L, int first, int last) {
    value_list out;
    out.reserve(static_cast<std::size_t>(std::max(0, last - first + 1)));
    const stack s{L};
    for (int i = first; i <= last; ++i) {
        if (append_scalar(out, L, i)) {
            continue; // without a result<value> each
        }
        auto v = s.to_value(i);
        if (v) {
            out.push_back(std::move(*v));
        } else {
            out.emplace_back(std::format("{}: {}", luaL_typename(L, i), lua_topointer(L, i)));
        }
    }
    return out;
}

// ---- the end of a request ---------------------------------------------------------------------------

void sandbox_impl::request_ended(request_record& req, const result<value_list>* outcome, bool abandoned) noexcept {
    stop_waiting(req);
    if (debugger_ && debugger_->step && debugger_->step->request == req.id) {
        debugger_->step.reset(); // a step that ran off the end of its request
        rearm_all();
    }
    if (req.resume_ref != kNoRef) {
        luaL_unref(state_, LUA_REGISTRYINDEX, req.resume_ref);
        req.resume_ref = kNoRef;
    }
    if (req.schedule_key != 0) {
        if (const auto it = schedule_.find(req.schedule_key); it != schedule_.end() && it->second.active == req.id) {
            it->second.active = {};
        }
    }
    if (req.kind == request_kind::kTask) {
        finish_task(req, outcome, abandoned);
    }
}

// ---- handler failures ----------------------------------------------------------------------------

void sandbox_impl::handler_failed_or_defer(const request_record& req, error err) {
    pending_failure f;
    f.owner = req.owner;
    f.kind = req.kind;
    f.source = req.source;
    f.handler_seq = req.handler_seq;
    // The state's memory is shared: a module that exhausted it would keep failing every handler.
    f.policy = req.budget.sticky == sticky_stop::kMemory ? handler_error_policy::kFault : req.policy;
    f.err = std::move(err);
    if (running_.empty()) {
        apply_failure(std::move(f));
    } else {
        pending_failures_.push_back(std::move(f)); // undo nothing while a run is active
    }
}

void sandbox_impl::apply_failure(pending_failure f) {
    ++handler_failures_;
    const module_record* mod = record(f.owner.module);
    handler_failure report;
    report.request = f.owner.request;
    report.module = f.owner.module;
    report.module_name = mod != nullptr ? mod->name : std::string{};
    switch (f.kind) {
    case request_kind::kFrame: report.kind = handler_kind::kFrame; break;
    case request_kind::kEvent: report.kind = handler_kind::kEvent; break;
    case request_kind::kTask: report.kind = handler_kind::kTask; break;
    default: report.kind = handler_kind::kTimer; break;
    }
    report.source = f.source;
    report.handler = f.handler_seq;
    report.action = f.policy;
    report.err = f.err;
    switch (f.policy) {
    case handler_error_policy::kFault: fault(f.owner, f.err); break;
    case handler_error_policy::kRemove:
        (void)ledger_.revert_request(f.owner.module, f.owner.request);
        if (f.handler_seq != 0) {
            (void)ledger_.revert_entry(f.handler_seq);
        }
        break;
    case handler_error_policy::kReport: (void)ledger_.revert_request(f.owner.module, f.owner.request); break;
    }
    // Lua hears about it through rhp.handler_failed, except about its own handlers' failures.
    if (f.source != kHandlerFailedEvent) {
        value::map info;
        info.emplace_back(value{"module"}, value{report.module_name});
        info.emplace_back(value{"kind"}, value{std::string{to_string(report.kind)}});
        info.emplace_back(value{"source"}, value{report.source});
        info.emplace_back(value{"id"}, value{static_cast<std::int64_t>(report.handler)});
        info.emplace_back(value{"action"}, value{std::string{to_string(report.action)}});
        info.emplace_back(value{"code"}, value{std::string{to_string(report.err.code)}});
        info.emplace_back(value{"message"}, value{report.err.message});
        info.emplace_back(value{"where"}, value{report.err.where});
        info.emplace_back(value{"traceback"}, value{report.err.traceback});
        (void)queue_script_event(kHandlerFailedEvent, module_id{}, value_list{value{std::move(info)}});
    }
    failure_reports_.push_back(std::move(report));
}

void sandbox_impl::report_failures() {
    for (auto& f : std::exchange(failure_reports_, {})) {
        if (options_.on_handler_error) {
            options_.on_handler_error(f);
        } else {
            output_for(f.request, f.module,
                       std::format("[handler failed] {} ({} {}): {} ({})", f.module_name.empty() ? "?" : f.module_name, f.kind, f.source, f.err, f.action));
        }
    }
}

// ---- deferred work -----------------------------------------------------------------------------------

bool sandbox_impl::defer_if_running(std::function<void()> op) {
    if (running_.empty()) {
        return false;
    }
    deferred_.push_back(std::move(op));
    return true;
}

void sandbox_impl::drain() {
    if (!running_.empty()) {
        return;
    }
    // Nothing queued (the usual case: twice per call, exec and pump): no lock, no swaps. Every list
    // the body below works through is in this test; a cancel queued by another thread sets the flag.
    if (!cancel_ids_pending_.load(std::memory_order_acquire) && pending_faults_.empty() && pending_failures_.empty() && deferred_.empty() &&
        collected_tasks_.empty() && failure_reports_.empty() && listener_calls_.empty() && finished_.empty()) {
        return;
    }
    std::vector<request_id> cancels;
    {
        const std::scoped_lock lock{inbox_mutex_};
        cancels.swap(cancel_ids_);
        cancel_ids_pending_.store(false, std::memory_order_release);
    }
    for (const request_id id : cancels) {
        if (const auto it = requests_.find(id); it != requests_.end() && !it->second->running) {
            (void)complete(*it->second, std::unexpected{make_error(errc::kCancelled, "script cancelled")});
        }
    }
    for (auto& [owner, err] : std::exchange(pending_faults_, {})) {
        fault(owner, std::move(err));
    }
    for (auto& f : std::exchange(pending_failures_, {})) {
        apply_failure(std::move(f));
    }
    for (auto& op : std::exchange(deferred_, {})) {
        op();
    }
    for (const std::uint64_t key : std::exchange(collected_tasks_, {})) {
        if (task_record* t = task(key)) {
            if (t->handles > 0) {
                --t->handles;
            }
            if (t->handles == 0 && t->finished) {
                luaL_unref(state_, LUA_REGISTRYINDEX, t->results_ref);
                tasks_.erase(key);
            }
        }
    }
    // Last: these callbacks may re-enter the sandbox.
    report_failures();
    call_listeners();
    if (options_.on_result) {
        for (auto& [id, r] : std::exchange(finished_, {})) {
            options_.on_result(id, r);
        }
    } else {
        finished_.clear();
    }
}

// ---- the frame ---------------------------------------------------------------------------------------

void sandbox_impl::resume_ready() {
    const steady::time_point now = script_now();
    if (!requests_dirty_ && frame_ < requests_next_frame_ && now < requests_next_wake_) {
        return; // every suspended request sleeps on: no walk over them
    }
    std::vector<request_id> ready;
    for (const auto& [id, req] : requests_) {
        if (!req->running && (req->woken || (req->wake_frame != 0 && frame_ >= req->wake_frame) || (req->wake_time && now >= *req->wake_time))) {
            ready.push_back(id);
        }
    }
    // Round robin from the request after the one resumed last, so with slicing on a busy request
    // can't take every slice.
    std::ranges::rotate(ready, std::ranges::upper_bound(ready, last_resumed_));
    for (const request_id id : ready) {
        if (slice_deadline_ && steady::now() >= *slice_deadline_) {
            requests_dirty_ = true;
            return; // the rest stay ready for the next pump()
        }
        if (const auto it = requests_.find(id); it != requests_.end() && !it->second->running) {
            last_resumed_ = id;
            request_record& req = *it->second;
            const int nargs = req.start_args >= 0 ? std::exchange(req.start_args, -1) : 0; // a task's first resume
            (void)step(req, nargs);
        }
    }
    requests_dirty_ = false;
    requests_next_frame_ = std::numeric_limits<std::uint64_t>::max();
    requests_next_wake_ = steady::time_point::max();
    for (const auto& [id, req] : requests_) {
        if (req->running) {
            continue;
        }
        if (req->woken) {
            requests_next_frame_ = 0; // woken during this pass: resumes at the next one
        }
        if (req->wake_frame != 0) {
            requests_next_frame_ = std::min(requests_next_frame_, req->wake_frame);
        }
        if (req->wake_time) {
            requests_next_wake_ = std::min(requests_next_wake_, *req->wake_time);
        }
    }
}

} // namespace Rhp::script::detail
