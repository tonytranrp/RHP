// The hook: where it is armed and with what count and mask (cancels and limits at safe points, the
// meter, the profiler and line events on every instruction), the count hook itself (limits, cancels,
// time slices, profiler samples) and the stops it makes sticky.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <limits>
#include <mutex>

#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/script/puc_lua/lua_internals.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/tools.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

namespace {

constexpr std::uint32_t kDefaultCheckInterval = 1'000;

} // namespace

// ---- arming ------------------------------------------------------------------------------------

std::uint32_t sandbox_impl::check_interval() const noexcept {
    const std::uint32_t interval = options_.limits.cancel_check_instructions != 0 ? options_.limits.cancel_check_instructions : kDefaultCheckInterval;
    // Lua takes the hook count as an int: a larger one would turn negative, which switches the hook off.
    return std::min(interval, static_cast<std::uint32_t>((std::numeric_limits<int>::max)()));
}

bool sandbox_impl::hook_everywhere() const noexcept {
    const Rhp::limits& l = options_.limits;
    return l.instructions != 0 || l.wall_ms != 0 || l.slice_us != 0 || l.cancel_checks == cancel_scope::kEverything;
}

std::uint32_t sandbox_impl::hook_count() const noexcept {
    return profiler_ ? std::min(check_interval(), profiler_->options.interval) : check_interval();
}

// `armed`: the run checks for cancels and limits. The profiler counts everywhere; the debugger adds
// line events.
void sandbox_impl::arm_hook(lua_State* L, bool armed) noexcept {
    credit_hook_progress(L); // lua_sethook restarts the countdown: the meter keeps what ran of it
    install_hook(L, hook_mask(armed), static_cast<int>(hook_count()));
}

// Line events: every line, or by function (internals::set_line_events switches them without
// restarting the instruction countdown, so limits and cancels keep working in loops of calls).
int sandbox_impl::hook_mask(bool armed) const noexcept {
    return (armed || counts_everywhere() ? LUA_MASKCOUNT : 0) | line_mask();
}

// Cancels and limits only need a bound, so a hook that does nothing else counts at safe points (loop
// back-edges and calls: internals::set_safepoint_hook) and costs nothing in straight-line code. The
// meter, the profiler and line events need every instruction: lua_sethook.
bool sandbox_impl::counts_at_safepoints(int mask) const noexcept {
    return mask == LUA_MASKCOUNT && !counts_everywhere();
}

void sandbox_impl::install_hook(lua_State* L, int mask, int count) noexcept {
    if (mask == 0) {
        lua_sethook(L, nullptr, 0, 0);
    } else if (counts_at_safepoints(mask)) {
        internals::set_safepoint_hook(L, &sandbox_impl::count_hook, count);
    } else {
        lua_sethook(L, &sandbox_impl::count_hook, mask, count);
    }
}

void sandbox_impl::rearm_all() noexcept {
    if (hook_dirty_) {
        return; // a stop fires on every instruction until the outermost run ends; that rearms
    }
    reset_hook();
    for (const auto& [id, req] : requests_) {
        if (req->thread != nullptr) {
            arm_hook(req->thread, armed_for(*req));
        }
    }
}

bool sandbox_impl::checked_now() const noexcept {
    if (hook_everywhere()) {
        return true;
    }
    if (!checks_requests()) {
        return false;
    }
    if (checked_depth_ != 0) {
        return true;
    }
    const active_run& top = running_.back();
    return top.request != nullptr && top.request->checked;
}

void sandbox_impl::sync_hook(lua_State* L, bool checked) noexcept {
    const int mask = hook_mask(checked);
    const int count = static_cast<int>(hook_count());
    // By function, a thread's line events come and go with its calls: either is in step.
    const int ignored = lines_wanted() == line_mode::kByFunction ? LUA_MASKLINE : 0;
    const bool at_safepoints = internals::hook_at_safepoints(L);
    const int current = at_safepoints ? LUA_MASKCOUNT : lua_gethookmask(L);
    if ((current | ignored) == mask && at_safepoints == counts_at_safepoints(mask) && ((mask & LUA_MASKCOUNT) == 0 || lua_gethookcount(L) == count)) {
        return;
    }
    credit_hook_progress(L);
    install_hook(L, mask, count);
}

bool sandbox_impl::checks_requests() const noexcept {
    return options_.limits.cancel_checks != cancel_scope::kNone;
}

void sandbox_impl::reset_hook() noexcept {
    arm_hook(state_, hook_everywhere() || (checked_depth_ != 0 && checks_requests()));
}

// A stop already switched the hook to every instruction (hook_dirty_): leave it, the outermost run
// resets it when it ends.
void sandbox_impl::enter_checked() noexcept {
    if (checked_depth_++ == 0 && checks_requests() && !hook_everywhere() && !hook_dirty_) {
        arm_hook(state_, true);
    }
}

void sandbox_impl::leave_checked() noexcept {
    if (--checked_depth_ == 0 && checks_requests() && !hook_everywhere() && !hook_dirty_) {
        arm_hook(state_, false);
    }
}

// ---- line events ---------------------------------------------------------------------------------

sandbox_impl::line_mode sandbox_impl::lines_wanted() const noexcept {
    if (coverage_ != nullptr || (debugger_ && debugger_->wants_every_line())) {
        return line_mode::kEverywhere;
    }
    return debugger_ && debugger_->wants_lines() ? line_mode::kByFunction : line_mode::kNone;
}

int sandbox_impl::line_mask() const noexcept {
    switch (lines_wanted()) {
    case line_mode::kNone: return 0;
    case line_mode::kEverywhere: return LUA_MASKLINE;
    case line_mode::kByFunction: return LUA_MASKLINE | LUA_MASKCALL | LUA_MASKRET; // lines until the next call or return decides
    }
    return 0;
}

// ---- the count hook --------------------------------------------------------------------------------

void sandbox_impl::check_cancels() noexcept {
    if (cancel_running_.exchange(false, std::memory_order_acq_rel)) {
        for (active_run& run : running_) {
            if (run.budget != nullptr && run.budget->sticky == sticky_stop::kNone) {
                run.budget->sticky = sticky_stop::kCancelled;
            }
        }
    }
    if (!cancel_ids_pending_.load(std::memory_order_acquire)) {
        return;
    }
    const std::scoped_lock lock{inbox_mutex_};
    // Running requests stop here; suspended ones are ended before they resume (take_cancel) or by
    // the next drain(), so their ids stay pending.
    std::erase_if(cancel_ids_, [this](request_id id) {
        for (active_run& run : running_) {
            if (run.request != nullptr && run.request->id == id) {
                if (run.budget->sticky == sticky_stop::kNone) {
                    run.budget->sticky = sticky_stop::kCancelled;
                }
                return true;
            }
        }
        return false;
    });
    cancel_ids_pending_.store(!cancel_ids_.empty(), std::memory_order_release);
}

bool sandbox_impl::take_cancel(request_id id) {
    if (!cancel_ids_pending_.load(std::memory_order_acquire)) {
        return false;
    }
    const std::scoped_lock lock{inbox_mutex_};
    const auto it = std::ranges::find(cancel_ids_, id);
    if (it == cancel_ids_.end()) {
        return false;
    }
    cancel_ids_.erase(it);
    cancel_ids_pending_.store(!cancel_ids_.empty(), std::memory_order_release);
    return true;
}

void sandbox_impl::count_hook(lua_State* L, lua_Debug* ar) {
    auto& self = impl_of(L);
    if (ar->event == LUA_HOOKLINE) {
        self.line_event(L, ar);
        return;
    }
    if (ar->event == LUA_HOOKCALL || ar->event == LUA_HOOKTAILCALL || ar->event == LUA_HOOKRET) {
        self.scope_lines(L, ar);
        return;
    }
    if (self.running_.empty()) {
        return; // a handler called from game code runs inside run_handler, so this is GC / setup code
    }
    // The instructions since this thread's last count event: its own count, which may be older than
    // hook_count() (a thread armed before the profiler started or stopped).
    const auto elapsed = static_cast<std::uint64_t>(lua_gethookcount(L));
    if (self.metering_) {
        self.meter_instructions_ += elapsed;
    }
    if (!self.hook_dirty_) { // after a stop the hook fires on every instruction until the run ends
        const bool checked = self.checked_now();
        if (self.profiler_) {
            self.profile_tick(L, elapsed);
        }
        self.sync_hook(L, checked);
        if (!checked) {
            return; // armed for the profiler only, or a thread whose hook was out of date
        }
    }
    self.check_cancels();
    const auto& limits = self.options_.limits;
    const bool timed = limits.wall_ms != 0 || self.slice_deadline_.has_value();
    const steady::time_point now = timed ? steady::now() : steady::time_point{};
    sticky_stop stop = sticky_stop::kNone;
    for (active_run& run : self.running_) {
        if (run.budget == nullptr) {
            continue;
        }
        run_budget& budget = *run.budget;
        if (budget.sticky == sticky_stop::kNone) {
            if (limits.instructions != 0 && (budget.instructions += elapsed) > limits.instructions) {
                budget.sticky = sticky_stop::kBudget;
            } else if (limits.wall_ms != 0 && budget.active + (now - run.started) > std::chrono::milliseconds{limits.wall_ms}) {
                budget.sticky = sticky_stop::kWall;
            }
        }
        if (budget.sticky != sticky_stop::kNone) {
            stop = budget.sticky; // the innermost stopped run decides the error
        }
    }
    if (stop != sticky_stop::kNone) {
        // From now on fire on every instruction (this thread and the main one), so a script that keeps
        // re-entering pcall can't swallow the stop between two widely spaced hook ticks.
        self.hook_dirty_ = true;
        lua_sethook(L, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
        lua_sethook(self.state_, &sandbox_impl::count_hook, LUA_MASKCOUNT, 1);
        stack{L}.raise(self.sticky_error(stop));
    }
    // End of the time slice: yield the request's own thread (never a coroutine it created, never
    // across a C call); it continues at the next pump().
    if (self.slice_deadline_ && now >= *self.slice_deadline_) {
        const active_run& top = self.running_.back();
        if (top.thread == L && top.request != nullptr && lua_isyieldable(L) != 0) {
            (void)lua_yield(L, 0);
        }
    }
}

error sandbox_impl::sticky_error(sticky_stop stop) const {
    const auto& limits = options_.limits;
    switch (stop) {
    case sticky_stop::kCancelled: return make_error(errc::kCancelled, "script cancelled");
    case sticky_stop::kBudget: return make_error(errc::kBudgetExceeded, std::format("instruction limit of {} exceeded", limits.instructions));
    case sticky_stop::kMemory: return make_error(errc::kMemoryExceeded, std::format("memory limit of {} bytes exceeded", limits.memory));
    case sticky_stop::kWall: return make_error(errc::kTimeout, std::format("wall time limit of {} ms exceeded", limits.wall_ms));
    case sticky_stop::kNone: break;
    }
    return make_error(errc::kRuntime);
}

} // namespace Rhp::script::detail
