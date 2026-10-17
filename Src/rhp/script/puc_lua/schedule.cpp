// Timers and frame callbacks: rhp.timer / rhp.after / rhp.every / rhp.every_frame(s), their control
// (rhp.pause / rhp.resume / rhp.reschedule / rhp.timers) and firing them from pump().

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>

namespace Rhp::script::detail {

namespace {

class schedule_effect final : public effect {
public:
    schedule_effect(sandbox_impl& box, std::uint64_t key) : box_(&box), key_(key) {}
    schedule_effect(const schedule_effect&) = delete;
    schedule_effect& operator=(const schedule_effect&) = delete;
    ~schedule_effect() override { box_->remove_schedule(key_); }

    void undo() override { box_->remove_schedule(key_); }

private:
    sandbox_impl* box_;
    std::uint64_t key_;
};

void check_function(lua_State* L, int index, std::string_view where) {
    if (lua_type(L, index) != LUA_TFUNCTION) {
        const stack s{L};
        s.raise(make_error(errc::kTypeMismatch, std::format("expected function, got {}", s.type_name(index)), std::string{where}));
    }
}

std::uint64_t checked_id(lua_State* L, int index, std::string_view where) {
    const stack s{L};
    const auto id = s.to_integer(index);
    if (!id || *id <= 0) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected an id, got {}", s.type_name(index)), std::string{where}));
    }
    return static_cast<std::uint64_t>(*id);
}

std::uint64_t checked_frames(lua_State* L, int index, std::string_view where) {
    const stack s{L};
    const auto n = s.to_integer(index);
    if (!n || *n < 1 || *n > 1'000'000'000'000'000) {
        s.raise(make_error(errc::kInvalidArgument, std::format("expected a frame count from 1 to 1e15, got {}", s.type_name(index)), std::string{where}));
    }
    return static_cast<std::uint64_t>(*n);
}

double to_ms(steady::duration d) {
    return std::chrono::duration<double, std::milli>{d}.count();
}

} // namespace

// ---- Lua-side builtins ---------------------------------------------------------------------------

// rhp.timer(ms, fn [, repeating]) → id: calls fn as its own request after ms (every ms if repeating).
int lua_rhp_timer(lua_State* L) {
    const double ms = checked_ms(L, 1, "rhp.timer");
    check_function(L, 2, "rhp.timer");
    const bool repeating = lua_toboolean(L, 3) != 0;
    auto& impl = impl_of(L);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.add_timer(L, ms, 2, repeating, handler_opts{}, repeating ? "rhp.timer (repeating)" : "rhp.timer")));
    return 1;
}

// rhp.after(ms, fn [, opts]) → id: one call after ms.
int lua_rhp_after(lua_State* L) {
    const double ms = checked_ms(L, 1, "rhp.after");
    check_function(L, 2, "rhp.after");
    auto& impl = impl_of(L);
    const handler_opts opts = impl.read_opts(L, 3, "rhp.after", sandbox_impl::kOptOnError);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.add_timer(L, ms, 2, false, opts, std::format("rhp.after {} ms", ms))));
    return 1;
}

// rhp.every(ms, fn [, opts]) → id: a call every ms, at most once per pump(); opts.times limits them.
int lua_rhp_every(lua_State* L) {
    const double ms = checked_ms(L, 1, "rhp.every");
    check_function(L, 2, "rhp.every");
    auto& impl = impl_of(L);
    const handler_opts opts = impl.read_opts(L, 3, "rhp.every", sandbox_impl::kOptTimes | sandbox_impl::kOptOnError);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.add_timer(L, ms, 2, true, opts, std::format("rhp.every {} ms", ms))));
    return 1;
}

// rhp.every_frame(fn [, opts]) → id: a call every pump().
int lua_rhp_every_frame(lua_State* L) {
    check_function(L, 1, "rhp.every_frame");
    auto& impl = impl_of(L);
    const handler_opts opts = impl.read_opts(L, 2, "rhp.every_frame", sandbox_impl::kOptTimes | sandbox_impl::kOptOnError);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.add_frames(L, 1, 1, opts)));
    return 1;
}

// rhp.every_frames(n, fn [, opts]) → id: a call every n pump() calls (the first n pumps from now).
int lua_rhp_every_frames(lua_State* L) {
    const std::uint64_t n = checked_frames(L, 1, "rhp.every_frames");
    check_function(L, 2, "rhp.every_frames");
    auto& impl = impl_of(L);
    const handler_opts opts = impl.read_opts(L, 3, "rhp.every_frames", sandbox_impl::kOptTimes | sandbox_impl::kOptOnError);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.add_frames(L, n, 2, opts)));
    return 1;
}

int lua_rhp_pause(lua_State* L) {
    impl_of(L).set_paused(L, checked_id(L, 1, "rhp.pause"), true);
    return 0;
}

int lua_rhp_resume(lua_State* L) {
    impl_of(L).set_paused(L, checked_id(L, 1, "rhp.resume"), false);
    return 0;
}

// rhp.reschedule(id, interval): a timer's ms or a frame callback's frames; restarts the countdown.
int lua_rhp_reschedule(lua_State* L) {
    const std::uint64_t id = checked_id(L, 1, "rhp.reschedule");
    const stack s{L};
    const auto interval = s.to_number(2);
    if (!interval || !(*interval >= 0.0)) {
        s.raise(make_error(errc::kInvalidArgument, std::format("expected an interval >= 0, got {}", s.type_name(2)), "rhp.reschedule"));
    }
    impl_of(L).reschedule(L, id, *interval);
    return 0;
}

int lua_rhp_timers(lua_State* L) {
    impl_of(L).push_timers(L);
    return 1;
}

// ---- options -------------------------------------------------------------------------------------

handler_opts sandbox_impl::read_opts(lua_State* L, int index, std::string_view where, unsigned allowed) {
    handler_opts out;
    if (lua_isnoneornil(L, index)) {
        return out;
    }
    const stack s{L};
    if (lua_type(L, index) != LUA_TTABLE) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected an options table, got {}", s.type_name(index)), std::string{where}));
    }
    index = lua_absindex(L, index);
    std::optional<error> failure;
    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        // key at -2, value at -1
        const auto key = lua_type(L, -2) == LUA_TSTRING ? s.to_string(-2) : std::nullopt;
        if (!failure) {
            if (key && *key == "times" && (allowed & kOptTimes) != 0) {
                const auto n = s.to_integer(-1);
                if (!n || *n < 1 || *n > 0xFFFF'FFFFll) {
                    failure = make_error(errc::kInvalidArgument, "times must be an integer >= 1", std::string{where});
                } else {
                    out.times = static_cast<std::uint32_t>(*n);
                }
            } else if (key && *key == "priority" && (allowed & kOptPriority) != 0) {
                const auto n = s.to_integer(-1);
                if (!n) {
                    failure = make_error(errc::kInvalidArgument, "priority must be an integer", std::string{where});
                } else {
                    out.priority = *n;
                }
            } else if (key && *key == "on_error" && (allowed & kOptOnError) != 0) {
                const auto v = s.to_string(-1);
                if (v && *v == "report") {
                    out.on_error = handler_error_policy::kReport;
                } else if (v && *v == "remove") {
                    out.on_error = handler_error_policy::kRemove;
                } else if (v && *v == "fault") {
                    out.on_error = handler_error_policy::kFault;
                } else {
                    failure = make_error(errc::kInvalidArgument, "on_error must be \"report\", \"remove\" or \"fault\"", std::string{where});
                }
            } else {
                failure = make_error(errc::kInvalidArgument, key ? std::format("unknown option '{}'", *key) : std::string{"option keys are names"},
                                     std::string{where});
            }
        }
        lua_pop(L, 1);
    }
    if (failure) {
        s.raise(*failure);
    }
    return out;
}

// ---- entries -------------------------------------------------------------------------------------

void sandbox_impl::refuse_while_closing(lua_State* L, std::string_view where) const {
    if (closing_lua_) {
        stack{L}.raise(make_error(errc::kUnloaded, "the sandbox is closing", std::string{where}));
    }
}

std::uint64_t sandbox_impl::add_timer(lua_State* L, double ms, int fn_index, bool repeating, const handler_opts& opts, std::string label) {
    refuse_while_closing(L, "rhp.timer");
    lua_pushvalue(L, fn_index);
    const int fn_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    const std::uint64_t key = ++schedule_keys_;
    schedule_entry entry;
    entry.owner = current_;
    entry.fn_ref = fn_ref;
    entry.kind = schedule_kind::kTimer;
    entry.repeating = repeating;
    entry.interval = milliseconds(ms);
    entry.due = script_now() + entry.interval;
    entry.times = repeating ? opts.times : std::optional<std::uint32_t>{1};
    entry.policy = opts.on_error.value_or(options_.handler_errors);
    schedule_.emplace(key, std::move(entry));
    const std::uint64_t seq = record_effect(std::move(label), std::make_unique<schedule_effect>(*this, key));
    if (const auto it = schedule_.find(key); it != schedule_.end()) {
        it->second.seq = seq;
    }
    return seq;
}

std::uint64_t sandbox_impl::add_frames(lua_State* L, std::uint64_t every, int fn_index, const handler_opts& opts) {
    refuse_while_closing(L, "rhp.every_frame");
    lua_pushvalue(L, fn_index);
    const int fn_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    const std::uint64_t key = ++schedule_keys_;
    schedule_entry entry;
    entry.owner = current_;
    entry.fn_ref = fn_ref;
    entry.kind = schedule_kind::kFrames;
    entry.repeating = true;
    entry.every = every;
    entry.next_frame = frame_ + every;
    entry.times = opts.times;
    entry.policy = opts.on_error.value_or(options_.handler_errors);
    schedule_.emplace(key, std::move(entry));
    const std::uint64_t seq =
        record_effect(every == 1 ? std::string{"rhp.every_frame"} : std::format("rhp.every_frames {}", every), std::make_unique<schedule_effect>(*this, key));
    if (const auto it = schedule_.find(key); it != schedule_.end()) {
        it->second.seq = seq;
    }
    return seq;
}

void sandbox_impl::remove_schedule(std::uint64_t key) noexcept {
    const auto it = schedule_.find(key);
    if (it == schedule_.end()) {
        return;
    }
    luaL_unref(state_, LUA_REGISTRYINDEX, it->second.fn_ref);
    schedule_.erase(it);
}

schedule_entry* sandbox_impl::schedule_by_seq(std::uint64_t seq) noexcept {
    for (auto& [key, entry] : schedule_) {
        if (entry.seq == seq) {
            return &entry;
        }
    }
    return nullptr;
}

void sandbox_impl::set_paused(lua_State* L, std::uint64_t seq, bool paused) {
    const std::string_view where = paused ? "rhp.pause" : "rhp.resume";
    if (owns_entry(seq)) {
        if (schedule_entry* e = schedule_by_seq(seq)) {
            if (e->paused == paused) {
                return;
            }
            e->paused = paused;
            if (e->kind == schedule_kind::kTimer) {
                const steady::time_point now = script_now();
                if (paused) {
                    e->remaining = e->due > now ? e->due - now : steady::duration{};
                } else {
                    e->due = now + e->remaining;
                }
            } else if (paused) {
                e->remaining_frames = e->next_frame > frame_ ? e->next_frame - frame_ : 0;
            } else {
                e->next_frame = frame_ + std::max<std::uint64_t>(e->remaining_frames, 1);
            }
            return;
        }
        if (subscription* sub = subscription_by_seq(seq)) {
            sub->paused = paused;
            return;
        }
    }
    stack{L}.raise(make_error(errc::kNotFound, std::format("no timer, frame callback or subscription {} of this module", seq), std::string{where}));
}

void sandbox_impl::reschedule(lua_State* L, std::uint64_t seq, double interval) {
    schedule_entry* e = owns_entry(seq) ? schedule_by_seq(seq) : nullptr;
    if (e == nullptr) {
        if (owns_entry(seq) && subscription_by_seq(seq) != nullptr) {
            stack{L}.raise(make_error(errc::kInvalidArgument, "a subscription has no interval", "rhp.reschedule"));
        }
        stack{L}.raise(make_error(errc::kNotFound, std::format("no timer or frame callback {} of this module", seq), "rhp.reschedule"));
    }
    if (e->kind == schedule_kind::kTimer) {
        e->interval = milliseconds(interval);
        e->due = script_now() + e->interval;
        e->remaining = e->interval;
        return;
    }
    constexpr double kMaxFrames = 1e15; // far beyond any run; keeps the cast and frame_ + every in range
    if (interval < 1.0 || interval > kMaxFrames || interval != static_cast<double>(static_cast<std::uint64_t>(interval))) {
        stack{L}.raise(make_error(errc::kInvalidArgument, "a frame callback's interval is a frame count >= 1", "rhp.reschedule"));
    }
    e->every = static_cast<std::uint64_t>(interval);
    e->next_frame = frame_ + e->every;
    e->remaining_frames = e->every;
}

void sandbox_impl::push_timers(lua_State* L) {
    const steady::time_point now = script_now();
    lua_newtable(L);
    lua_Integer n = 0;
    for (const auto& [key, e] : schedule_) {
        if (e.owner.module != current_.module) {
            continue;
        }
        lua_createtable(L, 0, 9);
        lua_pushinteger(L, static_cast<lua_Integer>(e.seq));
        lua_setfield(L, -2, "id");
        if (e.kind == schedule_kind::kTimer) {
            lua_pushliteral(L, "timer");
            lua_setfield(L, -2, "kind");
            lua_pushnumber(L, to_ms(e.interval));
            lua_setfield(L, -2, "interval");
            lua_pushnumber(L, to_ms(e.paused ? e.remaining : (e.due > now ? e.due - now : steady::duration{})));
            lua_setfield(L, -2, "remaining");
        } else {
            lua_pushliteral(L, "frames");
            lua_setfield(L, -2, "kind");
            lua_pushinteger(L, static_cast<lua_Integer>(e.every));
            lua_setfield(L, -2, "interval");
            lua_pushinteger(L, static_cast<lua_Integer>(e.paused ? e.remaining_frames : (e.next_frame > frame_ ? e.next_frame - frame_ : 0)));
            lua_setfield(L, -2, "remaining");
        }
        lua_pushinteger(L, static_cast<lua_Integer>(e.runs));
        lua_setfield(L, -2, "runs");
        if (e.times) {
            lua_pushinteger(L, static_cast<lua_Integer>(*e.times));
            lua_setfield(L, -2, "times");
        }
        lua_pushboolean(L, e.repeating ? 1 : 0);
        lua_setfield(L, -2, "repeating");
        lua_pushboolean(L, e.paused ? 1 : 0);
        lua_setfield(L, -2, "paused");
        lua_pushboolean(L, e.active && requests_.contains(e.active) ? 1 : 0);
        lua_setfield(L, -2, "running");
        lua_rawseti(L, -2, ++n);
    }
}

// ---- firing --------------------------------------------------------------------------------------

// Frame callbacks first (registration order), then due timers (due order). Entries made while this
// runs wait for the next pump(); an entry an earlier call paused or rescheduled is checked again.
void sandbox_impl::fire_schedule() {
    const steady::time_point now = script_now();
    std::vector<std::uint64_t> frames;
    std::vector<std::pair<steady::time_point, std::uint64_t>> timers;
    for (const auto& [key, e] : schedule_) {
        if (e.paused) {
            continue;
        }
        if (e.kind == schedule_kind::kFrames) {
            if (frame_ >= e.next_frame) {
                frames.push_back(key);
            }
        } else if (e.due <= now) {
            timers.emplace_back(e.due, key);
        }
    }
    std::ranges::sort(timers);
    for (const std::uint64_t key : frames) {
        fire_entry(key, now);
    }
    for (const auto& [when, key] : timers) {
        fire_entry(key, now);
    }
}

void sandbox_impl::fire_entry(std::uint64_t key, steady::time_point now) {
    const auto it = schedule_.find(key);
    if (it == schedule_.end()) {
        return; // an earlier call removed it
    }
    schedule_entry& e = it->second;
    if (e.paused || (e.kind == schedule_kind::kFrames ? frame_ < e.next_frame : e.due > now)) {
        return; // paused or rescheduled by an earlier call
    }
    if (e.kind == schedule_kind::kFrames) {
        e.next_frame = frame_ + e.every;
    } else if (e.repeating) {
        e.due += e.interval;
        if (e.due <= now) {
            e.due = now + e.interval; // fell behind: no burst of catch-up calls
        }
    }
    if (e.active && requests_.contains(e.active)) {
        return; // its previous call is still suspended: no overlapping calls
    }
    ++e.runs;
    const bool last = !e.repeating || (e.times && e.runs >= *e.times);
    const effect_owner owner = e.owner;
    const std::uint64_t seq = e.seq;
    const handler_error_policy policy = e.policy;
    const bool frames = e.kind == schedule_kind::kFrames;
    const module_record* mod = record(owner.module);
    std::string label = std::format("{} ({})", mod != nullptr ? mod->name : "?", frames ? "frame callback" : "timer");
    lua_rawgeti(state_, LUA_REGISTRYINDEX, e.fn_ref);
    request_record& req = start_request(frames ? request_kind::kFrame : request_kind::kTimer, owner, std::move(label), 0, false);
    req.schedule_key = key;
    req.handler_seq = seq;
    req.policy = policy;
    req.source = frames ? "frame" : "timer";
    // Looked up again: start_request allocates, and a finalizer it triggers may have removed the entry.
    if (const auto again = schedule_.find(key); again != schedule_.end()) {
        again->second.active = req.id;
    }
    if (last) {
        (void)ledger_.revert_entry(seq); // spent once its last call starts (the function is on the coroutine)
    }
    (void)step(req, 0);
}

} // namespace Rhp::script::detail
