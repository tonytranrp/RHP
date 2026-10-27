// Subscriptions (rhp.on / rhp.once / rhp.on_error), script-defined events (rhp.publish),
// rhp.wait_event, the C++ listeners of script events and the sandbox's counters.

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/utils/fixed_string.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::script::detail {

namespace {

class subscription_effect final : public effect {
public:
    subscription_effect(sandbox_impl& box, std::string event, std::uint64_t key) : box_(&box), event_(std::move(event)), key_(key) {}
    subscription_effect(const subscription_effect&) = delete;
    subscription_effect& operator=(const subscription_effect&) = delete;
    ~subscription_effect() override { box_->unsubscribe(event_, key_); }

    void undo() override { box_->unsubscribe(event_, key_); }

private:
    sandbox_impl* box_;
    std::string event_;
    std::uint64_t key_;
};

std::string_view checked_name(lua_State* L, int index, std::string_view where) {
    const stack s{L};
    const auto event = s.to_string(index);
    if (!event) {
        s.raise(make_error(errc::kTypeMismatch, std::format("expected an event name, got {}", s.type_name(index)), std::string{where}));
    }
    return *event;
}

int subscribe_builtin(lua_State* L, std::string_view where, bool once) {
    const std::string event{checked_name(L, 1, where)};
    check_function(L, 2, where);
    auto& impl = impl_of(L);
    const handler_opts opts = impl.read_opts(L, 3, where, sandbox_impl::kOptPriority | sandbox_impl::kOptOnError);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.subscribe(L, event, 2, once, opts)));
    return 1;
}

int wait_event_k(lua_State* L, int /*status*/, lua_KContext /*ctx*/) {
    return impl_of(L).finish_wait_event(L);
}

} // namespace

// ---- Lua-side builtins ---------------------------------------------------------------------------

// rhp.on(event, handler [, opts]) → id: runs handler as its own request each time the event fires.
int lua_rhp_on(lua_State* L) {
    return subscribe_builtin(L, "rhp.on", false);
}

// rhp.once(event, handler [, opts]) → id: the same, removed after the first delivery.
int lua_rhp_once(lua_State* L) {
    return subscribe_builtin(L, "rhp.once", true);
}

// rhp.on_error(handler [, opts]) → id: rhp.on("rhp.handler_failed", handler).
int lua_rhp_on_error(lua_State* L) {
    check_function(L, 1, "rhp.on_error");
    auto& impl = impl_of(L);
    const handler_opts opts = impl.read_opts(L, 2, "rhp.on_error", sandbox_impl::kOptPriority | sandbox_impl::kOptOnError);
    lua_pushinteger(L, static_cast<lua_Integer>(impl.subscribe(L, kHandlerFailedEvent, 1, false, opts)));
    return 1;
}

// rhp.publish(event, ...) → queued: delivers copies of the values at the next pump().
int lua_rhp_publish(lua_State* L) {
    const std::string event{checked_name(L, 1, "rhp.publish")};
    lua_pushboolean(L, impl_of(L).publish(L, event, 2) ? 1 : 0);
    return 1;
}

// rhp.wait_event(event [, timeout_ms]) → true, ... | false, "timeout".
int lua_rhp_wait_event(lua_State* L) {
    // A view of argument 1 (it stays on the stack): this function yields, and a yield may skip its
    // frame without destructors (cmake/lua/lua_cxx.cpp), so nothing here may own memory.
    const std::string_view event = checked_name(L, 1, "rhp.wait_event");
    std::optional<double> timeout;
    if (!lua_isnoneornil(L, 2)) {
        timeout = checked_ms(L, 2, "rhp.wait_event");
    }
    return impl_of(L).wait_event(L, event, timeout);
}

int lua_rhp_stats(lua_State* L) {
    impl_of(L).push_stats(L);
    return 1;
}

// ---- script_listener_table -----------------------------------------------------------------------

Rhp::subscription sandbox_impl::on_script_event(std::string_view name, script_event_fn fn) {
    const std::uint64_t id = listeners_->add(std::string{name}, std::move(fn));
    return Rhp::subscription{std::weak_ptr<subscribable>{listeners_}, id};
}

// ---- interest ------------------------------------------------------------------------------------

event_state* sandbox_impl::resolve_event(lua_State* L, std::string_view event, std::string_view where) {
    std::optional<error> failure;
    event_state* state = nullptr;
    {
        auto found = find_event(event);
        if (found) {
            state = (*found)->state;
        } else if (found.error().code != errc::kNotFound) {
            failure = std::move(found).error(); // two C++ events share the name
        } else if (!utils::is_dotted_name(event)) {
            failure = make_error(errc::kInvalidArgument, std::format("'{}' is not an event name (dotted lowercase, e.g. game.round_over)", event));
        }
    }
    if (failure) {
        failure->where = std::string{where};
        stack{L}.raise(*failure);
    }
    return state;
}

void sandbox_impl::acquire_interest(std::string_view event, event_state* state) {
    if (state != nullptr && !attached_.contains(event)) {
        attached_.emplace(std::string{event}, state);
        state->attach(this);
    }
}

void sandbox_impl::release_interest(const std::string& event) noexcept {
    const auto subs = subscriptions_.find(event);
    const auto waits = waiters_.find(event);
    if ((subs != subscriptions_.end() && !subs->second.empty()) || (waits != waiters_.end() && !waits->second.empty())) {
        return;
    }
    if (subs != subscriptions_.end()) {
        subscriptions_.erase(subs);
        ++subscriptions_version_;
    }
    if (waits != waiters_.end()) {
        waiters_.erase(waits);
    }
    if (const auto attached = attached_.find(event); attached != attached_.end()) {
        attached->second->detach(this);
        attached_.erase(attached);
    }
}

// ---- subscriptions -------------------------------------------------------------------------------

std::uint64_t sandbox_impl::subscribe(lua_State* L, std::string_view event, int fn_index, bool once, const handler_opts& opts) {
    refuse_while_closing(L, once ? "rhp.once" : "rhp.on");
    event_state* state = resolve_event(L, event, once ? "rhp.once" : "rhp.on");
    lua_pushvalue(L, fn_index);
    const int fn_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    const std::uint64_t key = ++subscription_keys_;
    auto& subs = subscriptions_[std::string{event}];
    // Higher priorities first; equal priorities keep subscription order.
    const auto at = std::ranges::find_if(subs, [&](const subscription& s) { return s.priority < opts.priority; });
    subscription sub;
    sub.key = key;
    sub.owner = current_;
    sub.fn_ref = fn_ref;
    sub.priority = opts.priority;
    sub.once = once;
    sub.policy = opts.on_error.value_or(options_.handler_errors);
    subs.insert(at, std::move(sub));
    ++subscriptions_version_;
    acquire_interest(event, state);
    std::string label = std::format("{} {}", once ? "rhp.once" : "rhp.on", event);
    const std::uint64_t seq = record_effect(std::move(label), std::make_unique<subscription_effect>(*this, std::string{event}, key));
    if (const auto it = subscriptions_.find(event); it != subscriptions_.end()) {
        for (subscription& s : it->second) {
            if (s.key == key) {
                s.seq = seq;
            }
        }
    }
    return seq;
}

void sandbox_impl::unsubscribe(const std::string& event, std::uint64_t key) noexcept {
    const auto it = subscriptions_.find(event);
    if (it == subscriptions_.end()) {
        return;
    }
    auto& subs = it->second;
    const auto sub = std::ranges::find(subs, key, &subscription::key);
    if (sub == subs.end()) {
        return;
    }
    luaL_unref(state_, LUA_REGISTRYINDEX, sub->fn_ref);
    subs.erase(sub);
    ++subscriptions_version_;
    release_interest(event);
}

subscription* sandbox_impl::subscription_by_seq(std::uint64_t seq) noexcept {
    for (auto& [event, subs] : subscriptions_) {
        for (subscription& s : subs) {
            if (s.seq == seq) {
                return &s;
            }
        }
    }
    return nullptr;
}

// ---- delivery ------------------------------------------------------------------------------------

void sandbox_impl::enqueue(std::string_view event, const event_args& args) noexcept {
    try {
        const std::uint32_t cap = options_.limits.event_queue;
        const std::scoped_lock lock{inbox_mutex_};
        if (cap != 0 && inbox_.size() >= cap) {
            dropped_events_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        inbox_.emplace_back(std::string{event}, args.own(args.data));
    } catch (...) { // out of memory: this sandbox misses the event
        dropped_events_.fetch_add(1, std::memory_order_relaxed);
    }
}

void sandbox_impl::deliver_now(std::string_view event, event_pusher args, module_id publisher, const value_list* values) {
    // 1. Handlers, each as its own request. A snapshot of their keys: handlers may (un)subscribe, so
    // each is looked up again before its call (where it was, unless the list changed), and the list
    // itself again once a subscription was added or removed.
    // One batch: a handler that returns normally leaves its record and coroutine to the next one
    // (restart_request: a request id, owner, budget and policy of its own, so a failure still undoes
    // only that call's effects). One that suspends keeps them as its own request; one that fails
    // closes them; the next handler then starts a new record.
    request_record* batch = nullptr;
    const utils::scope_guard release{[this, &batch]() noexcept {
        if (batch != nullptr) {
            release_kept(*batch);
        }
    }};
    if (const auto it = subscriptions_.find(event); it != subscriptions_.end()) {
        std::array<std::uint64_t, 16> few{}; // the usual handful without an allocation per delivery
        std::vector<std::uint64_t> many;
        const std::size_t count = it->second.size();
        if (count > few.size()) {
            many.resize(count);
        }
        const std::span<std::uint64_t> keys = count > few.size() ? std::span<std::uint64_t>{many} : std::span<std::uint64_t>{few.data(), count};
        for (std::size_t i = 0; i < keys.size(); ++i) {
            keys[i] = it->second[i].key;
        }
        auto list = it;
        std::uint64_t version = subscriptions_version_;
        for (std::size_t i = 0; i < keys.size(); ++i) {
            if (version != subscriptions_version_) {
                list = subscriptions_.find(event);
                version = subscriptions_version_;
                if (list == subscriptions_.end()) {
                    break;
                }
            }
            std::vector<subscription>& subs = list->second;
            const auto live = i < subs.size() && subs[i].key == keys[i] ? subs.begin() + static_cast<std::ptrdiff_t>(i) : std::ranges::find(subs, keys[i], &subscription::key);
            if (live == subs.end() || live->paused) {
                continue;
            }
            const subscription sub = *live; // the list may change during the call
            lua_rawgeti(state_, LUA_REGISTRYINDEX, sub.fn_ref);
            stack s{state_};
            const int nargs = args(s);
            request_record& req = batch != nullptr ? restart_request(*batch, request_kind::kEvent, sub.owner, nargs)
                                                   : start_request(request_kind::kEvent, sub.owner, {}, nargs, false);
            batch = &req; // from here on the guard owns it until step decides
            req.handler_seq = sub.once ? 0 : sub.seq;
            req.policy = sub.policy;
            req.source.assign(event);
            if (sub.once) {
                (void)ledger_.revert_entry(sub.seq); // spent once its call starts (the function is on the coroutine)
            }
            bool kept = false;
            (void)step(req, nargs, &kept);
            if (!kept) {
                batch = nullptr; // listed (it suspended) or recycled (it failed)
            }
        }
    }
    // 2. Waiters: they resume at the next resume pass with the arguments. One at a time, so a
    // failure part way (memory) leaves the rest waiting rather than stranded. The arguments are
    // pushed and packed before the waiter is taken, and it is looked up again after: those are Lua
    // allocations, and a collection they run can call a finalizer that ends the waiting request.
    if (waiters_.contains(event)) {
        const std::string name{event};
        for (;;) {
            auto it = waiters_.find(name);
            if (it == waiters_.end() || it->second.empty()) {
                break;
            }
            const request_id id = it->second.front();
            if (const auto req = requests_.find(id); req == requests_.end() || req->second->waiting != wait_kind::kEvent) {
                it->second.erase(it->second.begin());
                continue;
            }
            stack s{state_};
            const int nargs = args(s);
            const int packed = pack_top(state_, nargs);
            it = waiters_.find(name);
            const auto req = requests_.find(id);
            if (it == waiters_.end() || it->second.empty() || it->second.front() != id || req == requests_.end() ||
                req->second->waiting != wait_kind::kEvent) {
                luaL_unref(state_, LUA_REGISTRYINDEX, packed); // it went meanwhile: the next one, if any
                continue;
            }
            it->second.erase(it->second.begin());
            luaL_unref(state_, LUA_REGISTRYINDEX, req->second->resume_ref);
            req->second->resume_ref = packed;
            req->second->woken = true;
            requests_dirty_ = true;
        }
        release_interest(name);
    }
    // 3. C++ listeners (script events), at the end of this operation or pump().
    if (values != nullptr && !listeners_->empty()) {
        listener_calls_.push_back(queued_script_event{std::string{event}, publisher, *values});
    }
}

bool sandbox_impl::queue_script_event(std::string name, module_id publisher, value_list args) {
    const std::uint32_t cap = options_.limits.event_queue;
    if (cap != 0 && script_events_.size() >= cap) {
        dropped_events_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    script_events_.push_back(queued_script_event{std::move(name), publisher, std::move(args)});
    return true;
}

bool sandbox_impl::publish(lua_State* L, std::string_view event, int first_arg) {
    const stack s{L};
    std::optional<error> failure;
    value_list args;
    {
        if (!utils::is_dotted_name(event)) {
            failure = make_error(errc::kInvalidArgument, std::format("'{}' is not an event name (dotted lowercase, e.g. game.round_over)", event));
        } else if (event.starts_with("rhp.")) {
            failure = make_error(errc::kForbidden, std::format("'{}': names starting with rhp. are reserved", event));
        } else if (const auto found = find_event(event); found || found.error().code != errc::kNotFound) {
            failure = make_error(errc::kForbidden, std::format("C++ owns the event '{}'; scripts can't publish it", event));
        } else {
            const int top = lua_gettop(L);
            for (int i = first_arg; i <= top && !failure; ++i) {
                auto v = s.to_value(i);
                if (!v) {
                    failure = std::move(v).error();
                } else {
                    args.push_back(std::move(*v));
                }
            }
        }
    }
    if (failure) {
        failure->where = "rhp.publish";
        s.raise(*failure);
    }
    return queue_script_event(std::string{event}, current_.module, std::move(args));
}

// ---- waiting -------------------------------------------------------------------------------------

int sandbox_impl::wait_event(lua_State* L, std::string_view event, std::optional<double> timeout_ms) {
    refuse_while_closing(L, "rhp.wait_event");
    event_state* state = resolve_event(L, event, "rhp.wait_event");
    request_record& me = suspendable(L, "rhp.wait_event");
    waiters_[std::string{event}].push_back(me.id);
    acquire_interest(event, state);
    me.waiting = wait_kind::kEvent;
    me.wait_event.assign(event); // in the pooled record's buffer
    if (timeout_ms) {
        me.wake_time = script_now() + milliseconds(*timeout_ms);
    }
    return lua_yieldk(L, 0, 0, &wait_event_k);
}

int sandbox_impl::finish_wait_event(lua_State* L) {
    request_record* me = running_request();
    if (me == nullptr) {
        stack{L}.raise(make_error(errc::kRuntime, "rhp.wait_event resumed outside its request"));
    }
    const int ref = std::exchange(me->resume_ref, kNoRef);
    stop_waiting(*me);
    if (ref == kNoRef) {
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "timeout");
        return 2;
    }
    lua_pushboolean(L, 1);
    const int n = unpack_ref(L, ref);
    luaL_unref(state_, LUA_REGISTRYINDEX, ref);
    return n + 1;
}

void sandbox_impl::stop_waiting(request_record& req) noexcept {
    if (req.waiting == wait_kind::kEvent) {
        if (const auto it = waiters_.find(req.wait_event); it != waiters_.end()) {
            std::erase(it->second, req.id);
        }
        req.waiting = wait_kind::kNone;
        release_interest(req.wait_event);
        req.wait_event.clear(); // keeps its buffer: the record is pooled
    } else if (req.waiting == wait_kind::kTask) {
        if (task_record* t = task(req.wait_task)) {
            std::erase(t->joiners, req.id);
        }
        req.wait_task = 0;
        req.waiting = wait_kind::kNone;
    } else if (req.waiting == wait_kind::kAsync) {
        drop_async(std::exchange(req.async, nullptr));
        req.waiting = wait_kind::kNone;
    } else if (req.waiting == wait_kind::kDebug) {
        forget_paused(req.id);
        req.waiting = wait_kind::kNone;
    }
    req.woken = false;
}

int sandbox_impl::pack_top(lua_State* L, int n) {
    lua_createtable(L, n, 1);
    lua_insert(L, -(n + 1));
    for (int i = n; i >= 1; --i) {
        lua_rawseti(L, -(i + 1), i); // the table sits below the i values left
    }
    lua_pushinteger(L, n);
    lua_setfield(L, -2, "n");
    return luaL_ref(L, LUA_REGISTRYINDEX);
}

int sandbox_impl::unpack_ref(lua_State* L, int ref) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    lua_getfield(L, -1, "n");
    const auto n = static_cast<int>(lua_tointeger(L, -1));
    lua_pop(L, 1);
    luaL_checkstack(L, n + 1, "rhp: too many values");
    for (int i = 1; i <= n; ++i) {
        lua_rawgeti(L, -i, i);
    }
    lua_remove(L, -(n + 1));
    return n;
}

// ---- C++ listeners -------------------------------------------------------------------------------

void sandbox_impl::call_listeners() {
    for (auto& e : std::exchange(listener_calls_, {})) {
        // A copy of the name: a callback may unload the module (its record goes) before the next one runs.
        const module_record* mod = e.publisher ? record(e.publisher) : nullptr;
        const std::string module_name = mod != nullptr ? mod->name : std::string{};
        const script_event view{e.name, e.publisher, module_name, e.args};
        listeners_->dispatch(e.name, view);
    }
}

// ---- stats ---------------------------------------------------------------------------------------

sandbox_stats sandbox_impl::stats() const {
    sandbox_stats out;
    out.dropped_events = dropped_events_.load(std::memory_order_relaxed);
    {
        const std::scoped_lock lock{inbox_mutex_};
        out.queued_events = inbox_.size() + script_events_.size();
    }
    out.schedule_entries = schedule_.size();
    for (const auto& [event, subs] : subscriptions_) {
        out.subscriptions += subs.size();
    }
    out.tasks = static_cast<std::size_t>(std::ranges::count_if(tasks_, [](const auto& t) { return !t.second.finished; }));
    for (const auto& [id, req] : requests_) {
        if (req->waiting == wait_kind::kAsync) {
            ++out.async_waiting;
        } else if (req->waiting == wait_kind::kDebug) {
            ++out.paused;
        } else if (req->waiting != wait_kind::kNone) {
            ++out.waiting;
        }
    }
    out.async_compensated = async_compensated_;
    out.async_dropped = async_dropped_;
    out.handler_failures = handler_failures_;
    return out;
}

void sandbox_impl::push_stats(lua_State* L) {
    const sandbox_stats st = stats();
    lua_createtable(L, 0, 11);
    const auto field = [L](const char* name, std::uint64_t v) {
        lua_pushinteger(L, static_cast<lua_Integer>(v));
        lua_setfield(L, -2, name);
    };
    field("dropped_events", st.dropped_events);
    field("queued_events", st.queued_events);
    field("timers", st.schedule_entries);
    field("subscriptions", st.subscriptions);
    field("tasks", st.tasks);
    field("waiting", st.waiting);
    field("async_waiting", st.async_waiting);
    field("async_compensated", st.async_compensated);
    field("async_dropped", st.async_dropped);
    field("handler_failures", st.handler_failures);
    field("memory", memory_used_);
}

} // namespace Rhp::script::detail
