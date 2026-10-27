// Background tasks: rhp.spawn / rhp.tasks and the rhp.task handle (status / cancel / join / id).

#include <cstdint>
#include <cstring>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/keys.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>

namespace Rhp::script::detail {

namespace {

// Userdata payload of a task handle.
struct task_handle {
    std::uint64_t key;
    std::uint64_t seq;
};

class task_effect final : public effect {
public:
    task_effect(sandbox_impl& box, std::uint64_t key) : box_(&box), key_(key) {}
    task_effect(const task_effect&) = delete;
    task_effect& operator=(const task_effect&) = delete;
    ~task_effect() override { (void)box_->cancel_task(key_, "its module was reverted"); }

    void undo() override { (void)box_->cancel_task(key_, "its module was reverted"); }

private:
    sandbox_impl* box_;
    std::uint64_t key_;
};

task_record& checked_task(lua_State* L, int index) {
    const auto* h = static_cast<const task_handle*>(luaL_checkudata(L, index, kTaskKey));
    task_record* t = impl_of(L).task(h->key);
    if (t == nullptr) {
        stack{L}.raise(make_error(errc::kNotFound, std::format("task {} is gone", h->seq)));
    }
    return *t;
}

int lua_task_status(lua_State* L) {
    const task_record& t = checked_task(L, 1);
    stack{L}.push_string(impl_of(L).task_status(t));
    return 1;
}

int lua_task_cancel(lua_State* L) {
    task_record& t = checked_task(L, 1);
    auto& impl = impl_of(L);
    if (t.owner.module != impl.current_owner().module) {
        stack{L}.raise(make_error(errc::kNotFound, std::format("no task {} of this module", t.seq), "task:cancel"));
    }
    lua_pushboolean(L, impl.cancel_task(t.key, "cancelled") ? 1 : 0);
    return 1;
}

int join_k(lua_State* L, int /*status*/, lua_KContext ctx) {
    return impl_of(L).finish_join(L, static_cast<std::uint64_t>(ctx));
}

int lua_task_join(lua_State* L) {
    const task_record& t = checked_task(L, 1);
    return impl_of(L).join_task(L, t.key);
}

// __index: `id`, else the methods (upvalue 1).
int lua_task_index(lua_State* L) {
    const auto* h = static_cast<const task_handle*>(luaL_checkudata(L, 1, kTaskKey));
    if (lua_type(L, 2) == LUA_TSTRING && std::strcmp(lua_tostring(L, 2), "id") == 0) {
        lua_pushinteger(L, static_cast<lua_Integer>(h->seq));
        return 1;
    }
    lua_pushvalue(L, 2);
    lua_rawget(L, lua_upvalueindex(1));
    return 1;
}

int lua_task_gc(lua_State* L) {
    const auto* h = static_cast<const task_handle*>(lua_touserdata(L, 1));
    impl_of(L).handle_released(h->key);
    return 0;
}

int lua_task_tostring(lua_State* L) {
    const auto* h = static_cast<const task_handle*>(luaL_checkudata(L, 1, kTaskKey));
    auto& impl = impl_of(L);
    const task_record* t = impl.task(h->key);
    const std::string text = std::format("task {} ({})", h->seq, t != nullptr ? impl.task_status(*t) : std::string_view{"gone"});
    stack{L}.push_string(text);
    return 1;
}

} // namespace

// ---- Lua-side builtins ---------------------------------------------------------------------------

// rhp.spawn(fn, ...) → task: runs fn(...) as a background task of the calling module.
int lua_rhp_spawn(lua_State* L) {
    if (lua_type(L, 1) != LUA_TFUNCTION) {
        const stack s{L};
        s.raise(make_error(errc::kTypeMismatch, std::format("expected function, got {}", s.type_name(1)), "rhp.spawn"));
    }
    impl_of(L).spawn(L);
    return 1;
}

int lua_rhp_tasks(lua_State* L) {
    impl_of(L).push_tasks(L);
    return 1;
}

// ---- the task metatable ----------------------------------------------------------------------------

void sandbox_impl::open_stage7_libraries() {
    lua_State* L = state_;
    luaL_newmetatable(L, kTaskKey);
    lua_createtable(L, 0, 3);
    lua_pushcfunction(L, &lua_task_status);
    lua_setfield(L, -2, "status");
    lua_pushcfunction(L, &lua_task_cancel);
    lua_setfield(L, -2, "cancel");
    lua_pushcfunction(L, &lua_task_join);
    lua_setfield(L, -2, "join");
    lua_pushcclosure(L, &lua_task_index, 1);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, &lua_task_gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, &lua_task_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pushliteral(L, "task");
    lua_setfield(L, -2, "__name");
    lua_pushliteral(L, "locked");
    lua_setfield(L, -2, "__metatable");
    lua_pop(L, 1);
}

// ---- tasks ---------------------------------------------------------------------------------------

task_record* sandbox_impl::task(std::uint64_t key) noexcept {
    const auto it = tasks_.find(key);
    return it != tasks_.end() ? &it->second : nullptr;
}

task_record* sandbox_impl::task_by_seq(std::uint64_t seq) noexcept {
    for (auto& [key, t] : tasks_) {
        if (t.seq == seq) {
            return &t;
        }
    }
    return nullptr;
}

std::string_view sandbox_impl::task_status(const task_record& t) const noexcept {
    if (t.finished) {
        return to_string(t.state);
    }
    const auto req = requests_.find(t.request);
    return to_string(req != requests_.end() && req->second->running ? task_state::kRunning : task_state::kSuspended);
}

void sandbox_impl::push_task_handle(lua_State* L, task_record& t) {
    // Counted before allocating: a collection the allocation runs may not release the record.
    ++t.handles;
    const std::uint64_t key = t.key;
    const std::uint64_t seq = t.seq;
    auto* h = static_cast<task_handle*>(lua_newuserdatauv(L, sizeof(task_handle), 0));
    h->key = key;
    h->seq = seq;
    luaL_setmetatable(L, kTaskKey);
}

void sandbox_impl::spawn(lua_State* L) {
    refuse_while_closing(L, "rhp.spawn");
    const int nargs = lua_gettop(L) - 1;
    const std::uint64_t key = ++task_keys_;
    // The function and its arguments go to the main stack, where start_request takes them from.
    // Checked here, so nothing raises on the main state while this coroutine runs.
    if (lua_checkstack(state_, nargs + 8) == 0) {
        stack{L}.raise(make_error(errc::kLimitExceeded, std::format("{} arguments are too many", nargs), "rhp.spawn"));
    }
    lua_xmove(L, state_, nargs + 1);
    // Its coroutine, if the pool has none, is made on this one: an allocation that fails raises here.
    request_record& req = start_request(request_kind::kTask, effect_owner{current_.module, current_.revision}, {}, nargs, false, L);
    req.start_args = nargs;
    req.wake_frame = frame_ + 1; // never inside the spawner: at the next pump()
    req.task_key = key;
    req.source = "task";
    req.policy = options_.handler_errors;
    task_record t;
    t.key = key;
    t.owner = effect_owner{current_.module, current_.revision};
    t.request = req.id;
    tasks_.emplace(key, std::move(t));
    // Owned by the spawning request too, so a failed exec (or a failed handler under "report") takes
    // back what it spawned.
    const std::uint64_t seq = record_effect(where_of(req), std::make_unique<task_effect>(*this, key));
    task_record& rec = tasks_.at(key);
    rec.seq = seq;
    req.handler_seq = seq;
    push_task_handle(L, rec);
}

void sandbox_impl::push_tasks(lua_State* L) {
    lua_newtable(L);
    lua_Integer n = 0;
    std::vector<std::uint64_t> keys;
    for (const auto& [key, t] : tasks_) {
        if (!t.finished && t.owner.module == current_.module) {
            keys.push_back(key);
        }
    }
    for (const std::uint64_t key : keys) {
        if (task_record* t = task(key)) { // a collection while pushing can't erase unfinished tasks
            push_task_handle(L, *t);
            lua_rawseti(L, -2, ++n);
        }
    }
}

bool sandbox_impl::cancel_task(std::uint64_t key, std::string_view why) {
    task_record* t = task(key);
    if (t == nullptr || t->finished) {
        return false;
    }
    t->cancel_requested = true;
    const request_id r = t->request;
    for (const active_run& run : running_) {
        if (run.request != nullptr && run.request->id == r) {
            cancel(r); // it runs (it cancels itself): stopped at the next hook tick
            return true;
        }
    }
    abandon_request(r, why); // suspended (or not started): ends now, its to-be-closed variables closed
    return true;
}

int sandbox_impl::join_task(lua_State* L, std::uint64_t key) {
    task_record* t = task(key);
    if (t == nullptr) {
        stack{L}.raise(make_error(errc::kNotFound, "the task is gone", "task:join"));
    }
    if (t->finished) {
        return finish_join(L, key);
    }
    request_record& me = suspendable(L, "task:join");
    if (t->request == me.id) {
        stack{L}.raise(make_error(errc::kInvalidArgument, "a task can't join itself", "task:join"));
    }
    // A cycle: the joined task (or one it waits for, transitively) waits for this request.
    for (const task_record* step = t; step != nullptr;) {
        const auto req = requests_.find(step->request);
        if (req == requests_.end() || req->second->waiting != wait_kind::kTask) {
            break;
        }
        const task_record* next = task(req->second->wait_task);
        if (next != nullptr && !next->finished && next->request == me.id) {
            stack{L}.raise(make_error(errc::kInvalidArgument, "join cycle: the task waits for this one", "task:join"));
        }
        step = next;
    }
    t->joiners.push_back(me.id);
    me.waiting = wait_kind::kTask;
    me.wait_task = key;
    return lua_yieldk(L, 0, static_cast<lua_KContext>(key), &join_k);
}

int sandbox_impl::finish_join(lua_State* L, std::uint64_t key) {
    if (request_record* me = running_request(); me != nullptr && me->waiting == wait_kind::kTask) {
        stop_waiting(*me);
    }
    const task_record* t = task(key);
    if (t == nullptr || !t->finished) {
        stack{L}.raise(make_error(errc::kRuntime, "the task ended without a result", "task:join"));
    }
    if (t->state == task_state::kDone) {
        return t->results_ref == kNoRef ? 0 : unpack_ref(L, t->results_ref);
    }
    const error err = t->failure.value_or(make_error(errc::kCancelled, "the task was cancelled"));
    stack{L}.raise(err);
}

void sandbox_impl::finish_task(request_record& req, const result<value_list>* outcome, bool abandoned) noexcept {
    task_record* t = task(req.task_key);
    if (t == nullptr || t->finished) {
        return;
    }
    t->finished = true;
    t->request = {};
    try {
        if (!abandoned && outcome != nullptr && outcome->has_value()) {
            t->state = task_state::kDone;
        } else if (abandoned || t->cancel_requested) {
            t->state = task_state::kCancelled;
            t->failure = make_error(errc::kCancelled, outcome != nullptr && !outcome->has_value() ? outcome->error().message : "the task was cancelled");
        } else {
            t->state = task_state::kFailed;
            t->failure = outcome != nullptr && !outcome->has_value() ? outcome->error() : make_error(errc::kRuntime, "the task failed");
        }
    } catch (...) { // out of memory building the error: the state is still right
    }
    for (const request_id id : std::exchange(t->joiners, {})) {
        if (const auto it = requests_.find(id); it != requests_.end()) {
            it->second->woken = true;
            requests_dirty_ = true;
        }
    }
    const std::uint64_t seq = t->seq;
    const std::uint64_t key = t->key;
    try {
        (void)ledger_.revert_entry(seq); // spent: undoing it would do nothing
    } catch (...) {
    }
    if (task_record* still = task(key); still != nullptr && still->handles == 0) {
        luaL_unref(state_, LUA_REGISTRYINDEX, still->results_ref);
        tasks_.erase(key);
    }
}

void sandbox_impl::handle_released(std::uint64_t key) noexcept {
    if (closing_) {
        return;
    }
    try {
        collected_tasks_.push_back(key); // drain() applies it: a collection may run inside any loop
    } catch (...) {                      // out of memory: the record stays until the sandbox closes
    }
}

} // namespace Rhp::script::detail
