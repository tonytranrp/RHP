// Asynchronous bindings (Rhp::async<T>): the request that calls one waits, suspended, until the
// result arrives from any thread; pump() wakes it. A call whose request went away first (cancel,
// unload, limits.async_ms, the sandbox's end) is kept until its result arrives and then taken back.

#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/puc_lua/sandbox_impl.hpp>

namespace Rhp::script::detail {

bool sandbox_impl::can_suspend(lua_State* L) const noexcept {
    if (running_.empty() || closing_lua_) {
        return false;
    }
    const active_run& top = running_.back();
    return top.thread == L && top.request != nullptr && lua_isyieldable(L) != 0;
}

bool sandbox_impl::await_async(lua_State* L, std::shared_ptr<async_wait> op) {
    request_record& me = suspendable(L, "async");
    // The waker only posts: the request is found (or the call settled) by the next pump().
    if (!op->arm([inbox = async_inbox_, weak = std::weak_ptr<async_wait>{op}] { inbox->post(weak); })) {
        return false; // already there: the binding finishes at once
    }
    op->request = me.id;
    me.async = std::move(op);
    me.waiting = wait_kind::kAsync;
    if (options_.limits.async_ms != 0) {
        me.wake_time = script_now() + std::chrono::milliseconds{options_.limits.async_ms};
    }
    return true;
}

std::shared_ptr<async_wait> sandbox_impl::take_async(lua_State* L) {
    request_record* me = running_request();
    if (me == nullptr || me->thread != L || !me->async) {
        stack{L}.raise(make_error(errc::kRuntime, "an asynchronous call resumed outside its request"));
    }
    std::shared_ptr<async_wait> op = std::exchange(me->async, nullptr);
    me->waiting = wait_kind::kNone;
    if (!op->ready()) { // resumed by limits.async_ms
        drop_async(std::move(op));
        return nullptr;
    }
    return op;
}

void sandbox_impl::drop_async(std::shared_ptr<async_wait> op) noexcept {
    if (!op) {
        return;
    }
    op->detached = true;
    op->request_stop();
    if (op->ready()) { // it arrived, but nobody receives it
        if (op->compensate()) {
            ++async_compensated_;
        }
        return;
    }
    try {
        detached_async_.push_back(std::move(op));
    } catch (...) { // out of memory: let go of it; a late success is then the producer's to handle (complete() returns false)
    }
}

void sandbox_impl::wake_async() {
    if (!async_inbox_->any.load(std::memory_order_acquire)) {
        return;
    }
    std::vector<std::weak_ptr<async_wait>> arrived;
    {
        const std::scoped_lock lock{async_inbox_->mutex};
        arrived.swap(async_inbox_->arrived);
        async_inbox_->any.store(false, std::memory_order_relaxed);
    }
    for (const std::weak_ptr<async_wait>& weak : arrived) {
        const std::shared_ptr<async_wait> op = weak.lock();
        if (!op) {
            continue;
        }
        if (op->detached) {
            if (const auto it = std::ranges::find(detached_async_, op); it != detached_async_.end()) {
                detached_async_.erase(it);
                if (op->compensate()) {
                    ++async_compensated_;
                }
            }
            continue;
        }
        if (const auto it = requests_.find(op->request); it != requests_.end() && it->second->async == op) {
            it->second->woken = true;
            requests_dirty_ = true;
        }
    }
}

void sandbox_impl::close_async() noexcept {
    {
        const std::scoped_lock lock{async_inbox_->mutex};
        async_inbox_->closed = true;
        async_inbox_->arrived.clear();
    }
    for (const std::shared_ptr<async_wait>& op : detached_async_) {
        if (op->ready() && op->compensate()) {
            ++async_compensated_;
        }
    }
    detached_async_.clear(); // the rest: their producers see stop_requested() and complete() returns false
}

} // namespace Rhp::script::detail
