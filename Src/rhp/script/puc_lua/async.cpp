// Asynchronous bindings (Rhp::async<T>): the request that calls one waits, suspended, until the
// result arrives from any thread; pump() wakes it. A call whose request went away first (cancel,
// unload, limits.async_ms) is kept until its result arrives and then taken back. When the sandbox
// itself goes, release_async() hands the calls still pending to an owner that outlives it.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/sandbox.hpp>

namespace Rhp::script {

namespace detail {

void async_inbox::post(const std::weak_ptr<async_wait>& op) noexcept {
    const std::scoped_lock lock{mutex};
    if (closed) {
        return;
    }
    try {
        arrived.push_back(op);
    } catch (...) { // out of memory: the next pass looks at every call instead
        overflow = true;
    }
    any.store(true, std::memory_order_release);
}

std::vector<std::weak_ptr<async_wait>> async_inbox::take(bool& overflowed) {
    std::vector<std::weak_ptr<async_wait>> out;
    const std::scoped_lock lock{mutex};
    out.swap(arrived);
    arrived.reserve(out.capacity()); // the completing threads rarely allocate
    overflowed = std::exchange(overflow, false);
    any.store(false, std::memory_order_relaxed);
    return out;
}

void sandbox_impl::count(async_settled outcome) noexcept {
    if (outcome == async_settled::kUndone) {
        ++async_compensated_;
    } else if (outcome == async_settled::kDropped) {
        ++async_dropped_;
    }
}

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
        count(op->settle());
        return;
    }
    try {
        detached_async_.push_back(std::move(op));
    } catch (...) { // out of memory: `op` goes now; its destructor settles a success that slipped in
    }
}

void sandbox_impl::wake_async() {
    if (!async_inbox_->any.load(std::memory_order_acquire)) {
        return;
    }
    bool overflowed = false;
    const std::vector<std::weak_ptr<async_wait>> arrived = async_inbox_->take(overflowed);
    for (const std::weak_ptr<async_wait>& weak : arrived) {
        if (const std::shared_ptr<async_wait> op = weak.lock()) {
            arrive(op);
        }
    }
    if (overflowed) { // some arrivals weren't recorded: look at every call
        for (const auto& [id, req] : requests_) {
            if (req->waiting == wait_kind::kAsync && req->async && req->async->ready()) {
                req->woken = true;
                requests_dirty_ = true;
            }
        }
        std::vector<std::shared_ptr<async_wait>> ready;
        for (const auto& op : detached_async_) {
            if (op->ready()) {
                ready.push_back(op);
            }
        }
        for (const auto& op : ready) {
            arrive(op);
        }
    }
}

void sandbox_impl::arrive(const std::shared_ptr<async_wait>& op) {
    if (op->detached) {
        if (const auto it = std::ranges::find(detached_async_, op); it != detached_async_.end()) {
            detached_async_.erase(it);
            count(op->settle());
        }
        return;
    }
    if (const auto it = requests_.find(op->request); it != requests_.end() && it->second->async == op) {
        it->second->woken = true;
        requests_dirty_ = true;
    }
}

async_leftovers sandbox_impl::release_async() {
    async_leftovers out;
    out.inbox_ = async_inbox_;
    out.pending_ = std::exchange(detached_async_, {});
    async_inbox_ = std::make_shared<async_inbox>(); // calls made from here on are the sandbox's again
    return out;
}

void sandbox_impl::close_async() noexcept {
    {
        const std::scoped_lock lock{async_inbox_->mutex};
        async_inbox_->closed = true;
        async_inbox_->arrived.clear();
    }
    for (const std::shared_ptr<async_wait>& op : detached_async_) {
        count(op->settle()); // complete() returns false from here on: the producer cleans up
    }
    detached_async_.clear();
}

} // namespace detail

// ---- async_leftovers ----------------------------------------------------------------------------------

async_leftovers::async_leftovers() = default;
async_leftovers::~async_leftovers() {
    close();
}
async_leftovers::async_leftovers(async_leftovers&&) noexcept = default;

async_leftovers& async_leftovers::operator=(async_leftovers&& other) noexcept {
    if (this != &other) {
        close();
        inbox_ = std::move(other.inbox_);
        pending_ = std::move(other.pending_);
        undone_ = other.undone_;
        dropped_ = other.dropped_;
    }
    return *this;
}

std::size_t async_leftovers::pump() {
    if (!inbox_ || pending_.empty()) {
        return pending_.size();
    }
    if (inbox_->any.load(std::memory_order_acquire)) {
        bool overflowed = false;
        (void)inbox_->take(overflowed); // who arrived doesn't matter: every ready call settles below
    }
    for (auto it = pending_.begin(); it != pending_.end();) {
        if ((*it)->ready()) {
            const detail::async_settled outcome = (*it)->settle();
            undone_ += outcome == detail::async_settled::kUndone ? 1 : 0;
            dropped_ += outcome == detail::async_settled::kDropped ? 1 : 0;
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    return pending_.size();
}

void async_leftovers::close() noexcept {
    if (inbox_) {
        const std::scoped_lock lock{inbox_->mutex};
        inbox_->closed = true;
        inbox_->arrived.clear();
    }
    pending_.clear(); // each settles: a success already there is taken back, later ones are refused
    inbox_.reset();
}

} // namespace Rhp::script
