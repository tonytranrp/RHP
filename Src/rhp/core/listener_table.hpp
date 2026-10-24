#pragma once

#include <algorithm>
#include <atomic>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#include <rhp/utils/scope_guard.hpp>

namespace Rhp::core {

// Callbacks keyed by a filter value (an event kind, an event name), shared by the threads that add,
// remove and dispatch them.
//
//   add / remove      any thread
//   dispatch(match)   calls every callback whose key matches, on the calling thread, outside the lock
//
// remove() is a barrier: once it returns, that callback is neither running on another thread nor
// started again. A callback may remove itself (or another) while it runs; it then finishes its current
// call. So don't remove a callback from a thread holding a lock that callback takes while another
// thread dispatches it: remove() would wait for a call that waits for the lock.
template <class Key, class Fn>
class listener_table {
public:
    // Adds a callback; returns its id (never 0).
    std::uint64_t add(Key key, Fn fn) {
        const std::scoped_lock lock{mutex_};
        const std::uint64_t id = ++last_;
        entries_.push_back(entry{id, std::move(key), std::make_shared<slot>(std::move(fn))});
        count_.store(entries_.size(), std::memory_order_release);
        return id;
    }

    // Removes a callback and waits for its calls on other threads to finish. False for an unknown id.
    bool remove(std::uint64_t id) noexcept {
        std::unique_lock lock{mutex_};
        const auto it = std::ranges::find(entries_, id, &entry::id);
        if (it == entries_.end()) {
            return false;
        }
        const std::shared_ptr<slot> s = it->s;
        s->live = false;
        entries_.erase(it);
        count_.store(entries_.size(), std::memory_order_release);
        const std::thread::id me = std::this_thread::get_id();
        idle_.wait(lock, [&] { return std::ranges::all_of(s->callers, [me](std::thread::id t) { return t == me; }); });
        return true;
    }

    [[nodiscard]] bool empty() const noexcept { return count_.load(std::memory_order_acquire) == 0; }

    // True if a callback's key satisfies `match`.
    template <std::predicate<const Key&> Match>
    [[nodiscard]] bool any(Match match) const {
        const std::scoped_lock lock{mutex_};
        return std::ranges::any_of(entries_, [&](const entry& e) { return match(e.key); });
    }

    // Calls fn(args...) for every callback whose key satisfies `match`, in the order they were added.
    // The arguments are passed as lvalues to each callback. A callback's exception propagates (the
    // remaining callbacks are not called).
    template <std::predicate<const Key&> Match, class... Args>
    void dispatch(Match match, const Args&... args) const {
        std::vector<std::shared_ptr<slot>> targets;
        {
            const std::scoped_lock lock{mutex_};
            for (const entry& e : entries_) {
                if (match(e.key)) {
                    targets.push_back(e.s);
                }
            }
        }
        const std::thread::id me = std::this_thread::get_id();
        for (const auto& s : targets) {
            {
                const std::scoped_lock lock{mutex_};
                if (!s->live) {
                    continue; // removed after the snapshot: never started
                }
                s->callers.push_back(me);
            }
            const utils::scope_guard done{[&] {
                const std::scoped_lock lock{mutex_};
                s->callers.erase(std::ranges::find(s->callers, me));
                idle_.notify_all();
            }};
            s->fn(args...);
        }
    }

private:
    struct slot {
        explicit slot(Fn f) : fn(std::move(f)) {}
        Fn fn;
        std::vector<std::thread::id> callers; // threads inside fn right now (guarded by the table's mutex)
        bool live = true;                     // false once removed (guarded by the table's mutex)
    };

    struct entry {
        std::uint64_t id = 0;
        Key key;
        std::shared_ptr<slot> s;
    };

    mutable std::mutex mutex_;
    mutable std::condition_variable idle_;
    std::vector<entry> entries_;
    std::uint64_t last_ = 0;
    std::atomic<std::size_t> count_{0};
};

} // namespace Rhp::core
