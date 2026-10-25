#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::script {

class stack;

namespace detail {

// Pushes the arguments of one fire() onto a stack; returns how many it pushed. Non-owning: valid
// only during the fire() call that made it.
struct event_pusher {
    const void* data = nullptr;
    int (*push)(stack& s, const void* data) = nullptr;

    int operator()(stack& s) const { return push(s, data); }
};

// The arguments of one fire(), type-erased: `push` reads them in place, `own` copies them into a
// function that outlives the call (for listeners on other threads), `values` converts them
// (Rhp::to_value; nil for an argument without a conversion) for listeners outside Lua.
struct event_args {
    const void* data = nullptr;
    int (*push)(stack& s, const void* data) = nullptr;
    std::function<int(stack&)> (*own)(const void* data) = nullptr;
    std::vector<value> (*values)(const void* data) = nullptr;
};

// A sandbox (or a host forwarding events to its clients) subscribed to an event.
class event_listener {
public:
    // The thread that owns the listener's Lua state (the thread that calls its pump()).
    [[nodiscard]] virtual std::thread::id listener_thread() const noexcept = 0;

    // On the listener's thread: run the subscribed handlers now.
    virtual void deliver(std::string_view event, const event_args& args) = 0;

    // From any other thread, under the event's lock: queue (a copy of what the listener needs) for
    // its next pump().
    virtual void enqueue(std::string_view event, const event_args& args) noexcept = 0;

protected:
    event_listener() = default;
    ~event_listener() = default;
    event_listener(const event_listener&) = default;
    event_listener& operator=(const event_listener&) = default;
};

// Shared state of one Rhp::lua_event type: the sandboxes listening to it.
//
// fire() delivers synchronously to listeners owned by the calling thread and queues a copy of the
// arguments for every other listener. While nobody listens, fire() is one acquire load.
//
// detach() is a barrier: once it returns, no other thread is delivering to that listener (a listener
// may detach itself while it is being delivered to; that delivery then finishes).
class event_state {
public:
    constexpr event_state() noexcept = default;

    [[nodiscard]] bool active() const noexcept { return active_.load(std::memory_order_acquire); }

    void fire(std::string_view name, const event_args& args);
    void attach(event_listener* listener);
    void detach(const event_listener* listener) noexcept;
    [[nodiscard]] std::size_t listeners();

private:
    struct shared {
        std::vector<event_listener*> listeners;
        // Deliveries in progress: which listener, on which thread.
        std::vector<std::pair<const event_listener*, std::thread::id>> delivering;
        std::condition_variable idle;
        std::size_t waiting = 0; // detach() calls waiting on `idle`: a delivery's end notifies only then
    };

    // Marks `listener` as being delivered to on this thread, if it is still attached.
    [[nodiscard]] bool begin_delivery(const event_listener* listener, std::thread::id me);
    void end_delivery(const event_listener* listener, std::thread::id me) noexcept;

    std::atomic<bool> active_{false};
    std::mutex mutex_;
    // Created on the first attach: keeps the state constant-initialized (constinit).
    std::unique_ptr<shared> shared_;
};

// Type-erased view of one Rhp::lua_event type, so Lua can subscribe by name at runtime.
struct event_descriptor {
    std::string_view name;
    std::size_t arity = 0;
    event_state* state = nullptr;
};

// Process-wide name -> event table. Returns false if another event type already uses the name; that
// name then refuses subscriptions (kAlreadyLoaded) because it can't know which event was meant.
bool register_event(const event_descriptor* event) noexcept;

// Fails with kNotFound if no event type uses the name, kAlreadyLoaded if two do.
[[nodiscard]] result<const event_descriptor*> find_event(std::string_view name);

[[nodiscard]] std::vector<const event_descriptor*> registered_events();

} // namespace detail
} // namespace Rhp::script
