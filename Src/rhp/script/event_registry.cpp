#include <algorithm>
#include <array>
#include <exception>
#include <format>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <rhp/script/detail/event_registry.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::script::detail {

// ---- event_state -----------------------------------------------------------------------------------

void event_state::fire(std::string_view name, const event_args& args) {
    const auto me = std::this_thread::get_id();
    // Listeners owned by this thread: a handful in practice, so no allocation per fire below 8.
    std::array<event_listener*, 8> few{};
    std::size_t local_count = 0;
    std::vector<event_listener*> more;
    {
        const std::scoped_lock lock{mutex_};
        if (!shared_) {
            return;
        }
        for (event_listener* listener : shared_->listeners) {
            if (listener->listener_thread() == me) {
                if (local_count < few.size()) {
                    few[local_count++] = listener;
                } else {
                    more.push_back(listener);
                }
                continue;
            }
            listener->enqueue(name, args); // noexcept: a listener that can't copy misses the event
        }
    }
    // Delivered unlocked: handlers may subscribe, unsubscribe or fire other events. A listener that
    // detached meanwhile (a handler reverted its sandbox's subscription) is skipped; one detaching from
    // another thread waits for its delivery here to end.
    const auto deliver_to = [&](event_listener* listener) {
        if (!begin_delivery(listener, me)) {
            return;
        }
        const utils::scope_guard done{[&] { end_delivery(listener, me); }};
        listener->deliver(name, args);
    };
    for (std::size_t i = 0; i < local_count; ++i) {
        deliver_to(few[i]);
    }
    for (event_listener* listener : more) {
        deliver_to(listener);
    }
}

bool event_state::begin_delivery(const event_listener* listener, std::thread::id me) {
    const std::scoped_lock lock{mutex_};
    if (!shared_ || std::ranges::find(shared_->listeners, listener) == shared_->listeners.end()) {
        return false;
    }
    shared_->delivering.emplace_back(listener, me);
    return true;
}

void event_state::end_delivery(const event_listener* listener, std::thread::id me) noexcept {
    const std::scoped_lock lock{mutex_};
    auto& d = shared_->delivering;
    if (const auto it = std::ranges::find(d, std::pair<const event_listener*, std::thread::id>{listener, me}); it != d.end()) {
        d.erase(it);
    }
    shared_->idle.notify_all();
}

void event_state::attach(event_listener* listener) {
    const std::scoped_lock lock{mutex_};
    if (!shared_) {
        shared_ = std::make_unique<shared>();
    }
    if (std::ranges::find(shared_->listeners, listener) == shared_->listeners.end()) {
        shared_->listeners.push_back(listener);
    }
    active_.store(true, std::memory_order_release);
}

void event_state::detach(const event_listener* listener) noexcept {
    std::unique_lock lock{mutex_};
    if (!shared_) {
        return;
    }
    auto& l = shared_->listeners;
    if (const auto it = std::ranges::find(l, listener); it != l.end()) {
        l.erase(it);
    }
    active_.store(!l.empty(), std::memory_order_release);
    // Wait for deliveries to it on other threads (its own thread may be inside one: that finishes).
    const auto me = std::this_thread::get_id();
    shared_->idle.wait(lock, [&] {
        return std::ranges::none_of(shared_->delivering, [&](const auto& d) { return d.first == listener && d.second != me; });
    });
}

std::size_t event_state::listeners() {
    const std::scoped_lock lock{mutex_};
    return shared_ ? shared_->listeners.size() : 0;
}

// ---- registry ----------------------------------------------------------------------------------------

namespace {

struct registry {
    struct slot {
        const event_descriptor* event = nullptr;
        bool conflicted = false;
    };

    std::mutex mutex;
    std::map<std::string, slot, std::less<>> events;
};

// Function-local static: safe to use from other translation units' static initializers.
registry& instance() {
    static registry r;
    return r;
}

} // namespace

bool register_event(const event_descriptor* event) noexcept {
    try {
        auto& r = instance();
        const std::scoped_lock lock{r.mutex};
        auto [it, inserted] = r.events.try_emplace(std::string{event->name}, registry::slot{event, false});
        if (!inserted && it->second.event != event) {
            it->second.conflicted = true;
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

result<const event_descriptor*> find_event(std::string_view name) {
    auto& r = instance();
    const std::scoped_lock lock{r.mutex};
    const auto it = r.events.find(name);
    if (it == r.events.end()) {
        return fail(errc::kNotFound, std::format("no event '{}' in this program", name));
    }
    if (it->second.conflicted) {
        return fail(errc::kAlreadyLoaded, std::format("two different events use the name '{}'", name));
    }
    return it->second.event;
}

std::vector<const event_descriptor*> registered_events() {
    auto& r = instance();
    const std::scoped_lock lock{r.mutex};
    std::vector<const event_descriptor*> out;
    out.reserve(r.events.size());
    for (const auto& [name, slot] : r.events) {
        out.push_back(slot.event);
    }
    return out;
}

} // namespace Rhp::script::detail
