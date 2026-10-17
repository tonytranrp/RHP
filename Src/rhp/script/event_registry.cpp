#include <algorithm>
#include <exception>
#include <format>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <rhp/script/detail/event_registry.hpp>

namespace Rhp::script::detail {

// ---- event_state -----------------------------------------------------------------------------------

void event_state::fire(std::string_view name, const event_args& args) {
    const auto me = std::this_thread::get_id();
    std::vector<event_listener*> local;
    {
        const std::scoped_lock lock{mutex_};
        if (!listeners_) {
            return;
        }
        for (event_listener* listener : *listeners_) {
            if (listener->listener_thread() == me) {
                local.push_back(listener);
                continue;
            }
            listener->enqueue(name, args); // noexcept: a listener that can't copy misses the event
        }
    }
    // Delivered unlocked: handlers may subscribe, unsubscribe or fire other events. A listener that
    // detached meanwhile (a handler reverted its sandbox's subscription) is skipped.
    for (event_listener* listener : local) {
        if (attached(listener)) {
            listener->deliver(name, args);
        }
    }
}

void event_state::attach(event_listener* listener) {
    const std::scoped_lock lock{mutex_};
    if (!listeners_) {
        listeners_ = std::make_unique<std::vector<event_listener*>>();
    }
    if (std::ranges::find(*listeners_, listener) == listeners_->end()) {
        listeners_->push_back(listener);
    }
    active_.store(true, std::memory_order_release);
}

void event_state::detach(const event_listener* listener) noexcept {
    const std::scoped_lock lock{mutex_};
    if (!listeners_) {
        return;
    }
    if (const auto it = std::ranges::find(*listeners_, listener); it != listeners_->end()) {
        listeners_->erase(it);
    }
    active_.store(!listeners_->empty(), std::memory_order_release);
}

std::size_t event_state::listeners() {
    const std::scoped_lock lock{mutex_};
    return listeners_ ? listeners_->size() : 0;
}

bool event_state::attached(const event_listener* listener) {
    const std::scoped_lock lock{mutex_};
    return listeners_ && std::ranges::find(*listeners_, listener) != listeners_->end();
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
