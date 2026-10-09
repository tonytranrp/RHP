#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <variant>
#include <vector>

#include <rhp/event/events.hpp>

namespace Rhp::event {

// The handlers of one host. Thread-safe: subscribe and unsubscribe from any thread; publish calls
// matching handlers on the publishing thread, outside the lock (a handler may unsubscribe itself).
// A handler that is running when it is unsubscribed may finish that one call.
class hub {
public:
    using handler = std::function<void(const any&)>;
    static constexpr std::size_t kAnyKind = std::variant_size_v<any>;

    // `kind`: one event's index in `any`, or kAnyKind for every event.
    std::uint64_t add(std::size_t kind, handler fn) {
        const std::scoped_lock lock{mutex_};
        const std::uint64_t id = ++last_;
        entries_.push_back({id, kind, std::make_shared<handler>(std::move(fn))});
        return id;
    }

    void remove(std::uint64_t id) noexcept {
        const std::scoped_lock lock{mutex_};
        std::erase_if(entries_, [id](const entry& e) { return e.id == id; });
    }

    // True if anyone listens to `kind` (lets the host skip building events nobody wants).
    [[nodiscard]] bool wants(std::size_t kind) const {
        const std::scoped_lock lock{mutex_};
        for (const entry& e : entries_) {
            if (e.kind == kind || e.kind == kAnyKind) {
                return true;
            }
        }
        return false;
    }

    void publish(const any& e) const {
        std::vector<std::shared_ptr<handler>> targets;
        {
            const std::scoped_lock lock{mutex_};
            for (const entry& item : entries_) {
                if (item.kind == e.index() || item.kind == kAnyKind) {
                    targets.push_back(item.fn);
                }
            }
        }
        for (const auto& fn : targets) {
            (*fn)(e);
        }
    }

private:
    struct entry {
        std::uint64_t id = 0;
        std::size_t kind = 0;
        std::shared_ptr<handler> fn;
    };

    mutable std::mutex mutex_;
    std::vector<entry> entries_;
    std::uint64_t last_ = 0;
};

// Keeps a handler subscribed for as long as it lives (move-only). Outliving the host is fine: it
// then does nothing.
class [[nodiscard]] subscription {
public:
    subscription() = default;
    subscription(std::weak_ptr<hub> h, std::uint64_t id) noexcept : hub_(std::move(h)), id_(id) {}
    ~subscription() { reset(); }

    subscription(subscription&& other) noexcept : hub_(std::move(other.hub_)), id_(std::exchange(other.id_, 0)) {}
    subscription& operator=(subscription&& other) noexcept {
        if (this != &other) {
            reset();
            hub_ = std::move(other.hub_);
            id_ = std::exchange(other.id_, 0);
        }
        return *this;
    }
    subscription(const subscription&) = delete;
    subscription& operator=(const subscription&) = delete;

    // Unsubscribes now.
    void reset() noexcept {
        if (id_ != 0) {
            if (const auto h = hub_.lock()) {
                h->remove(id_);
            }
            id_ = 0;
        }
        hub_.reset();
    }

    [[nodiscard]] bool active() const noexcept { return id_ != 0 && !hub_.expired(); }

private:
    std::weak_ptr<hub> hub_;
    std::uint64_t id_ = 0;
};

template <host_event E, std::invocable<const E&> F>
[[nodiscard]] subscription subscribe(const std::shared_ptr<hub>& h, F fn) {
    const std::uint64_t id = h->add(kind_of<E>, [fn = std::move(fn)](const any& e) mutable { fn(std::get<E>(e)); });
    return subscription{h, id};
}

template <std::invocable<const any&> F>
[[nodiscard]] subscription subscribe_any(const std::shared_ptr<hub>& h, F fn) {
    const std::uint64_t id = h->add(hub::kAnyKind, [fn = std::move(fn)](const any& e) mutable { fn(e); });
    return subscription{h, id};
}

} // namespace Rhp::event
