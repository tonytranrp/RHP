#pragma once

#include <cstdint>
#include <memory>
#include <utility>

namespace Rhp {

// Something callbacks subscribe to (a host's event hub, a sandbox's script-event listeners). It
// hands out ids; Rhp::subscription calls unsubscribe(id) when it dies.
class subscribable {
public:
    // Thread-safe in every implementation; a no-op for an unknown id.
    virtual void unsubscribe(std::uint64_t id) noexcept = 0;

protected:
    subscribable() = default;
    ~subscribable() = default;
    subscribable(const subscribable&) = default;
    subscribable& operator=(const subscribable&) = default;
};

// Keeps a callback subscribed for as long as it lives (move-only). Outliving what it subscribed to
// is fine: it then does nothing.
class [[nodiscard]] subscription {
public:
    subscription() = default;
    subscription(std::weak_ptr<subscribable> source, std::uint64_t id) noexcept : source_(std::move(source)), id_(id) {}
    ~subscription() { reset(); }

    subscription(subscription&& other) noexcept : source_(std::move(other.source_)), id_(std::exchange(other.id_, 0)) {}
    subscription& operator=(subscription&& other) noexcept {
        if (this != &other) {
            reset();
            source_ = std::move(other.source_);
            id_ = std::exchange(other.id_, 0);
        }
        return *this;
    }
    subscription(const subscription&) = delete;
    subscription& operator=(const subscription&) = delete;

    // Unsubscribes now.
    void reset() noexcept {
        if (id_ != 0) {
            if (const auto source = source_.lock()) {
                source->unsubscribe(id_);
            }
            id_ = 0;
        }
        source_.reset();
    }

    [[nodiscard]] bool active() const noexcept { return id_ != 0 && !source_.expired(); }

private:
    std::weak_ptr<subscribable> source_;
    std::uint64_t id_ = 0;
};

} // namespace Rhp
