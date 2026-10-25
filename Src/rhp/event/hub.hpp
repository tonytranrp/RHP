#pragma once

#include <concepts>
#include <cstddef>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <rhp/core/listener_table.hpp>
#include <rhp/core/subscription.hpp>
#include <rhp/event/events.hpp>

namespace Rhp::event {

// The handlers of one host. Thread-safe (core::listener_table): subscribe and unsubscribe from any
// thread; publish calls matching handlers on the publishing thread, outside the lock (a handler may
// unsubscribe itself). Once an unsubscribe returns, that handler neither runs nor starts again on
// another thread.
class hub final : public Rhp::subscribable {
public:
    using handler = std::function<void(const any&)>;
    static constexpr std::size_t kAnyKind = std::variant_size_v<any>;

    // `kind`: one event's index in `any`, or kAnyKind for every event.
    std::uint64_t add(std::size_t kind, handler fn);

    void unsubscribe(std::uint64_t id) noexcept override;
    void remove(std::uint64_t id) noexcept { unsubscribe(id); }

    // True if anyone listens to `kind` (lets the host skip building events nobody wants).
    [[nodiscard]] bool wants(std::size_t kind) const;

    void publish(const any& e) const;

private:
    core::listener_table<std::size_t, handler> handlers_;
};

// The script-event handlers of one host (host.on_script_event), by event name ("*": every name).
// Thread-safe like hub; publish calls matching handlers outside the lock.
class script_hub final : public Rhp::subscribable {
public:
    using handler = std::function<void(const script_event&)>;

    std::uint64_t add(std::string name, handler fn);

    void unsubscribe(std::uint64_t id) noexcept override;

    [[nodiscard]] bool wants(std::string_view name) const;

    void publish(const script_event& e) const;

private:
    core::listener_table<std::string, handler> handlers_;
};

// Both tables are compiled once, in hub.cpp (with the members above): a file including this header
// doesn't instantiate them (and the std::function over every host event) again.
extern template class core::listener_table<std::size_t, hub::handler>;
extern template class core::listener_table<std::string, script_hub::handler>;

// Keeps a handler subscribed for as long as it lives (move-only); see Rhp::subscription.
using subscription = Rhp::subscription;

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
