#pragma once

#include <concepts>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/convert.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/detail/event_registry.hpp>
#include <rhp/script/lib.hpp>
#include <rhp/script/marshal.hpp>
#include <rhp/script/stack.hpp>
#include <rhp/utils/fixed_string.hpp>

namespace Rhp {

namespace script::detail {

// What a queued event keeps of an argument: views are copied, they die with fire().
template <class T>
using event_capture_t = std::conditional_t<std::is_same_v<T, std::string_view> || std::is_same_v<T, const char*>, std::string, T>;

// An event argument is a plain value type that crosses the Lua boundary: Rhp::convertible, or an
// opaque handle type some installed lib declares (handle_value).
template <class T>
concept event_arg = std::same_as<T, std::remove_cvref_t<T>> && (convertible<T> || handle_value<T>) &&
                    std::copy_constructible<event_capture_t<T>>;

template <class... Args>
concept event_arg_types = (event_arg<Args> && ...);

// A handle type is pushed as the handle userdata of whichever lib in the receiving sandbox declared
// it; if none did, as its Rhp::convert form, else nil.
template <class T>
void push_event_arg(stack& s, const T& v) {
    if constexpr (handle_value<T>) {
        if (s.push_handle(&handle_type_tag_v<T>, &v, sizeof(T))) {
            return;
        }
    }
    if constexpr (pushable<T>) {
        push(s, v);
    } else {
        s.push_nil();
    }
}

} // namespace script::detail

// A typed event C++ fires and scripts subscribe to:
//
//   inline constexpr Rhp::lua_event<"player.died", game::entity_id, std::string_view> player_died{};
//
//   player_died.fire(id, "lava");     // RHP_ENABLE=0: no-op
//
//   rhp.on("player.died", function(id, cause) print(id, cause) end)   -- removed with its module
//
// The name is dotted lowercase. Delivery is fire-and-forget: synchronous in sandboxes owned by the
// firing thread, queued to the next pump() of every other subscribed sandbox. Each handler runs as
// its own script request (it may rhp.wait). While nothing is subscribed, fire() is one acquire load.
// One event type per name; the event registers itself the first time the program fires it.
template <utils::fixed_string Name, class... Args>
    requires utils::dotted_name<Name> && script::detail::event_arg_types<Args...>
class lua_event {
public:
    static constexpr std::string_view name = Name.view();
    static constexpr std::size_t arity = sizeof...(Args);

    constexpr lua_event() noexcept = default;

    void fire(const Args&... args) const {
#if RHP_ENABLE
        (void)registered_; // odr-use: instantiates the registration below
        if (!state_.active()) [[likely]] {
            return;
        }
        const refs_t refs{args...};
        state_.fire(name, script::detail::event_args{&refs, &push_refs, &own_refs, &value_refs});
#else
        ((void)args, ...);
#endif
    }

    // Sandboxes subscribed right now. 0 when RHP_ENABLE=0.
    [[nodiscard]] static std::size_t listeners() {
#if RHP_ENABLE
        return state_.listeners();
#else
        return 0;
#endif
    }

private:
#if RHP_ENABLE
    using refs_t = std::tuple<const Args&...>;
    using owned_t = std::tuple<script::detail::event_capture_t<Args>...>;

    static int push_all(script::stack& s, const auto& values) {
        std::apply([&s](const auto&... v) { (script::detail::push_event_arg(s, v), ...); }, values);
        return static_cast<int>(arity);
    }

    static int push_refs(script::stack& s, const void* data) { return push_all(s, *static_cast<const refs_t*>(data)); }

    static std::function<int(script::stack&)> own_refs(const void* data) {
        owned_t copy = std::apply([](const Args&... v) { return owned_t{v...}; }, *static_cast<const refs_t*>(data));
        return [copy = std::move(copy)](script::stack& s) { return push_all(s, copy); };
    }

    template <class T>
    static value to_value_or_nil(const T& v) {
        if constexpr (to_value_convertible<T>) {
            return Rhp::to_value(v);
        } else {
            return value{};
        }
    }

    static std::vector<value> value_refs(const void* data) {
        return std::apply([](const auto&... v) { return std::vector<value>{to_value_or_nil(v)...}; }, *static_cast<const refs_t*>(data));
    }

    static inline constinit script::detail::event_state state_{};
    static constexpr script::detail::event_descriptor descriptor_{name, arity, &state_};
    static inline const bool registered_ = script::detail::register_event(&descriptor_);
#endif
};

} // namespace Rhp
