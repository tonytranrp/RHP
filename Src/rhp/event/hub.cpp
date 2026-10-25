#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <rhp/core/listener_table.hpp>
#include <rhp/event/hub.hpp>

namespace Rhp::core {

template class listener_table<std::size_t, event::hub::handler>;
template class listener_table<std::string, event::script_hub::handler>;

} // namespace Rhp::core

namespace Rhp::event {

std::uint64_t hub::add(std::size_t kind, handler fn) {
    return handlers_.add(kind, std::move(fn));
}

void hub::unsubscribe(std::uint64_t id) noexcept {
    (void)handlers_.remove(id);
}

bool hub::wants(std::size_t kind) const {
    return handlers_.any([kind](std::size_t k) { return k == kind || k == kAnyKind; });
}

void hub::publish(const any& e) const {
    handlers_.dispatch([index = e.index()](std::size_t k) { return k == index || k == kAnyKind; }, e);
}

std::uint64_t script_hub::add(std::string name, handler fn) {
    return handlers_.add(std::move(name), std::move(fn));
}

void script_hub::unsubscribe(std::uint64_t id) noexcept {
    (void)handlers_.remove(id);
}

bool script_hub::wants(std::string_view name) const {
    return handlers_.any([name](const std::string& n) { return n == name || n == "*"; });
}

void script_hub::publish(const script_event& e) const {
    handlers_.dispatch([&e](const std::string& n) { return n == e.event || n == "*"; }, e);
}

} // namespace Rhp::event
