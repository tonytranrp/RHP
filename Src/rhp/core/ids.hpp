#pragma once

#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <format>
#include <functional>

namespace Rhp {

// Distinct integer id types that don't convert into each other: module_id{3} != request_id{3}.
// 0 is reserved as "none".
template <class Tag, std::unsigned_integral Rep = std::uint64_t>
class strong_id {
public:
    using rep = Rep;

    constexpr strong_id() noexcept = default;
    explicit constexpr strong_id(Rep v) noexcept : value_(v) {}

    [[nodiscard]] constexpr Rep value() const noexcept { return value_; }
    [[nodiscard]] constexpr bool valid() const noexcept { return value_ != 0; }
    explicit constexpr operator bool() const noexcept { return valid(); }

    [[nodiscard]] constexpr auto operator<=>(const strong_id&) const noexcept = default;

private:
    Rep value_ = 0;
};

using module_id = strong_id<struct module_tag>;
using request_id = strong_id<struct request_tag>;
using session_id = strong_id<struct session_tag>;
using identity_id = strong_id<struct identity_tag>;
using revision_id = strong_id<struct revision_tag, std::uint32_t>;

// Monotonic generator: next() never returns 0. Not thread-safe; each owner keeps its own.
template <class Id>
class id_generator {
public:
    [[nodiscard]] constexpr Id next() noexcept { return Id{++last_}; }
    [[nodiscard]] constexpr Id last() const noexcept { return Id{last_}; }

private:
    typename Id::rep last_ = 0;
};

} // namespace Rhp

template <class Tag, class Rep>
struct std::hash<Rhp::strong_id<Tag, Rep>> {
    std::size_t operator()(const Rhp::strong_id<Tag, Rep>& id) const noexcept {
        return std::hash<Rep>{}(id.value());
    }
};

template <class Tag, class Rep>
struct std::formatter<Rhp::strong_id<Tag, Rep>> : std::formatter<Rep> {
    auto format(const Rhp::strong_id<Tag, Rep>& id, std::format_context& ctx) const {
        return std::formatter<Rep>::format(id.value(), ctx);
    }
};
