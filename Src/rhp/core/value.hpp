#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace Rhp {

// Dynamic value that crosses the wire and the Lua boundary. Mirrors what MessagePack and Lua can
// both represent: nil, bool, integer, number, string, bytes, array, map (any key type).
class value {
public:
    struct nil_t {
        [[nodiscard]] bool operator==(const nil_t&) const = default;
    };
    using bytes = std::vector<std::byte>;
    using array = std::vector<value>;
    using map = std::vector<std::pair<value, value>>; // insertion order kept; keys may be any value

    enum class kind : std::uint8_t {
        kNil,
        kBool,
        kInteger,
        kNumber,
        kString,
        kBytes,
        kArray,
        kMap
    };

    value() noexcept = default;
    value(nil_t) noexcept {}
    value(bool b) noexcept : data_(b) {}

    template <std::integral T>
        requires(!std::same_as<T, bool> && !std::same_as<T, char>)
    value(T i) noexcept : data_(static_cast<std::int64_t>(i)) {}

    template <std::floating_point T>
    value(T d) noexcept : data_(static_cast<double>(d)) {}

    value(std::string s) noexcept : data_(std::move(s)) {}
    value(std::string_view s) : data_(std::string{s}) {}
    value(const char* s) : data_(std::string{s}) {}
    value(bytes b) noexcept : data_(std::move(b)) {}
    value(array a) noexcept : data_(std::move(a)) {}
    value(map m) noexcept : data_(std::move(m)) {}

    [[nodiscard]] kind type() const noexcept { return static_cast<kind>(data_.index()); }

    [[nodiscard]] bool is_nil() const noexcept { return type() == kind::kNil; }
    [[nodiscard]] bool is_bool() const noexcept { return type() == kind::kBool; }
    [[nodiscard]] bool is_integer() const noexcept { return type() == kind::kInteger; }
    [[nodiscard]] bool is_number() const noexcept { return type() == kind::kNumber; }
    [[nodiscard]] bool is_string() const noexcept { return type() == kind::kString; }
    [[nodiscard]] bool is_bytes() const noexcept { return type() == kind::kBytes; }
    [[nodiscard]] bool is_array() const noexcept { return type() == kind::kArray; }
    [[nodiscard]] bool is_map() const noexcept { return type() == kind::kMap; }

    // nullptr when the value holds a different alternative.
    template <class T>
    [[nodiscard]] const T* get_if() const noexcept { return std::get_if<T>(&data_); }

    template <class T>
    [[nodiscard]] T* get_if() noexcept { return std::get_if<T>(&data_); }

    // Looks up a key in a map value; nullptr if not a map or missing.
    [[nodiscard]] const value* find(const value& key) const noexcept;

    // String keys ("name", std::string, std::string_view) without building a temporary value.
    template <class S>
        requires std::convertible_to<const S&, std::string_view>
    [[nodiscard]] const value* find(const S& key) const noexcept {
        return find_string(std::string_view{key});
    }

    [[nodiscard]] bool operator==(const value&) const = default;

private:
    [[nodiscard]] const value* find_string(std::string_view key) const noexcept;

    std::variant<nil_t, bool, std::int64_t, double, std::string, bytes, array, map> data_;
};

inline constexpr value::nil_t nil{};

// What a script returns: every value of its return list.
using value_list = std::vector<value>;

[[nodiscard]] std::string_view to_string(value::kind k) noexcept;

inline const value* value::find(const value& key) const noexcept {
    const auto* entries = get_if<map>();
    if (entries == nullptr) {
        return nullptr;
    }
    for (const auto& [k, v] : *entries) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}

inline const value* value::find_string(std::string_view key) const noexcept {
    const auto* entries = get_if<map>();
    if (entries == nullptr) {
        return nullptr;
    }
    for (const auto& [k, v] : *entries) {
        if (const auto* s = k.get_if<std::string>(); s != nullptr && *s == key) {
            return &v;
        }
    }
    return nullptr;
}

} // namespace Rhp
