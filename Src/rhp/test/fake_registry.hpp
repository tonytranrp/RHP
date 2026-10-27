#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/value.hpp>

namespace Rhp::test {

// What the functions of fake libs (Rhp::test::fake<L>) were called with and what they return,
// process-wide, by path ("game.spawn", "entity:move"). Tests read and set it from Lua through
// fake.calls / fake.returns / fake.reset, and from C++ here. Thread-safe.
class fake_registry {
public:
    [[nodiscard]] static fake_registry& instance();

    void record(std::string_view path, std::vector<value> args);
    [[nodiscard]] std::vector<std::vector<value>> calls(std::string_view path) const;
    // What the next calls return (until changed or reset); nullopt: the declared type's default.
    void set_returns(std::string_view path, std::vector<value> values);
    [[nodiscard]] std::optional<std::vector<value>> returns(std::string_view path) const;
    // Forgets calls and configured returns (of one path, or all when empty).
    void reset(std::string_view path = {});
    // Forgets every recorded call (configured returns stay). The runner does it before each test.
    void clear_calls();
    // Strict fakes raise "not mocked: path(...)" for calls nothing configured.
    void set_strict(bool strict);
    [[nodiscard]] bool strict() const;

private:
    fake_registry() = default;

    mutable std::mutex mutex_;
    std::map<std::string, std::vector<std::vector<value>>, std::less<>> calls_;
    std::map<std::string, std::vector<value>, std::less<>> returns_;
    bool strict_ = false;
};

} // namespace Rhp::test
