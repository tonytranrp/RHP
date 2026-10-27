#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/value.hpp>
#include <rhp/test/fake_registry.hpp>

namespace Rhp::test {

fake_registry& fake_registry::instance() {
    static fake_registry registry;
    return registry;
}

void fake_registry::record(std::string_view path, std::vector<value> args) {
    const std::scoped_lock lock{mutex_};
    auto it = calls_.find(path);
    if (it == calls_.end()) {
        it = calls_.emplace(std::string{path}, std::vector<std::vector<value>>{}).first;
    }
    it->second.push_back(std::move(args));
}

std::vector<std::vector<value>> fake_registry::calls(std::string_view path) const {
    const std::scoped_lock lock{mutex_};
    const auto it = calls_.find(path);
    return it != calls_.end() ? it->second : std::vector<std::vector<value>>{};
}

void fake_registry::set_returns(std::string_view path, std::vector<value> values) {
    const std::scoped_lock lock{mutex_};
    returns_.insert_or_assign(std::string{path}, std::move(values));
}

std::optional<std::vector<value>> fake_registry::returns(std::string_view path) const {
    const std::scoped_lock lock{mutex_};
    const auto it = returns_.find(path);
    if (it == returns_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void fake_registry::reset(std::string_view path) {
    const std::scoped_lock lock{mutex_};
    if (path.empty()) {
        calls_.clear();
        returns_.clear();
        return;
    }
    if (const auto it = calls_.find(path); it != calls_.end()) {
        calls_.erase(it);
    }
    if (const auto it = returns_.find(path); it != returns_.end()) {
        returns_.erase(it);
    }
}

void fake_registry::clear_calls() {
    const std::scoped_lock lock{mutex_};
    calls_.clear();
}

void fake_registry::set_strict(bool strict) {
    const std::scoped_lock lock{mutex_};
    strict_ = strict;
}

bool fake_registry::strict() const {
    const std::scoped_lock lock{mutex_};
    return strict_;
}

} // namespace Rhp::test
