#include <format>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/script/detail/patch_registry.hpp>

namespace Rhp::script::detail {

namespace {

struct registry {
    struct slot {
        const point_descriptor* point = nullptr;
        bool conflicted = false;
    };

    std::mutex mutex;
    std::map<std::string, slot, std::less<>> points;
};

// Function-local static: safe to use from other translation units' static initializers.
registry& instance() {
    static registry r;
    return r;
}

} // namespace

bool register_point(const point_descriptor* point) noexcept {
    try {
        auto& r = instance();
        const std::scoped_lock lock{r.mutex};
        auto [it, inserted] = r.points.try_emplace(std::string{point->id}, registry::slot{point, false});
        if (!inserted && it->second.point != point) {
            it->second.conflicted = true;
            return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

result<const point_descriptor*> find_point(std::string_view id) {
    auto& r = instance();
    const std::scoped_lock lock{r.mutex};
    const auto it = r.points.find(id);
    if (it == r.points.end()) {
        return fail(errc::kNotFound, std::format("no patch point '{}' in this program", id));
    }
    if (it->second.conflicted) {
        return fail(errc::kAlreadyLoaded, std::format("two different patch points use the id '{}'", id));
    }
    return it->second.point;
}

std::vector<const point_descriptor*> registered_points() {
    auto& r = instance();
    const std::scoped_lock lock{r.mutex};
    std::vector<const point_descriptor*> out;
    out.reserve(r.points.size());
    for (const auto& [id, slot] : r.points) {
        out.push_back(slot.point);
    }
    return out;
}

} // namespace Rhp::script::detail
