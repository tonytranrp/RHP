#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>

namespace Rhp::script {

class effect;
class stack;

namespace detail {

// Type-erased view of one Rhp::patch_point type, so Lua can find points by id at runtime.
// One constexpr instance per point type; registered before main.
struct point_descriptor {
    std::string_view id;
    std::size_t arity = 0;
    // Attaches the Lua function at `fn_index` as a new top layer owned by the current module.
    // Returns the effect that removes it again.
    result<std::unique_ptr<effect>> (*attach_lua)(stack& s, int fn_index) = nullptr;
    // Number of layers currently installed (all sandboxes).
    std::size_t (*depth)() = nullptr;
    // Calls that hit a layer owned by another thread and ran the C++ default instead.
    std::uint64_t (*off_thread_misses)() = nullptr;
    // Calls the point with values converted to its parameters (overrides included) and returns its
    // result as values (none for void). nullptr when a parameter or the result isn't a value type.
    result<std::vector<value>> (*invoke)(std::span<const value> args) = nullptr;
};

// Process-wide id -> point table. Returns false if another point type already uses the id; that
// id then refuses patches (kAlreadyLoaded) because it can't know which point was meant.
bool register_point(const point_descriptor* point) noexcept;

// nullptr if unknown. Fails with kAlreadyLoaded if two point types share the id.
[[nodiscard]] result<const point_descriptor*> find_point(std::string_view id);

[[nodiscard]] std::vector<const point_descriptor*> registered_points();

} // namespace detail
} // namespace Rhp::script
