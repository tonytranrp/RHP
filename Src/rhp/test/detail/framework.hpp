#pragma once

#include <span>
#include <string_view>

namespace Rhp::test::detail {

// One file of the Lua test framework (Src/rhp/test/lua/*.lua, embedded at build time).
struct lua_source {
    std::string_view name; // the chunk name ("rhp.test/core.lua")
    std::string_view text;
};

// The framework's files, in the order they run in a test sandbox's scratch environment.
[[nodiscard]] std::span<const lua_source> framework_sources() noexcept;

} // namespace Rhp::test::detail
