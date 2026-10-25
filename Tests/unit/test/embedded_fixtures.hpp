#pragma once

// The Lua fixtures and golden reports of rhp_test_tests, embedded at configure time
// (cmake/RhpEmbed.cmake) so the suite also runs where the source tree isn't reachable (a phone).

#include <span>
#include <string_view>

namespace rhp_test_fixtures {

struct lua_source {
    std::string_view name; // relative to Tests/unit/test ("fixtures/specs/basics_spec.lua")
    std::string_view text;
};

[[nodiscard]] std::span<const lua_source> fixture_files() noexcept;

} // namespace rhp_test_fixtures
