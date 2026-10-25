#pragma once

// Private to Src/rhp/script/puc_lua: the few things the test tools read from inside PUC Lua's
// structures (lua_internals.cpp is the only file that includes Lua's private headers). Lua is built
// from a pinned source (cmake/Dependencies.cmake), so these layouts are the ones compiled in.

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

struct lua_State;
struct lua_Debug;

namespace Rhp::script::detail::internals {

// Instructions L ran since its count hook last fired (or was set), and restarts the countdown so they
// aren't reported twice. 0 while L's hook doesn't count.
[[nodiscard]] std::uint32_t take_hook_progress(lua_State* L) noexcept;

// The prototype of the Lua function a hook event is in (an identity for caches; never dereferenced
// outside this file), or nullptr for a C function.
[[nodiscard]] const void* proto_of(const lua_Debug* ar) noexcept;

// The prototype of the Lua function on top of L's stack, or nullptr if it isn't a Lua function.
[[nodiscard]] const void* proto_on_top(lua_State* L) noexcept;

// The chunk name a prototype was compiled under ("@game.combat", "=exec"), as stored.
[[nodiscard]] std::string_view proto_source(const void* proto) noexcept;

// The first and last line of a prototype's function (0 and 0 for a chunk's main function).
[[nodiscard]] std::pair<int, int> proto_lines(const void* proto) noexcept;

// The prototype of the Lua function `level` frames up L's stack (0: the running one), or nullptr.
[[nodiscard]] const void* proto_at(lua_State* L, int level) noexcept;

// Turns L's line events on or off, keeping its hook, count and the countdown in progress (lua_sethook
// would restart it: a loop of calls would then never reach a count event).
void set_line_events(lua_State* L, bool on) noexcept;

// Every line of `proto` and of every function nested in it that has an instruction a line hook can
// stop at (what debug.getinfo(f, "L").activelines reports, for the whole tree), sorted and unique.
// Appends the prototypes walked (the chunk's own first) to `protos`.
[[nodiscard]] std::vector<std::uint32_t> executable_lines(const void* proto, std::vector<const void*>& protos);

} // namespace Rhp::script::detail::internals
