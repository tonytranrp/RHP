#pragma once

// Private to Src/rhp/script/puc_lua: the few things RHP reads or sets inside PUC Lua's structures,
// for the hook (counting at safe points, line events per function, the countdown in progress) and
// the tools (the meter, coverage, the debugger's scopes); lua_internals.cpp is the only file that
// includes Lua's private headers. Lua is built from a pinned source (cmake/Dependencies.cmake), so
// these layouts are the ones compiled in.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

struct lua_State;
struct lua_Debug;

// cmake/lua/lua_cxx.cpp (the Lua translation unit): a count hook checked at safe points, the step
// function of work done in C, the key addresses are shown under.
void rhp_lua_sethook_safepoints(lua_State* L, void (*hook)(lua_State*, lua_Debug*), int count);
int rhp_lua_hook_at_safepoints(lua_State* L);
void rhp_lua_set_step_function(lua_State* L, int (*f)(lua_State*));
void rhp_lua_set_address_key(lua_State* L, const char* key);
const void* rhp_lua_topointer(lua_State* L, int idx);
const void* rhp_lua_hide_address(lua_State* L, const void* p);

namespace Rhp::script::detail::internals {

// Sets L's count hook to fire at safe points only: loop back-edges (charged their loop body's length)
// and Lua calls (charged 1), once `count` is used up. Straight-line code isn't counted, so the count is
// a bound for cancels and limits, not an exact instruction count (lua_sethook gives that). L has no
// hook mask while it waits (lua_gethookmask is 0), and code runs as fast as with no hook.
void set_safepoint_hook(lua_State* L, void (*hook)(lua_State*, lua_Debug*), int count) noexcept;

// Whether L's count hook is one set_safepoint_hook set (its count is then lua_gethookcount).
[[nodiscard]] bool hook_at_safepoints(lua_State* L) noexcept;

// Pattern matching and plain find run in C, where no hook fires; they count their work in steps and,
// every few thousand, on a thread that has a hook, call `f` directly (not through lua_call) with the
// step count on top of the stack. `f` may raise to stop the run. Kept in L's registry (may raise).
void set_step_function(lua_State* L, int (*f)(lua_State*));

// tostring, string.format's %p and shown_pointer show a keyed hash (SipHash-2-4 under `key`) where
// Lua showed an object's address, so scripts can't learn the address space layout. Kept in L's
// registry (may raise).
void set_address_key(lua_State* L, std::span<const std::byte, 16> key);

// What tostring shows as the address of the value at `index` (nullptr for a value without one).
[[nodiscard]] const void* shown_pointer(lua_State* L, int index);

// What tostring would show for address `p` (another C++ object's, say): its keyed hash in a sandbox.
[[nodiscard]] const void* shown_address(lua_State* L, const void* p);

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
