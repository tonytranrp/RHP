#pragma once

// Private to Src/rhp/script/puc_lua: the Lua C functions of the `rhp` table that live outside
// sandbox.cpp (open_libraries registers them).

struct lua_State;

namespace Rhp::script::detail {

// schedule.cpp: timers and frame callbacks.
int lua_rhp_timer(lua_State* L);
int lua_rhp_after(lua_State* L);
int lua_rhp_every(lua_State* L);
int lua_rhp_every_frame(lua_State* L);
int lua_rhp_every_frames(lua_State* L);
int lua_rhp_pause(lua_State* L);
int lua_rhp_resume(lua_State* L);
int lua_rhp_reschedule(lua_State* L);
int lua_rhp_timers(lua_State* L);

// script_events.cpp: subscriptions, script events, waiting for events.
int lua_rhp_on(lua_State* L);
int lua_rhp_once(lua_State* L);
int lua_rhp_on_error(lua_State* L);
int lua_rhp_publish(lua_State* L);
int lua_rhp_wait_event(lua_State* L);
int lua_rhp_stats(lua_State* L);

// tasks.cpp: background tasks.
int lua_rhp_spawn(lua_State* L);
int lua_rhp_tasks(lua_State* L);

// The reserved event every failed handler call is published as (to Lua and C++ listeners).
inline constexpr const char* kHandlerFailedEvent = "rhp.handler_failed";

} // namespace Rhp::script::detail
