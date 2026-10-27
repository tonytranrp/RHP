#pragma once

// Private to Src/rhp/script/puc_lua: the Lua C functions of the `rhp` table that live outside
// sandbox.cpp (open_libraries registers them).

#include <string_view>

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

// tools.cpp: tunables.
int lua_rhp_tunables(lua_State* L);
// Pushes the value at a dotted lib path ("game.sub.speed") through the lib proxies' getters (nil
// when a part is missing). May raise.
void push_lib_path(lua_State* L, std::string_view path);
// A request's function for sandbox::tune: (path, value) assigns lib path = value through the
// lib's setter (role, range and journal included).
int lua_tune_thunk(lua_State* L);

// testing.cpp: rhp.api() (sandbox::api as a table).
int lua_rhp_api(lua_State* L);

// testing.cpp: coroutine.wrap (the standard one, crediting the meter like the guarded resume).
int lua_coroutine_wrap(lua_State* L);

// buffer.cpp: sets rhp.buffer in the table on top of the stack and defines the span and buffer
// types (typed views and byte buffers, views.cpp).
void open_buffer_library(lua_State* L);

// The reserved event every failed handler call is published as (to Lua and C++ listeners).
inline constexpr const char* kHandlerFailedEvent = "rhp.handler_failed";

} // namespace Rhp::script::detail
