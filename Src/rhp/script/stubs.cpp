// LuaLS annotations that need no lib type: the rhp API (rhp_api) and the helpers generate<L> shares.
// Built with or without RHP_ENABLE: stubs need no Lua.

#include <cstddef>
#include <format>
#include <initializer_list>
#include <string>
#include <string_view>

#include <rhp/core/role.hpp>
#include <rhp/script/stubs.hpp>

namespace Rhp::script::stubs {

namespace detail {

std::string arg_list(std::size_t arity) {
    std::string out;
    for (std::size_t i = 1; i <= arity; ++i) {
        out += std::format("{}arg{}", i > 1 ? ", " : "", i);
    }
    return out;
}

void trim_trailing_blank(std::string& out) {
    while (out.size() >= 2 && out.ends_with("\n\n")) {
        out.pop_back();
    }
}

} // namespace detail

// Observe identities get neither rhp.patch nor what registers a lasting handler (timers, frame
// callbacks, subscriptions, tasks): sandbox.cpp replaces those with functions that raise.
std::string rhp_api(role caller) {
    const bool patch = allows(caller, role::kPatch);
    std::string out = R"lua(---@meta

---@class rhp
---@field role string "observe", "patch" or "admin"
rhp = {}

)lua";
    if (patch) {
        out += R"lua(---Overrides a C++ patch point until this module is reverted.
---@param id string
---@param handler fun(original: function, ...): any
function rhp.patch(id, handler) end

)lua";
    }
    out += R"lua(---Suspends this script for `frames` pump() calls (at least 1).
---@param frames integer
function rhp.wait(frames) end

---Suspends this script until the next pump().
function rhp.next_frame() end

---Suspends this script for at least `ms` milliseconds.
---@param ms number
function rhp.sleep(ms) end

)lua";
    if (patch) {
        out += R"lua(---Calls `fn` after `ms` milliseconds (every `ms` if `repeating`). Removed when this module is reverted.
---@param ms number
---@param fn fun()
---@param repeating? boolean
---@return integer id
function rhp.timer(ms, fn, repeating) end

---Calls `fn` once after `ms` milliseconds. Removed when this module is reverted.
---@param ms number
---@param fn fun()
---@param opts? rhp.handler_options
---@return integer id
function rhp.after(ms, fn, opts) end

---Calls `fn` every `ms` milliseconds, at most once per pump(); `opts.times` limits the calls.
---@param ms number
---@param fn fun()
---@param opts? rhp.handler_options
---@return integer id
function rhp.every(ms, fn, opts) end

---Calls `fn` every pump(), starting with the next one. Removed when this module is reverted.
---@param fn fun()
---@param opts? rhp.handler_options
---@return integer id
function rhp.every_frame(fn, opts) end

---Calls `fn` every `frames` pump() calls (the first `frames` pumps from now).
---@param frames integer
---@param fn fun()
---@param opts? rhp.handler_options
---@return integer id
function rhp.every_frames(frames, fn, opts) end

)lua";
    }
    out += R"lua(---Stops a timer, frame callback or subscription of this module from firing until rhp.resume(id).
---@param id integer
function rhp.pause(id) end

---Lets a paused timer, frame callback or subscription fire again (timers keep their remaining time).
---@param id integer
function rhp.resume(id) end

---Sets a timer's interval (milliseconds) or a frame callback's period (frames) and restarts its countdown.
---@param id integer
---@param interval number
function rhp.reschedule(id, interval) end

---This module's timers and frame callbacks.
---@return rhp.schedule_info[]
function rhp.timers() end

)lua";
    if (patch) {
        out += R"lua(---Calls `handler` each time the event fires: a C++ event of that name, else an rhp.publish of this identity. Removed when this module is reverted.
---@param event string
---@param handler fun(...)
---@param opts? rhp.handler_options
---@return integer id
function rhp.on(event, handler, opts) end

---Like rhp.on, removed after the first delivery.
---@param event string
---@param handler fun(...)
---@param opts? rhp.handler_options
---@return integer id
function rhp.once(event, handler, opts) end

---Calls `handler` with a table describing each failed timer, frame callback, event handler or task of this identity.
---@param handler fun(failure: rhp.handler_failure)
---@param opts? rhp.handler_options
---@return integer id
function rhp.on_error(handler, opts) end

)lua";
    }
    out += R"lua(---Removes a timer, frame callback or subscription, or cancels a task, made by this module.
---@param id integer
function rhp.off(id) end

---Delivers an event to every rhp.on / rhp.once / rhp.wait_event of this identity at the next pump(). Values are copied (no functions or userdata). Returns false if the event queue was full.
---@param event string
---@param ... any
---@return boolean queued
function rhp.publish(event, ...) end

---Suspends this script until `event` fires (a C++ event or an rhp.publish); returns true and its arguments, or false, "timeout" after `timeout_ms`.
---@param event string
---@param timeout_ms? number
---@return boolean fired
---@return any ...
function rhp.wait_event(event, timeout_ms) end

)lua";
    if (patch) {
        out += R"lua(---Runs `fn(...)` as a background task of this module, starting at the next pump(). Cancelled when this module is reverted.
---@param fn fun(...): ...
---@param ... any
---@return rhp.task
function rhp.spawn(fn, ...) end

)lua";
    }
    out += R"lua(---This module's tasks that have not finished.
---@return rhp.task[]
function rhp.tasks() end

---Queue and handler counters of this identity's sandbox.
---@return rhp.stats
function rhp.stats() end

---The variables the installed libs expose, with their values and tags (all, or those under `prefix`).
---@param prefix? string a lib or a path ("game", "game.speed")
---@return rhp.tunable[]
function rhp.tunables(prefix) end

---Everything this identity can use: the installed libs, C++ events and patch points, described as tables.
---@return table
function rhp.api() end

---Streams a value to the host while the script keeps running.
---@param value any
function rhp.emit(value) end

---Byte buffers this script owns (never journaled: script state, like a table).
---@class rhp.buffer_lib
rhp.buffer = {}

---A buffer of `size` bytes, each `fill` (default 0).
---@param size integer
---@param fill? integer
---@return rhp.buffer
function rhp.buffer.new(size, fill) end

---A buffer holding a copy of a string's, a buffer's or a span's bytes.
---@param bytes string|rhp.buffer|rhp.span<number>|rhp.span<integer>
---@return rhp.buffer
function rhp.buffer.from(bytes) end

---Elements of C++ memory (or of a buffer), read and written in place: v[i] (1-based, bounds-checked), #v, pairs(v). Writes to C++ memory need the patch role and are undone with the module.
---@class rhp.span<T>: { [integer]: T }
---@operator len: integer
local span = {}

---@param i integer
---@return T
function span:get(i) end

---@param i integer
---@param value T
function span:set(i, value) end

---Elements i..j (default: to the end) sharing the memory.
---@param i integer
---@param j? integer
---@return rhp.span<T>
function span:slice(i, j) end

---Sets elements i..j (default: all) to `value`.
---@param value T
---@param i? integer
---@param j? integer
function span:fill(value, i, j) end

---Copies a span's, a buffer's or a table's elements here, from element `pos` (default 1).
---@param source rhp.span<number>|rhp.span<integer>|rhp.buffer|T[]
---@param pos? integer
function span:copy(source, pos) end

---Elements i..j (default: all) as a new table.
---@param i? integer
---@param j? integer
---@return T[]
function span:totable(i, j) end

---The element type: "f32", "u8", "i64", ...
---@return string
function span:kind() end

---Whether elements may be set.
---@return boolean
function span:writable() end

---Bytes a script owns, read and written through methods at 1-based byte positions: numbers of every width, little ("le", default) or big ("be") endian; b:view("u8")[i] indexes bytes.
---@class rhp.buffer
---@operator len: integer
local buffer = {}

---Bytes i..j (default: to the end) sharing the memory.
---@param i integer
---@param j? integer
---@return rhp.buffer
function buffer:slice(i, j) end

---Sets bytes i..j (default: all) to `byte`.
---@param byte integer
---@param i? integer
---@param j? integer
function buffer:fill(byte, i, j) end

---Copies a string's, a buffer's, a byte span's or a table's bytes here, from byte `pos` (default 1).
---@param source string|rhp.buffer|rhp.span<integer>|integer[]
---@param pos? integer
function buffer:copy(source, pos) end

---A typed view of the bytes from `pos` (default 1): `count` elements (default: as many as fit) of "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64" or "byte".
---@param kind string
---@param pos? integer
---@param count? integer
---@return rhp.span<number>|rhp.span<integer>
function buffer:view(kind, pos, count) end

---Bytes i..j (default: all) as a string.
---@param i? integer
---@param j? integer
---@return string
function buffer:tostring(i, j) end

---@param pos integer
---@param len integer
---@return string
function buffer:read_string(pos, len) end

---@param pos integer
---@param s string
---@return integer next
function buffer:write_string(pos, s) end

---string.pack(fmt, ...) written at `pos`.
---@param pos integer
---@param fmt string
---@param ... any
---@return integer next
function buffer:pack(pos, fmt, ...) end

---string.unpack(fmt, ...) of the bytes from `pos`: the values, then the position after them.
---@param pos integer
---@param fmt string
---@return any ...
function buffer:unpack(pos, fmt) end

)lua";
    for (const std::string_view kind : {"i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64"}) {
        const std::string_view type = kind.front() == 'f' ? "number" : "integer";
        out += std::format("---@param pos integer\n---@param order? \"le\"|\"be\"\n---@return {}\nfunction buffer:read_{}(pos, order) end\n\n", type, kind);
        out += std::format("---@param pos integer\n---@param value {}\n---@param order? \"le\"|\"be\"\n---@return integer next\nfunction buffer:write_{}(pos, value, order) end\n\n",
                           type, kind);
    }
    out += R"lua(---Number of pump() calls so far.
---@return integer
function rhp.frame() end

---A loaded module of this identity (read-only, always its current revision).
---@param name string
---@return table
function require(name) end

---@class rhp.handler_options
---@field times? integer calls before it removes itself (rhp.every and frame callbacks only)
---@field priority? integer higher runs first (rhp.on, rhp.once, rhp.on_error only); ties keep subscription order
---@field on_error? "report"|"remove"|"fault" what a failing call does (default: the sandbox's policy)

---@class rhp.schedule_info
---@field id integer
---@field kind "timer"|"frames"
---@field interval number milliseconds, or frames
---@field remaining number milliseconds, or frames
---@field runs integer
---@field times? integer
---@field repeating boolean
---@field paused boolean
---@field running boolean

---@class rhp.task
---@field id integer
---@field status fun(self: rhp.task): "suspended"|"running"|"done"|"failed"|"cancelled"
---@field cancel fun(self: rhp.task): boolean
---@field join fun(self: rhp.task): ...

---@class rhp.handler_failure
---@field module string
---@field kind "timer"|"frame"|"event"|"task"
---@field source string
---@field id integer
---@field action "report"|"remove"|"fault"
---@field code string
---@field message string
---@field where string
---@field traceback string

---@class rhp.tunable
---@field path string
---@field type string
---@field value any
---@field writable boolean
---@field min? number
---@field max? number
---@field step? number
---@field unit? string
---@field doc? string

---@class rhp.stats
---@field dropped_events integer
---@field queued_events integer
---@field timers integer
---@field subscriptions integer
---@field tasks integer
---@field waiting integer
---@field async_waiting integer
---@field async_compensated integer
---@field async_dropped integer
---@field handler_failures integer
---@field memory integer

---@class rhp.module
---@field on_load? fun()
---@field on_unload? fun()
---@field on_save? fun(): any
---@field on_restore? fun(state: any)
)lua";
    return out;
}

} // namespace Rhp::script::stubs
