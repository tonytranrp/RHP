// The debugger: breakpoints, steps and pause() suspend a request's coroutine from the line hook;
// stacks and variables of a paused request are read without running any Lua (no calls, no
// metamethods), so inspecting can't change what the script does.

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/debug.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/puc_lua/tools.hpp>
#include <rhp/script/stack.hpp>

namespace Rhp::script::detail {

namespace {

constexpr const char* kDebugEvent = "rhp.debug";
constexpr std::size_t kMaxText = 120;           // characters of a rendered string
constexpr std::size_t kMaxFields = 200;         // fields listed per table
constexpr std::size_t kMaxCount = 100'000;      // fields counted per table
constexpr std::size_t kMaxBreakpoints = 10'000; // lines per source

template <class F>
result<void> protect(lua_State* L, F&& fn) {
    struct holder {
        std::remove_reference_t<F>* fn;
    } h{&fn};
    return stack{L}.run_protected(
        [](lua_State* inner) -> int {
            (*static_cast<holder*>(lua_touserdata(inner, 1))->fn)();
            return 0;
        },
        &h);
}

// The module (or exec chunk) name a function was compiled under, without '@' / '='.
std::string_view chunk_of(const lua_Debug& ar) noexcept {
    const std::string_view source = ar.source != nullptr ? std::string_view{ar.source, ar.srclen} : std::string_view{};
    if (!source.empty() && (source.front() == '@' || source.front() == '=')) {
        return source.substr(1);
    }
    return source;
}

int stack_depth(lua_State* L) noexcept {
    lua_Debug ar{};
    int depth = 0;
    while (lua_getstack(L, depth, &ar) != 0) {
        ++depth;
    }
    return depth;
}

bool is_identifier(std::string_view s) noexcept {
    if (s.empty() || (std::isalpha(static_cast<unsigned char>(s.front())) == 0 && s.front() != '_')) {
        return false;
    }
    return std::ranges::all_of(s, [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_'; });
}

std::string quoted(std::string_view s) {
    std::string out = "\"";
    for (const char c : s.substr(0, kMaxText)) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (static_cast<unsigned char>(c) < 0x20) {
            std::format_to(std::back_inserter(out), "\\x{:02x}", static_cast<unsigned char>(c));
        } else {
            out += c;
        }
    }
    out += s.size() > kMaxText ? "\"..." : "\"";
    return out;
}

// The name a table field is listed (and addressed in paths) by: `name`, `[3]`, `["a b"]`.
std::string key_name(lua_State* L, int key) {
    switch (lua_type(L, key)) {
    case LUA_TSTRING: {
        std::size_t n = 0;
        const char* p = lua_tolstring(L, key, &n);
        const std::string_view k{p, n};
        return is_identifier(k) ? std::string{k} : std::format("[{}]", quoted(k));
    }
    case LUA_TNUMBER:
        if (lua_isinteger(L, key) != 0) {
            return std::format("[{}]", lua_tointeger(L, key));
        }
        return std::format("[{}]", lua_tonumber(L, key));
    case LUA_TBOOLEAN: return lua_toboolean(L, key) != 0 ? "[true]" : "[false]";
    default: return std::format("[{}]", lua_typename(L, lua_type(L, key)));
    }
}

// Pushes the raw field `key` (a key_name) of the table on top, replacing it. False (nothing
// pushed, the table popped) when the top isn't a table or the key isn't addressable.
bool descend(lua_State* L, std::string_view key) {
    if (lua_type(L, -1) != LUA_TTABLE) {
        lua_pop(L, 1);
        return false;
    }
    if (key.size() >= 2 && key.front() == '[' && key.back() == ']') {
        const std::string_view inner = key.substr(1, key.size() - 2);
        if (inner.size() >= 2 && (inner.front() == '"' || inner.front() == '\'') && inner.back() == inner.front()) {
            const std::string_view text = inner.substr(1, inner.size() - 2);
            lua_pushlstring(L, text.data(), text.size());
        } else if (inner == "true" || inner == "false") {
            lua_pushboolean(L, inner == "true" ? 1 : 0);
        } else {
            lua_Integer i = 0;
            const auto [end, ec] = std::from_chars(inner.data(), inner.data() + inner.size(), i);
            if (ec != std::errc{} || end != inner.data() + inner.size()) {
                lua_pop(L, 1);
                return false;
            }
            lua_pushinteger(L, i);
        }
    } else {
        lua_pushlstring(L, key.data(), key.size());
    }
    lua_rawget(L, -2);
    lua_remove(L, -2);
    return true;
}

// The value at `index` as a debug_variable named `name`, read raw.
debug_variable render(lua_State* L, int index, std::string name) {
    index = lua_absindex(L, index);
    debug_variable v;
    v.name = std::move(name);
    const int type = lua_type(L, index);
    v.type = lua_typename(L, type);
    switch (type) {
    case LUA_TNIL: v.text = "nil"; break;
    case LUA_TBOOLEAN: v.text = lua_toboolean(L, index) != 0 ? "true" : "false"; break;
    case LUA_TNUMBER:
        v.text = lua_isinteger(L, index) != 0 ? std::format("{}", lua_tointeger(L, index)) : std::format("{}", lua_tonumber(L, index));
        break;
    case LUA_TSTRING: {
        std::size_t n = 0;
        const char* p = lua_tolstring(L, index, &n);
        v.text = quoted({p, n});
        break;
    }
    case LUA_TTABLE: {
        std::size_t count = 0;
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
            lua_pop(L, 1);
            if (++count >= kMaxCount) {
                lua_pop(L, 1);
                break;
            }
        }
        v.text = std::format("{{...}} ({}{} fields)", count, count >= kMaxCount ? "+" : "");
        v.expandable = count > 0;
        break;
    }
    case LUA_TFUNCTION: {
        lua_Debug ar{};
        lua_pushvalue(L, index);
        if (lua_getinfo(L, ">S", &ar) != 0 && ar.what != nullptr && std::string_view{ar.what} != "C") {
            v.text = std::format("function ({}:{})", chunk_of(ar), ar.linedefined);
        } else {
            v.text = "function [C]";
        }
        break;
    }
    case LUA_TUSERDATA: {
        // A handle's or a lib proxy's metatable names it (__name); read raw.
        if (lua_getmetatable(L, index) != 0) {
            lua_pushliteral(L, "__name");
            if (lua_rawget(L, -2) == LUA_TSTRING) {
                v.type = lua_tostring(L, -1);
            }
            lua_pop(L, 2);
        }
        v.text = v.type;
        break;
    }
    default: v.text = v.type; break;
    }
    return v;
}

// Every raw field of the table on top (left on the stack), at most kMaxFields.
std::vector<debug_variable> fields_of(lua_State* L) {
    std::vector<debug_variable> out;
    const int table = lua_gettop(L);
    lua_pushnil(L);
    while (lua_next(L, table) != 0) {
        if (out.size() >= kMaxFields) {
            lua_pop(L, 2);
            out.push_back(debug_variable{"...", "", std::format("(more than {} fields)", kMaxFields), false});
            break;
        }
        out.push_back(render(L, -1, key_name(L, -2)));
        lua_pop(L, 1);
    }
    return out;
}

// Pushes onto L the frame function's upvalue `name` (false if it has none).
bool push_upvalue(lua_State* co, lua_State* L, lua_Debug& ar, std::string_view name) {
    lua_getinfo(co, "f", &ar); // pushes the function onto co
    lua_xmove(co, L, 1);
    const int fn = lua_gettop(L);
    for (int n = 1;; ++n) {
        const char* up = lua_getupvalue(L, fn, n);
        if (up == nullptr) {
            break;
        }
        if (std::string_view{up} == name) {
            lua_remove(L, fn);
            return true;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    return false;
}

// Pushes onto L the frame's local `name` (the innermost one when shadowed).
bool push_local(lua_State* co, lua_State* L, lua_Debug& ar, std::string_view name) {
    int found = 0;
    for (int n = 1;; ++n) {
        const char* local = lua_getlocal(co, &ar, n);
        if (local == nullptr) {
            break;
        }
        lua_pop(co, 1);
        if (std::string_view{local} == name) {
            found = n;
        }
    }
    if (found == 0) {
        return false;
    }
    (void)lua_getlocal(co, &ar, found);
    lua_xmove(co, L, 1);
    return true;
}

// Pushes onto L the frame's environment: its function's _ENV, or (a function that uses no globals has
// none) the request's module environment `env_ref`.
bool push_env(lua_State* co, lua_State* L, lua_Debug& ar, int env_ref) {
    if (push_upvalue(co, L, ar, "_ENV")) {
        return true;
    }
    if (env_ref == kNoRef) {
        return false;
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, env_ref);
    return true;
}

// Pushes onto L the variable `name` of a scope (or, for kGlobals, the module environment's field).
bool push_named(lua_State* co, lua_State* L, lua_Debug& ar, debug_scope scope, std::string_view name, int env_ref) {
    switch (scope) {
    case debug_scope::kLocals: return push_local(co, L, ar, name);
    case debug_scope::kUpvalues: return push_upvalue(co, L, ar, name);
    case debug_scope::kGlobals:
        if (!push_env(co, L, ar, env_ref)) {
            return false;
        }
        return descend(L, name);
    }
    return false;
}

std::vector<debug_variable> list_scope(lua_State* co, lua_State* L, lua_Debug& ar, debug_scope scope, int env_ref) {
    std::vector<debug_variable> out;
    if (scope == debug_scope::kLocals) {
        for (int n = 1;; ++n) {
            const char* local = lua_getlocal(co, &ar, n);
            if (local == nullptr) {
                break;
            }
            lua_xmove(co, L, 1);
            if (local[0] != '(') { // "(temporary)", "(C temporary)": the VM's own slots
                out.push_back(render(L, -1, local));
            }
            lua_pop(L, 1);
        }
        for (int n = 1;; ++n) { // varargs
            const char* local = lua_getlocal(co, &ar, -n);
            if (local == nullptr) {
                break;
            }
            lua_xmove(co, L, 1);
            out.push_back(render(L, -1, std::format("...[{}]", n)));
            lua_pop(L, 1);
        }
    } else if (scope == debug_scope::kUpvalues) {
        lua_getinfo(co, "f", &ar);
        lua_xmove(co, L, 1);
        const int fn = lua_gettop(L);
        for (int n = 1;; ++n) {
            const char* up = lua_getupvalue(L, fn, n);
            if (up == nullptr) {
                break;
            }
            if (std::string_view{up} != "_ENV") { // listed as the globals scope
                out.push_back(render(L, -1, *up != '\0' ? std::string{up} : std::format("[{}]", n)));
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    } else if (push_env(co, L, ar, env_ref)) {
        if (lua_type(L, -1) == LUA_TTABLE) {
            out = fields_of(L);
        }
        lua_pop(L, 1);
    }
    return out;
}

// "player.pos.x", "list[2]", "t['a b']" -> {"player", "pos", "x"}, {"list", "[2]"}, {"t", "['a b']"}.
std::optional<std::vector<std::string>> parse_path(std::string_view text) {
    std::vector<std::string> out;
    std::size_t i = 0;
    const auto ident = [&]() -> std::optional<std::string> {
        const std::size_t start = i;
        while (i < text.size() && (std::isalnum(static_cast<unsigned char>(text[i])) != 0 || text[i] == '_')) {
            ++i;
        }
        const std::string_view name = text.substr(start, i - start);
        return is_identifier(name) ? std::optional<std::string>{std::string{name}} : std::nullopt;
    };
    auto first = ident();
    if (!first) {
        return std::nullopt;
    }
    out.push_back(std::move(*first));
    while (i < text.size()) {
        if (text[i] == '.') {
            ++i;
            auto name = ident();
            if (!name) {
                return std::nullopt;
            }
            out.push_back(std::move(*name));
        } else if (text[i] == '[') {
            const std::size_t close = text.find(']', i);
            if (close == std::string_view::npos) {
                return std::nullopt;
            }
            out.emplace_back(text.substr(i, close - i + 1));
            i = close + 1;
        } else {
            return std::nullopt;
        }
    }
    return out;
}

} // namespace

// ---- the line hook ---------------------------------------------------------------------------------

void sandbox_impl::line_event(lua_State* L, lua_Debug* ar) {
    if (!debugger_ || running_.empty() || closing_lua_) {
        return;
    }
    debugger_state& d = *debugger_;
    const active_run& top = running_.back();
    request_record* req = top.request;
    const bool own_thread = req != nullptr && top.thread == L;
    std::string_view reason;
    if (d.step && own_thread && req->id == d.step->request) {
        const int depth = stack_depth(L);
        const step_mode mode = d.step->mode;
        if (mode == step_mode::kInto || (mode == step_mode::kOver && depth <= d.step->depth) || (mode == step_mode::kOut && depth < d.step->depth)) {
            reason = "step";
        }
    }
    if (reason.empty() && d.pause_next) {
        reason = "pause";
    }
    const int line = ar->currentline;
    if (reason.empty() && (line <= 0 || static_cast<std::size_t>(line) >= d.lines.size() || !d.lines[static_cast<std::size_t>(line)])) {
        return; // the fast path: no breakpoint on this line anywhere
    }
    if (lua_getinfo(L, "S", ar) == 0) {
        return;
    }
    const std::string_view source = chunk_of(*ar);
    if (reason.empty()) {
        const auto it = d.breakpoints.find(source);
        if (it == d.breakpoints.end() || !std::ranges::binary_search(it->second, static_cast<std::uint32_t>(line))) {
            return;
        }
        reason = "breakpoint";
    }
    try {
        debug_stop stop{req != nullptr ? req->id : request_id{},
                        req != nullptr ? where_of(*req) : std::string{},
                        std::string{reason},
                        std::string{source},
                        static_cast<std::uint32_t>(std::max(line, 0)),
                        req != nullptr ? req->owner.module : current_.module};
        if (!own_thread || lua_isyieldable(L) == 0) {
            // A handler game code called, a coroutine the script made, code under a C call: it can't
            // wait here. A breakpoint is reported once per place; pause and step wait for a line that can.
            if (reason == "breakpoint" && d.reported.insert(std::format("{}:{}", source, line)).second) {
                publish_debug_event("hit", stop);
            }
            return;
        }
        if (reason == "pause") {
            d.pause_next = false;
        } else if (reason == "step") {
            d.step.reset();
        }
        req->waiting = wait_kind::kDebug;
        publish_debug_event("paused", stop);
        d.paused.insert_or_assign(stop.request, std::move(stop));
    } catch (...) { // out of memory: don't pause
        if (req != nullptr && req->waiting == wait_kind::kDebug) {
            req->waiting = wait_kind::kNone;
        }
        return;
    }
    (void)lua_yield(L, 0); // from a hook: the coroutine suspends once the hook returns
}

void sandbox_impl::publish_debug_event(std::string_view kind, const debug_stop& stop) {
    value::map info;
    info.emplace_back(value{"kind"}, value{std::string{kind}});
    info.emplace_back(value{"request"}, value{static_cast<std::int64_t>(stop.request.value())});
    info.emplace_back(value{"reason"}, value{stop.reason});
    info.emplace_back(value{"source"}, value{stop.source});
    info.emplace_back(value{"line"}, value{static_cast<std::int64_t>(stop.line)});
    info.emplace_back(value{"label"}, value{stop.label});
    (void)queue_script_event(kDebugEvent, module_id{}, value_list{value{std::move(info)}});
}

void sandbox_impl::forget_paused(request_id id) noexcept {
    if (!debugger_) {
        return;
    }
    debugger_->paused.erase(id);
    if (debugger_->step && debugger_->step->request == id) {
        debugger_->step.reset();
    }
}

// ---- control ---------------------------------------------------------------------------------------

result<std::vector<std::uint32_t>> sandbox_impl::set_breakpoints(std::string_view source, std::span<const std::uint32_t> lines) {
    if (lines.size() > kMaxBreakpoints) {
        return fail(errc::kLimitExceeded, std::format("at most {} breakpoints per source", kMaxBreakpoints), "debug");
    }
    std::vector<std::uint32_t> kept;
    for (const std::uint32_t line : lines) {
        if (line > 0 && line < (1u << 24)) {
            kept.push_back(line);
        }
    }
    std::ranges::sort(kept);
    kept.erase(std::ranges::unique(kept).begin(), kept.end());
    if (!debugger_) {
        debugger_ = std::make_unique<debugger_state>();
    }
    if (kept.empty()) {
        if (const auto it = debugger_->breakpoints.find(source); it != debugger_->breakpoints.end()) {
            debugger_->breakpoints.erase(it);
        }
    } else {
        debugger_->breakpoints.insert_or_assign(std::string{source}, kept);
    }
    debugger_->rebuild_lines();
    debugger_->reported.clear();
    rearm_all();
    return kept;
}

void sandbox_impl::debug_pause() {
    if (!debugger_) {
        debugger_ = std::make_unique<debugger_state>();
    }
    debugger_->pause_next = true;
    rearm_all();
}

void sandbox_impl::debug_reset() {
    if (!debugger_) {
        return;
    }
    const auto paused = std::exchange(debugger_->paused, {});
    debugger_.reset(); // first: nothing pauses again while they resume
    for (const auto& [id, stop] : paused) {
        if (const auto it = requests_.find(id); it != requests_.end() && it->second->waiting == wait_kind::kDebug) {
            it->second->waiting = wait_kind::kNone;
            it->second->woken = true;
            requests_dirty_ = true;
        }
    }
    rearm_all();
}

std::vector<debug_stop> sandbox_impl::paused() const {
    std::vector<debug_stop> out;
    if (debugger_) {
        for (const auto& [id, stop] : debugger_->paused) {
            out.push_back(stop);
        }
    }
    return out;
}

result<lua_State*> sandbox_impl::paused_thread(request_id id) const {
    const auto it = requests_.find(id);
    if (!debugger_ || !debugger_->paused.contains(id) || it == requests_.end() || it->second->waiting != wait_kind::kDebug) {
        return fail(errc::kNotFound, std::format("request {} isn't paused", id), "debug");
    }
    return it->second->thread;
}

result<void> sandbox_impl::debug_resume(request_id id, step_mode mode) {
    auto co = paused_thread(id);
    if (!co) {
        return std::unexpected{std::move(co).error()};
    }
    request_record& req = *requests_.at(id);
    if (mode != step_mode::kContinue) {
        debugger_->step = debugger_state::stepping{id, mode, stack_depth(*co)};
    } else if (debugger_->step && debugger_->step->request == id) {
        debugger_->step.reset();
    }
    debugger_->paused.erase(id);
    req.waiting = wait_kind::kNone;
    req.woken = true; // runs on at the next pump()
    requests_dirty_ = true;
    rearm_all();
    return {};
}

// ---- inspection ------------------------------------------------------------------------------------

result<std::vector<debug_frame>> sandbox_impl::debug_stack(request_id id) {
    auto co = paused_thread(id);
    if (!co) {
        return std::unexpected{std::move(co).error()};
    }
    std::vector<debug_frame> out;
    lua_Debug ar{};
    for (int level = 0; lua_getstack(*co, level, &ar) != 0; ++level) {
        if (lua_getinfo(*co, "Snl", &ar) == 0) {
            break;
        }
        debug_frame f;
        f.level = static_cast<std::uint32_t>(level);
        f.name = ar.name != nullptr ? ar.name : "?";
        f.what = ar.what != nullptr ? ar.what : "?";
        f.source = f.what == "C" ? std::string{"[C]"} : std::string{chunk_of(ar)};
        f.line = ar.currentline > 0 ? static_cast<std::uint32_t>(ar.currentline) : 0;
        f.defined = ar.linedefined > 0 ? static_cast<std::uint32_t>(ar.linedefined) : 0;
        out.push_back(std::move(f));
    }
    if (!out.empty() && out.back().name == "?" && out.back().what == "Lua") {
        out.back().name = outer_name(*requests_.at(id));
    }
    return out;
}

std::string sandbox_impl::outer_name(const request_record& req) {
    switch (req.kind) {
    case request_kind::kCall: return req.label.substr(req.label.rfind('.') + 1);
    case request_kind::kTimer: return "(timer)";
    case request_kind::kFrame: return "(frame callback)";
    case request_kind::kEvent: return std::format("(event {})", req.source);
    case request_kind::kTask: return "(task)";
    case request_kind::kExec:
    case request_kind::kLoad: break;
    }
    return "?";
}

int sandbox_impl::env_of(const request_record& req) const noexcept {
    const module_record* mod = record(req.owner.module);
    if (mod == nullptr) {
        return kNoRef;
    }
    if (mod->pending && req.owner.revision == mod->pending->revision) {
        return mod->pending->env_ref;
    }
    return mod->live.env_ref;
}

result<std::vector<debug_variable>> sandbox_impl::debug_variables(request_id id, std::uint32_t frame, debug_scope scope, std::span<const std::string> path) {
    auto co = paused_thread(id);
    if (!co) {
        return std::unexpected{std::move(co).error()};
    }
    std::optional<error> failure;
    std::vector<debug_variable> out;
    auto read = protect(state_, [&] {
        lua_State* L = state_;
        lua_Debug ar{};
        if (lua_getstack(*co, static_cast<int>(frame), &ar) == 0) {
            failure = make_error(errc::kOutOfRange, std::format("request {} has no frame {}", id, frame), "debug");
            return;
        }
        luaL_checkstack(L, 8, "rhp: debug");
        if (lua_checkstack(*co, 4) == 0) {
            failure = make_error(errc::kLimitExceeded, "the paused coroutine's stack is full", "debug");
            return;
        }
        const int env_ref = env_of(*requests_.at(id));
        if (path.empty()) {
            out = list_scope(*co, L, ar, scope, env_ref);
            return;
        }
        const int top = lua_gettop(L);
        if (!push_named(*co, L, ar, scope, path.front(), env_ref)) {
            lua_settop(L, top);
            failure = make_error(errc::kNotFound, std::format("no {} variable '{}'", to_string(scope), path.front()), "debug");
            return;
        }
        for (std::size_t i = 1; i < path.size(); ++i) {
            if (!descend(L, path[i])) {
                lua_settop(L, top);
                failure = make_error(errc::kNotFound, std::format("'{}' has no field {}", path[i - 1], path[i]), "debug");
                return;
            }
        }
        if (lua_type(L, -1) != LUA_TTABLE) {
            lua_settop(L, top);
            failure = make_error(errc::kTypeMismatch, std::format("'{}' is not a table", path.back()), "debug");
            return;
        }
        out = fields_of(L);
        lua_settop(L, top);
    });
    if (!read) {
        return std::unexpected{std::move(read).error()};
    }
    if (failure) {
        return std::unexpected{std::move(*failure)};
    }
    return out;
}

result<debug_variable> sandbox_impl::debug_evaluate(request_id id, std::uint32_t frame, std::string_view expression) {
    auto co = paused_thread(id);
    if (!co) {
        return std::unexpected{std::move(co).error()};
    }
    const auto path = parse_path(expression);
    if (!path) {
        return fail(errc::kInvalidArgument, std::format("'{}' is not a variable path (name, .field, [index])", expression), "debug");
    }
    std::optional<error> failure;
    debug_variable out;
    auto read = protect(state_, [&] {
        lua_State* L = state_;
        lua_Debug ar{};
        if (lua_getstack(*co, static_cast<int>(frame), &ar) == 0) {
            failure = make_error(errc::kOutOfRange, std::format("request {} has no frame {}", id, frame), "debug");
            return;
        }
        luaL_checkstack(L, 8, "rhp: debug");
        if (lua_checkstack(*co, 4) == 0) {
            failure = make_error(errc::kLimitExceeded, "the paused coroutine's stack is full", "debug");
            return;
        }
        const int top = lua_gettop(L);
        const std::string& name = path->front();
        bool found = push_local(*co, L, ar, name) || push_upvalue(*co, L, ar, name);
        if (!found && push_env(*co, L, ar, env_of(*requests_.at(id)))) { // the module's globals
            found = descend(L, name) && !lua_isnil(L, -1);
            if (!found) {
                lua_settop(L, top);
            }
        }
        if (!found) { // the shared base: libs and the standard library
            lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
            found = descend(L, name) && !lua_isnil(L, -1);
        }
        if (!found) {
            lua_settop(L, top);
            failure = make_error(errc::kNotFound, std::format("no variable '{}'", name), "debug");
            return;
        }
        for (std::size_t i = 1; i < path->size(); ++i) {
            const std::string& key = (*path)[i];
            if (lua_type(L, -1) == LUA_TUSERDATA && key.front() != '[') {
                // A lib proxy (its getters are C++): read through it. Anything else stays raw.
                lua_getfield(L, -1, key.c_str());
                lua_remove(L, -2);
                continue;
            }
            if (!descend(L, key)) {
                lua_settop(L, top);
                failure = make_error(errc::kNotFound, std::format("'{}' has no field {}", (*path)[i - 1], key), "debug");
                return;
            }
        }
        out = render(L, -1, std::string{expression});
        lua_settop(L, top);
    });
    if (!read) {
        return std::unexpected{std::move(read).error()};
    }
    if (failure) {
        return std::unexpected{std::move(*failure)};
    }
    return out;
}

} // namespace Rhp::script::detail
