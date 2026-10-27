// Tools over a running sandbox: tunables (rhp.tunables, sandbox::tunables / tune).

#include <algorithm>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/core/value.hpp>
#include <rhp/script/puc_lua/builtins.hpp>
#include <rhp/script/puc_lua/sandbox_impl.hpp>
#include <rhp/script/tunables.hpp>

namespace Rhp::script::detail {

void push_lib_path(lua_State* L, std::string_view path) {
    luaL_checkstack(L, 3, "rhp: lib path");
    const std::size_t first = path.find('.');
    const std::string_view root = path.substr(0, first);
    lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
    lua_pushlstring(L, root.data(), root.size());
    lua_rawget(L, -2); // libs are globals of the base table; never a module's own
    lua_remove(L, -2);
    std::size_t start = first == std::string_view::npos ? path.size() : first + 1;
    while (start < path.size()) {
        if (lua_isnil(L, -1)) {
            return;
        }
        const std::size_t end = std::min(path.find('.', start), path.size());
        lua_pushlstring(L, path.data() + start, end - start);
        lua_gettable(L, -2); // the proxy's getter (a sub-lib, a var or a ro)
        lua_remove(L, -2);
        start = end + 1;
    }
}

int lua_tune_thunk(lua_State* L) {
    std::size_t length = 0;
    const char* text = lua_tolstring(L, 1, &length);
    const std::string_view path{text, length};
    const std::size_t dot = path.rfind('.');
    push_lib_path(L, path.substr(0, dot)); // the lib that has the variable
    const std::string_view name = path.substr(dot + 1);
    lua_pushlstring(L, name.data(), name.size());
    lua_pushvalue(L, 2);
    lua_settable(L, -3); // the proxy's setter: role, range and journal
    return 0;
}

// rhp.tunables([prefix]) -> {{path, type, value, writable, min, max, step, unit, doc}, ...}
int lua_rhp_tunables(lua_State* L) {
    const sandbox_impl& impl = impl_of(L);
    std::size_t length = 0;
    const char* text = luaL_optlstring(L, 1, "", &length);
    const std::string_view prefix{text, length};
    const bool can_write = allows(impl.caller_role(), role::kPatch);
    lua_newtable(L);
    lua_Integer n = 0;
    for (const tunable_info& t : impl.tunable_list()) {
        if (!path_matches(t.path, prefix)) {
            continue;
        }
        lua_createtable(L, 0, 9);
        lua_pushlstring(L, t.path.data(), t.path.size());
        lua_setfield(L, -2, "path");
        lua_pushlstring(L, t.type.data(), t.type.size());
        lua_setfield(L, -2, "type");
        lua_pushboolean(L, t.writable && can_write ? 1 : 0);
        lua_setfield(L, -2, "writable");
        push_lib_path(L, t.path);
        lua_setfield(L, -2, "value");
        for (const auto& [key, number] : {std::pair{"min", t.min}, std::pair{"max", t.max}, std::pair{"step", t.step}}) {
            if (number) {
                lua_pushnumber(L, static_cast<lua_Number>(*number));
                lua_setfield(L, -2, key);
            }
        }
        if (!t.unit.empty()) {
            lua_pushlstring(L, t.unit.data(), t.unit.size());
            lua_setfield(L, -2, "unit");
        }
        if (!t.doc.empty()) {
            lua_pushlstring(L, t.doc.data(), t.doc.size());
            lua_setfield(L, -2, "doc");
        }
        lua_rawseti(L, -2, ++n);
    }
    return 1;
}

// ---- sandbox::tunables / tune ----------------------------------------------------------------------

result<std::vector<tunable_info>> sandbox_impl::tunables(std::string_view prefix) {
    std::vector<tunable_info> out;
    for (const tunable_info& t : tunables_) {
        if (path_matches(t.path, prefix)) {
            out.push_back(t);
            out.back().writable = t.writable && allows(options_.caller_role, role::kPatch);
        }
    }
    if (out.empty() && !prefix.empty()) {
        return fail(errc::kNotFound, std::format("no variable is or starts with '{}'", prefix), "tunables");
    }
    auto read = protect(state_, [&] {
        lua_State* L = state_;
        for (tunable_info& t : out) {
            push_lib_path(L, t.path);
            auto v = stack{L}.to_value(-1);
            t.current = v ? std::move(*v) : value{}; // a value with no wire form (a handle): nil
            lua_pop(L, 1);
        }
    });
    if (!read) {
        return std::unexpected{std::move(read).error()};
    }
    return out;
}

result<void> sandbox_impl::tune(std::string_view path, const value& v) {
    const auto known = std::ranges::find(tunables_, path, &tunable_info::path);
    if (known == tunables_.end()) {
        return fail(errc::kNotFound, std::format("no variable '{}'", path), "tune");
    }
    if (!known->writable) {
        return fail(errc::kForbidden, "read-only", std::string{path});
    }
    const operation_scope operation{*this};
    drain();
    result<void> out{};
    auto glue = protect(state_, [&] {
        lua_State* L = state_;
        const slice_scope slice{*this};
        lua_pushcfunction(L, &lua_tune_thunk);
        stack{L}.push_string(path);
        stack{L}.push_value(v);
        request_record& req = start_request(request_kind::kExec, effect_owner{scratch_}, "tune", 2, true);
        if (auto done = step(req, 2); done && !*done) {
            out = std::unexpected{std::move(*done).error()};
        }
    });
    if (!glue) {
        out = std::unexpected{std::move(glue).error()};
    }
    drain();
    return out;
}

} // namespace Rhp::script::detail
