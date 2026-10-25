// Tools over a running sandbox: tunables (rhp.tunables, sandbox::tunables / tune).

#include <algorithm>
#include <cstddef>
#include <string_view>
#include <utility>

#include <lauxlib.h>
#include <lua.h>

#include <rhp/core/role.hpp>
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

} // namespace Rhp::script::detail
